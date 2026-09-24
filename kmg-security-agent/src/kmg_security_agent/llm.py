"""Bounded OpenAI-compatible HTTP adapter; source code never becomes executable."""
from datetime import datetime, timezone
from contextlib import contextmanager
import signal
import threading
from email.utils import parsedate_to_datetime
import json
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse
from .config import Config

class AgentError(RuntimeError):
    pass
class BudgetError(AgentError):
    pass
class ExternalError(AgentError):
    pass

def transport_schema(schema):
    # Providers implement different JSON Schema subsets. Shape and enums go to
    # the model; all bounds/uniqueness still run in our strict local validator.
    unsupported = {'minLength', 'maxLength', 'minItems', 'maxItems', 'uniqueItems', 'minimum'}
    if isinstance(schema, dict):
        return {key: transport_schema(value) for key, value in schema.items() if key not in unsupported}
    if isinstance(schema, list):
        return [transport_schema(value) for value in schema]
    return schema

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward Authorization/source to a different URL automatically.
        return None

class LLMClient:
    def __init__(self, config: Config, *, timeout=1560, request_timeout=180, max_requests=25, progress=lambda _: None):
        self.config = config
        self.started = time.monotonic()
        self.deadline = self.started + timeout
        self.request_timeout = request_timeout
        self.max_requests = max_requests
        self.progress = progress
        self.usage = {'requests': 0, 'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0,
                      'usage_missing_responses': 0, 'retries': 0, 'model': config.model, 'tokens_complete': True}
        self.opener = urllib.request.build_opener(NoRedirect())

    def remaining(self):
        return self.deadline - time.monotonic()

    def _check(self):
        if self.remaining() <= 0:
            raise BudgetError('Исчерпан общий лимит времени анализа')
        if self.usage['requests'] >= self.max_requests:
            raise BudgetError('Исчерпан лимит запросов к модели')

    @contextmanager
    def _deadline_guard(self):
        # SIGALRM interrupts a stalled socket on the supported macOS/Linux CLI.
        enabled = hasattr(signal, 'setitimer') and threading.current_thread() is threading.main_thread()
        if not enabled:
            yield
            return
        previous = signal.getsignal(signal.SIGALRM)
        def expired(signum, frame):
            raise BudgetError('Исчерпан общий лимит времени анализа')
        previous_timer = signal.getitimer(signal.ITIMER_REAL)
        guard_started = time.monotonic()
        signal.signal(signal.SIGALRM, expired)
        signal.setitimer(signal.ITIMER_REAL, max(0.001, self.remaining()))
        try:
            yield
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
            previous_remaining = previous_timer[0] - (time.monotonic()-guard_started)
            if previous_remaining > 0:
                signal.setitimer(signal.ITIMER_REAL, previous_remaining, previous_timer[1])

    def complete(self, system: str, user: str, *, schema=None, name='security_review', max_tokens=12000):
        with self._deadline_guard():
            return self._complete(system, user, schema=schema, name=name, max_tokens=max_tokens)

    def _complete(self, system: str, user: str, *, schema=None, name='security_review', max_tokens=12000):
        body = {'model': self.config.model, 'messages': [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}],
                'temperature': 0, 'max_tokens': max_tokens, 'stream': False}
        if schema:
            body['response_format'] = {'type': 'json_schema', 'json_schema': {'name': name, 'strict': True, 'schema': transport_schema(schema)}}
        if urlparse(self.config.base_url).hostname == 'openrouter.ai':
            body['provider'] = {'allow_fallbacks': True}
            if self.config.model.startswith('qwen/'):
                body['reasoning'] = {'effort': 'low', 'exclude': True}
            if not self.config.allow_paid:
                body['provider']['max_price'] = {'prompt': 0, 'completion': 0}
        payload = json.dumps(body, ensure_ascii=False).encode('utf-8')
        for attempt in range(3):
            self._check()
            self.usage['requests'] += 1
            request = urllib.request.Request(self.config.base_url + '/chat/completions', payload,
                        {'Authorization': 'Bearer ' + self.config.api_key, 'Content-Type': 'application/json',
                         'User-Agent': 'kmg-security-agent/0.1.0'}, method='POST')
            try:
                with self.opener.open(request, timeout=max(0.1, min(self.request_timeout, self.remaining()))) as response:
                    parts, size = [], 0
                    reader = getattr(response, 'read1', response.read)
                    while size <= 2_000_000:
                        if self.remaining() <= 0:
                            raise BudgetError('Исчерпан общий лимит времени анализа')
                        part = reader(min(65536, 2_000_001-size))
                        if not part:
                            break
                        parts.append(part)
                        size += len(part)
                    raw = b''.join(parts)
                if len(raw) > 2_000_000:
                    raise ExternalError('Слишком большой ответ API')
                data = json.loads(raw)
                if not isinstance(data, dict) or data.get('error'):
                    raise ExternalError('API вернул ошибку вместо результата')
                usage = data.get('usage')
                valid_usage_fields = 0
                if isinstance(usage, dict):
                    for key in ('prompt_tokens', 'completion_tokens', 'total_tokens'):
                        value = usage.get(key)
                        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                            self.usage[key] += value
                            valid_usage_fields += 1
                if valid_usage_fields != 3:
                    self.usage['usage_missing_responses'] += 1
                    self.usage['tokens_complete'] = False
                choices = data.get('choices', [])
                if not choices or not isinstance(choices[0], dict):
                    raise ExternalError('В ответе API отсутствует результат модели')
                choice = choices[0]
                text = choice.get('message', {}).get('content')
                if not isinstance(text, str) or not text.strip():
                    raise ExternalError('Модель вернула пустой ответ')
                if choice.get('finish_reason') == 'length':
                    raise AgentError('Ответ модели оборван по лимиту токенов; проверка не завершена')
                if self.remaining() <= 0:
                    raise BudgetError('Общий лимит времени истек во время запроса')
                return text
            except urllib.error.HTTPError as exc:
                code = exc.code
                hint = ''
                try:
                    error_data = json.loads(exc.read(8192))
                    provider_message = str(error_data.get('error', {}).get('message', '')).lower()
                    if 'free-models-per-day' in provider_message or 'daily limit' in provider_message:
                        hint = ': исчерпан дневной лимит бесплатных моделей'
                    elif 'upstream' in provider_message or 'provider' in provider_message:
                        hint = ': ограничение на стороне провайдера модели'
                except (ValueError, OSError, AttributeError):
                    pass
                # Do not print response bodies, URLs with query strings, or headers.
                if code in (429, 502, 503, 504) and attempt < 2 and 'дневной' not in hint:
                    delay = self._retry_delay(exc.headers.get('Retry-After'), attempt)
                    self._backoff(delay)
                    self.usage['retries'] += 1
                    continue
                descriptions = {401: 'ключ не принят', 402: 'недостаточно квоты/кредитов', 403: 'доступ запрещен',
                                404: 'модель или endpoint не найден', 429: 'лимит запросов', 400: 'несовместимые параметры модели'}
                raise ExternalError(f'API HTTP {code}: {descriptions.get(code, "внешний сервис недоступен")}' + hint) from None
            except (urllib.error.URLError, TimeoutError, OSError):
                if self.remaining() <= 0:
                    raise BudgetError('Исчерпан общий лимит времени анализа') from None
                raise ExternalError('Не удалось связаться с API (сеть, TLS или таймаут запроса)') from None
            except (json.JSONDecodeError, UnicodeDecodeError, TypeError, AttributeError, KeyError):
                raise ExternalError('Некорректная структура ответа API') from None
        raise ExternalError('API недоступен после повторов')

    @staticmethod
    def _retry_delay(value, attempt):
        fallback = 2 ** (attempt + 1)
        if value:
            try:
                return max(fallback, float(value))
            except ValueError:
                try:
                    return max(fallback, (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds())
                except (ValueError, TypeError, OverflowError):
                    pass
        return fallback

    def _backoff(self, delay):
        if delay + 1 >= self.remaining():
            raise BudgetError('Retry-After превышает оставшийся лимит времени')
        self.progress(f'API просит повторить запрос через {round(delay)} с')
        end = time.monotonic() + delay
        while time.monotonic() < end:
            time.sleep(min(1, end - time.monotonic()))
