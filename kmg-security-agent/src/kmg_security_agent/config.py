"""Explicit, local configuration. Never log configuration secrets."""
from dataclasses import dataclass, field
import os
from pathlib import Path
from urllib.parse import urlparse

class ConfigError(ValueError):
    pass

@dataclass(frozen=True)
class Config:
    api_key: str = field(repr=False)
    model: str = 'qwen/qwen3.8-27b:free'
    base_url: str = 'https://openrouter.ai/api/v1'
    allow_paid: bool = False


def load_config(env_file: Path | None = None) -> Config:
    values = {}
    path = env_file if env_file is not None else Path.cwd() / '.env'
    if path.exists():
        if not path.is_file() or path.stat().st_size > 65536:
            raise ConfigError('Некорректный файл конфигурации .env')
        for number, raw in enumerate(path.read_text(encoding='utf-8-sig').splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('export '):
                line = line[7:].strip()
            if '=' not in line:
                raise ConfigError(f'Неверный формат .env, строка {number}')
            name, value = line.split('=', 1)
            name, value = name.strip(), value.strip()
            if value.startswith(('"', "'")):
                if len(value) < 2 or value[-1] != value[0]:
                    raise ConfigError(f'Незакрытые кавычки .env, строка {number}')
                value = value[1:-1]
            else:
                value = value.split(' #', 1)[0].rstrip()
            values[name] = value
    values.update(os.environ)
    # LLM_* is the provider-neutral interface (e.g. the organiser's OpenAI-compatible endpoint);
    # OPENROUTER_* is kept for backward compatibility.
    def pick(name, default=''):
        return (values.get('LLM_' + name) or values.get('OPENROUTER_' + name) or default).strip()
    key = pick('API_KEY')
    model = pick('MODEL', 'qwen/qwen3.8-27b:free')
    base = pick('BASE_URL', 'https://openrouter.ai/api/v1').rstrip('/')
    if not key:
        raise ConfigError('Не задан ключ модели (LLM_API_KEY или OPENROUTER_API_KEY)')
    if not model or any(ch.isspace() for ch in model):
        raise ConfigError('LLM_MODEL должен содержать точный ID модели')
    parsed = urlparse(base)
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in {'localhost', '127.0.0.1', '::1'}):
        raise ConfigError('API должен использовать HTTPS либо локальный HTTP')
    if parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.hostname:
        raise ConfigError('Некорректный LLM_BASE_URL')
    allow_paid = values.get('ALLOW_PAID_MODEL', 'false').lower() == 'true'
    if parsed.hostname == 'openrouter.ai' and not allow_paid and not model.endswith(':free'):
        raise ConfigError('Платная модель запрещена; выберите :free или явно задайте ALLOW_PAID_MODEL=true')
    return Config(key, model, base, allow_paid)
