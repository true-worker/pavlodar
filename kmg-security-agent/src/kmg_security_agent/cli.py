"""Console interface. No target module is imported or executed."""
import argparse
from datetime import datetime, timezone
import json
import os
from contextlib import nullcontext
from pathlib import Path
import sys
import time
import uuid
from . import __version__
from .config import ConfigError, load_config
from .security import Redactor
from .llm import AgentError, BudgetError, LLMClient


def parser():
    root = argparse.ArgumentParser(prog='kmg-agent', description='Статическая проверка Python/Django по восьми требованиям ИБ')
    root.add_argument('--env-file', type=Path, help='Путь к .env агента (до имени команды)')
    root.add_argument('--version', action='version', version=__version__)
    sub = root.add_subparsers(dest='command', required=True)
    doctor = sub.add_parser('doctor', help='Небольшой реальный запрос к модели без исходников')
    doctor.add_argument('--timeout', type=int, default=120)
    for name in ('scan', 'evaluate'):
        cmd = sub.add_parser(name, help='Проверить репозиторий' if name == 'scan' else 'Live-проверка размеченных синтетических примеров')
        if name == 'scan':
            cmd.add_argument('--repo', type=Path, required=True)
        else:
            cmd.add_argument('--fixtures', type=Path, default=Path('tests/fixtures'))
        cmd.add_argument('--output', type=Path, default=Path('reports') / name)
        cmd.add_argument('--timeout', type=int, default=1560)
        cmd.add_argument('--request-timeout', type=int, default=180)
        cmd.add_argument('--max-requests', type=int, default=25 if name == 'scan' else 40)
        if name == 'scan':
            cmd.add_argument('--mode', choices=('hybrid', 'static', 'llm'), default='hybrid',
                             help='hybrid: правила + LLM (по умолчанию); static: только правила, без ключа; llm: только модель')
            cmd.add_argument('--strict-llm', action='store_true',
                             help='В режиме hybrid считать сбой модели ошибкой проверки (код 2) вместо вывода по правилам')
    return root


def _now():
    return datetime.now(timezone.utc).isoformat()


def _fresh_output(root, forbidden):
    root = root.expanduser().resolve()
    for target in forbidden:
        if root == target or root.is_relative_to(target):
            raise ConfigError('Каталог отчёта должен находиться вне проверяемого проекта')
    run_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    output = root / run_id
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    return output, run_id


def _progress(message):
    print(message, file=sys.stderr, flush=True)


def _summary(report, output):
    """Human-readable CI log: result, count and violated requirement IDs without opening artifacts."""
    lines = ['=' * 72, f'KMG Security Agent: результат = {report["result"]}, код завершения = {report["exit_code"]}',
             f'Нарушений ИБ: {report["finding_count"]}; нарушены требования: '
             + (', '.join(report['violated_requirement_ids']) or 'нет')]
    for check in report['requirements']:
        count = sum(1 for f in report['findings'] if f['requirement_id'] == check['requirement_id'])
        lines.append(f'  {check["requirement_id"]} {check["status"]:<20} находок: {count}  {check["title"]}')
    extra = report.get('additional_findings', [])
    if extra:
        lines.append(f'Дополнительные замечания (не блокируют): {len(extra)}')
    for error in report['errors']:
        lines.append('Ошибка: ' + error)
    lines += [f'Отчёт: {output / "report.md"}', '=' * 72]
    print('\n'.join(lines), file=sys.stderr, flush=True)


def _run_scan(args, config, redactor, config_error=None):
    from . import inventory, analysis, reporting
    repo = args.repo.expanduser().resolve()
    if not repo.is_dir():
        raise ConfigError('Путь --repo не является существующим каталогом')
    output, run_id = _fresh_output(args.output, [repo])
    started_at, started = _now(), time.monotonic()
    mode, strict = getattr(args, 'mode', 'llm'), getattr(args, 'strict_llm', False)
    model_name = config.model if config else None
    client = LLMClient(config, timeout=args.timeout, request_timeout=args.request_timeout, max_requests=args.max_requests,
                       progress=_progress) if config else None

    def guard():
        return client._deadline_guard() if client else nullcontext()

    base_meta = {'run_id': run_id, 'started_at': started_at, 'model': model_name, 'agent_version': __version__, 'mode': mode}
    try:
        with guard():
            data = inventory.collect(repo, redactor)
    except (OSError, ValueError, BudgetError):
        metadata = dict(base_meta, finished_at=_now(), duration_seconds=round(time.monotonic()-started, 3),
                        target={'commit': None, 'dirty': None, 'content_hash': None})
        reporting.write_results(output, metadata, [], {'schema_version': '1.0', 'files': [], 'chunks': []}, {},
                                ['Не удалось безопасно прочитать репозиторий'], [], redactor)
        print(json.dumps({'exit_code': 2, 'output': str(output)}, ensure_ascii=False))
        return 2
    _progress(f'Прочитано файлов: {len(data["documents"])}; фрагментов: {len(data["chunks"])}')

    static_result, llm_result, llm_error = None, None, None
    fatal_errors = list(data['errors'])
    if mode in ('hybrid', 'static'):
        _progress('Статические правила ИБ-01…ИБ-08')
        static_result = analysis.static_checks(data)
    if mode in ('hybrid', 'llm'):
        if client is None:
            llm_error = 'модель не настроена: ' + (config_error or 'нет ключа')
        else:
            try:
                with guard():
                    llm_result = analysis.scan(client, data, _progress)
            except BudgetError as exc:
                llm_error = str(exc)
            if llm_result and (llm_result['errors'] or llm_result['external_error']):
                llm_error = '; '.join(llm_result['errors'][:3]) or 'сбой внешнего сервиса'
    if mode == 'llm' or (strict and llm_error):
        checks = llm_result['checks'] if llm_result else []
        errors = (llm_result['errors'] if llm_result else []) or ([llm_error] if llm_error else [])
        external = bool(llm_result and llm_result['external_error']) or (llm_result is None)
    else:
        checks = analysis.combine(static_result, llm_result, llm_error)
        errors, external = [], False
        try:
            fatal_errors += inventory.check_unchanged(data)
        except (OSError, ValueError):
            fatal_errors.append('Не удалось повторно проверить неизменность исходников')
    errors = list(dict.fromkeys(fatal_errors + errors))

    manifest = inventory.public_manifest(data)
    coverage = (llm_result or {}).get('coverage') or {'expected_chunks': len(data['chunks']), 'completed_chunk_ids': []}
    manifest['analysis_coverage'] = coverage
    completed = set(coverage.get('completed_chunk_ids', []))
    for record in manifest['files']:
        if record['decision'] == 'analyze':
            ids = set(record.get('chunk_ids', []))
            record['analysis_status'] = ('empty_source' if not ids and record.get('line_count') == 0 else 'completed' if ids and ids <= completed
                                         else 'partial' if ids & completed else 'static_rules_only' if static_result else 'not_reviewed')
    metadata = dict(base_meta, finished_at=_now(), duration_seconds=round(time.monotonic()-started, 3), target=data['target'],
                    coverage={'files_read': len(data['documents']), 'chunks': len(data['chunks']),
                              'llm_chunks_reviewed': len(completed), 'llm_error': llm_error},
                    additional_findings=(static_result or {}).get('additional_findings', []),
                    static_rules_version=(static_result or {}).get('rules_version'),
                    route_map=(static_result or {}).get('routes', []))
    limitations = ['Статический анализ: код проверяемого проекта не запускается; права Windows ACL и среда развёртывания динамически не проверялись.',
                   'Цитаты и номера строк проверены детерминированно; семантические выводы LLM могут содержать ошибки.']
    if llm_error and mode == 'hybrid' and not strict:
        limitations.append('LLM-анализ не завершён (' + llm_error + '); итог основан на детерминированных правилах.')
    if client:
        client.deadline = time.monotonic() + 60
    with guard():
        report = reporting.write_results(output, metadata, checks, manifest, client.usage if client else {'requests': 0},
                                         errors, limitations, redactor, external_error=external)
    _summary(report, output)
    print(redactor(json.dumps({'exit_code': report['exit_code'], 'output': str(output), 'findings': report['finding_count'],
                               'violated_requirements': report['violated_requirement_ids'],
                               'requests': client.usage['requests'] if client else 0}, ensure_ascii=False)), flush=True)
    return report['exit_code']


def _run_evaluate(args, config, redactor):
    from . import inventory, index, analysis
    from .llm import ExternalError, BudgetError
    fixtures = args.fixtures.expanduser().resolve()
    labels_path = fixtures / 'labels.json'
    if not labels_path.is_file():
        raise ConfigError('Не найден fixtures/labels.json')
    labels = json.loads(labels_path.read_text(encoding='utf-8'))
    cases = labels.get('cases', [])
    if not cases or len({c['id'] for c in cases}) != len(cases):
        raise ConfigError('Некорректный список размеченных примеров')
    output, run_id = _fresh_output(args.output, [fixtures])
    client = LLMClient(config, timeout=args.timeout, request_timeout=args.request_timeout, max_requests=args.max_requests, progress=_progress)
    results, errors = [], []
    for case in cases:
        case_repo = (fixtures / case['repo']).resolve()
        if not case_repo.is_relative_to(fixtures) or not case_repo.is_dir():
            raise ConfigError('Неверный путь к размеченному примеру')
        _progress(f'Пример {len(results)+1}/{len(cases)}: {case["id"]}')
        try:
            with client._deadline_guard():
                data = inventory.collect(case_repo, redactor)
                if data['errors']:
                    raise AgentError('Не все файлы примера прочитаны')
                # Labels are for scoring only; never passed to the model.
                review = analysis.review_requirement(client, data, index.build_index(data['documents']), [], case['requirement_id'])
                changed = inventory.check_unchanged(data)
            if changed:
                raise AgentError('Файлы примера изменились во время анализа')
            evidence_paths = {e['path'] for f in review['findings'] for e in f['evidence']}
            expected_paths = set(case.get('expected_evidence_paths', []))
            correct = review['status'] == case['expected_status'] and (not expected_paths or bool(evidence_paths & expected_paths))
            results.append({'id': case['id'], 'expected_status': case['expected_status'], 'correct': correct, 'review': review})
            if not review.get('coverage_complete', False) or review['status'] == 'inconclusive':
                errors.append(case['id'] + ': модель не завершила вывод по требованию')
        except (ExternalError, BudgetError) as exc:
            errors.append(str(exc))
            break
        except AgentError as exc:
            results.append({'id': case['id'], 'correct': False, 'error': str(exc)})
            errors.append(str(exc))
    complete = len(results) == len(cases) and not errors
    tp = sum(r.get('expected_status') == 'violated' and r.get('review', {}).get('status') == 'violated' for r in results)
    fp = sum(r.get('expected_status') == 'no_violations_found' and r.get('review', {}).get('status') == 'violated' for r in results)
    fn = sum(r.get('expected_status') == 'violated' and r.get('review', {}).get('status') != 'violated' for r in results)
    code = 2 if not complete else (0 if all(r['correct'] for r in results) else 1)
    report = {'schema_version': '1.0', 'run_id': run_id, 'kind': 'model_evaluation', 'model': config.model,
              'complete': complete, 'exit_code': code, 'total_cases': len(cases), 'completed_cases': len(results),
              'correct_cases': sum(r['correct'] for r in results), 'precision': tp/(tp+fp) if tp+fp else None,
              'recall': tp/(tp+fn) if tp+fn else None, 'metrics_are_partial': not complete, 'usage': client.usage, 'results': results, 'errors': errors}
    (output/'evaluation.json').write_text(redactor(json.dumps(report, ensure_ascii=False, indent=2)) + '\n', encoding='utf-8')
    lines = ['# Проверка модели на синтетических примерах', '', f'Завершено: {len(results)}/{len(cases)}. Верно: {report["correct_cases"]}. Код: {code}.', '',
             'Эта оценка не заменяет проверку на скрытой разметке организатора.', '']
    lines.extend(f'- {r["id"]}: {"совпало" if r["correct"] else "не совпало/ошибка"}' for r in results)
    lines.extend(errors)
    (output/'evaluation.md').write_text(redactor('\n'.join(lines))+'\n', encoding='utf-8')
    print(json.dumps({'exit_code': code, 'output': str(output), 'completed_cases': len(results), 'correct_cases': report['correct_cases']}, ensure_ascii=False))
    return code


def main(argv=None):
    args = parser().parse_args(argv)
    redactor = Redactor()
    try:
        if not 1 <= args.timeout <= 1620:
            raise ConfigError('--timeout должен быть от 1 до 1620 секунд (резерв на отчёт до предела 30 минут)')
        if args.command != 'doctor' and (args.request_timeout < 1 or args.max_requests < 1):
            raise ConfigError('Лимиты запросов должны быть положительными')
        if args.command == 'scan' and args.mode != 'llm':
            try:
                config = load_config(args.env_file) if args.mode == 'hybrid' else None
            except ConfigError as exc:
                if args.strict_llm:
                    raise
                _progress(f'LLM недоступна ({exc}); проверка выполняется детерминированными правилами')
                return _run_scan(args, None, redactor, str(exc))
            if config is not None:
                redactor = Redactor(config.api_key)
            return _run_scan(args, config, redactor)
        config = load_config(args.env_file)
        redactor = Redactor(config.api_key)
        if args.command == 'doctor':
            client = LLMClient(config, timeout=args.timeout, request_timeout=min(100, args.timeout), max_requests=3, progress=_progress)
            reply = client.complete('Reply with the word OK. This is a connectivity test.', 'OK?', max_tokens=2048)
            print(json.dumps({'ok': bool(reply.strip()), 'model': config.model, 'duration_seconds': round(time.monotonic()-client.started, 3), 'usage': client.usage}, ensure_ascii=False))
            return 0
        if args.command == 'scan':
            return _run_scan(args, config, redactor)
        return _run_evaluate(args, config, redactor)
    except (ConfigError, AgentError, OSError, ValueError) as exc:
        # Never print arbitrary OSError paths or decoded API bodies/config values.
        message = str(exc) if isinstance(exc, (ConfigError, AgentError)) else 'Ошибка чтения/записи или формата локальных данных'
        print(redactor(message), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('Проверка прервана пользователем; успешного заключения нет', file=sys.stderr)
        return 2
