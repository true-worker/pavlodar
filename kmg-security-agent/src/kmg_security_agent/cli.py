"""Console interface. No target module is imported or executed."""
import argparse
from datetime import datetime, timezone
import json
import os
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


def _run_scan(args, config, redactor):
    from . import inventory, analysis, reporting
    repo = args.repo.expanduser().resolve()
    if not repo.is_dir():
        raise ConfigError('Путь --repo не является существующим каталогом')
    output, run_id = _fresh_output(args.output, [repo])
    started_at, started = _now(), time.monotonic()
    client = LLMClient(config, timeout=args.timeout, request_timeout=args.request_timeout, max_requests=args.max_requests, progress=_progress)
    try:
        with client._deadline_guard():
            data = inventory.collect(repo, redactor)
    except (OSError, ValueError, BudgetError):
        metadata = {'run_id': run_id, 'started_at': started_at, 'finished_at': _now(), 'duration_seconds': round(time.monotonic()-started, 3),
                    'target': {'commit': None, 'dirty': None, 'content_hash': None}, 'model': config.model, 'agent_version': __version__}
        reporting.write_results(output, metadata, [], {'schema_version': '1.0', 'files': [], 'chunks': []}, {},
                                ['Не удалось безопасно прочитать репозиторий'], [], redactor)
        print(json.dumps({'exit_code': 2, 'output': str(output)}, ensure_ascii=False))
        return 2
    _progress(f'Прочитано файлов: {len(data["documents"])}; фрагментов: {len(data["chunks"])}')
    with client._deadline_guard():
        result = analysis.scan(client, data, _progress)
    manifest = inventory.public_manifest(data)
    manifest['analysis_coverage'] = result['coverage']
    completed = set(result['coverage']['completed_chunk_ids'])
    for record in manifest['files']:
        if record['decision'] == 'analyze':
            ids = set(record.get('chunk_ids', []))
            record['analysis_status'] = ('empty_source' if not ids and record.get('line_count') == 0 else 'completed' if ids and ids <= completed else 'partial' if ids & completed else 'not_reviewed')
    metadata = {'run_id': run_id, 'started_at': started_at, 'finished_at': _now(), 'duration_seconds': round(time.monotonic()-started, 3),
                'target': data['target'], 'model': config.model, 'agent_version': __version__, 'mode': 'static',
                'coverage': result['coverage']}
    client.deadline = time.monotonic() + 60
    with client._deadline_guard():
        report = reporting.write_results(output, metadata, result['checks'], manifest, client.usage, result['errors'],
                 ['Статический анализ. Работоспособность развернутой среды и Windows ACL динамически не проверялись.',
                  'Семантические выводы модели могут содержать ошибки; проверка цитаты подтверждает только расположение кода.'],
                 redactor, external_error=result['external_error'])
    code = report['exit_code']
    print(redactor(json.dumps({'exit_code': code, 'output': str(output), 'findings': len(report.get('findings', [])),
                              'requests': client.usage['requests'], 'violated_requirements': [c['requirement_id'] for c in result['checks'] if c['status'] == 'violated']}, ensure_ascii=False)), flush=True)
    return code


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
