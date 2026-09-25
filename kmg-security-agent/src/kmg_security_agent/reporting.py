"""Render one deterministic result as machine-readable JSON and Markdown."""

from __future__ import annotations

from copy import deepcopy
import json
import math
from pathlib import Path
from typing import Callable

from .decision import decide
from .evidence import deduplicate
from .schemas import REQUIREMENT_IDS, ValidationError, parse_review


SCHEMA_VERSION = "1.0"
_STATUSES = {"no_violations_found", "violated", "inconclusive", "error"}


def _redact(value: object, redactor: Callable[[str], str]) -> object:
    """Never use repr() on unsupported objects, which could expose credentials."""
    if isinstance(value, str):
        return redactor(value)
    if isinstance(value, dict):
        return {redactor(str(key)): _redact(item, redactor) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(item, redactor) for item in value]
    if value is None or type(value) in (bool, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    return "[unsupported metadata value]"


def _definitions() -> dict:
    try:
        from .requirements import REQUIREMENTS
        return REQUIREMENTS
    except ImportError:
        # Isolated tests and early failure reports must remain writable.
        return {}


def _publication_findings(check: dict, errors: list[str]) -> list[dict]:
    findings = check.get("findings", [])
    if not isinstance(findings, list):
        errors.append("Report input contains an invalid findings collection")
        return []
    published = []
    for finding in findings:
        provenance = finding.get("evidence_validation") if isinstance(finding, dict) else None
        if not isinstance(provenance, dict) or provenance.get("method") != "source_quote_match":
            errors.append("An unverified model candidate was withheld from the report")
            continue
        try:
            # Validate the trusted-to-be-provenanced object again, without its
            # deterministic annotations, before it reaches the public report.
            raw = {key: finding[key] for key in (
                "requirement_id", "title", "severity", "explanation", "recommendation",
            )}
            raw["evidence"] = [{key: item[key] for key in (
                "path", "start_line", "end_line", "quote",
            )} for item in finding["evidence"]]
            parse_review(json.dumps({
                "requirement_id": check["requirement_id"],
                "status": "violated", "rationale": "Source-validated candidate",
                "findings": [raw], "limitations": [],
            }), check["requirement_id"])
        except (KeyError, TypeError, ValidationError):
            errors.append("An invalid finding was withheld from the report")
            continue
        published.append(deepcopy(finding))
    return deduplicate(published)


def _normalize_checks(checks: list[dict], errors: list[str]) -> list[dict]:
    by_id = {}
    for check in checks:
        if not isinstance(check, dict) or check.get("requirement_id") not in REQUIREMENT_IDS:
            errors.append("Report input contains an unknown requirement")
            continue
        requirement_id = check["requirement_id"]
        if requirement_id in by_id:
            errors.append("Report input contains a duplicate requirement check")
            continue
        by_id[requirement_id] = check
    definitions = _definitions()
    result = []
    for requirement_id in REQUIREMENT_IDS:
        check = by_id.get(requirement_id)
        if check is None:
            result.append({
                "requirement_id": requirement_id,
                "title": definitions.get(requirement_id, {}).get("title", requirement_id),
                "requirement_text": definitions.get(requirement_id, {}).get("text", ""),
                "status": "inconclusive", "coverage_complete": False,
                "rationale": "Required analysis was not completed.",
                "findings": [], "limitations": ["No completed requirement review is available."],
            })
            continue
        error_count = len(errors)
        findings = _publication_findings(check, errors)
        status = check.get("status")
        if status not in _STATUSES:
            errors.append("Report input contains an unknown review status")
            status = "error"
        coverage_complete = check.get("coverage_complete") is True
        if (status == "violated" and not findings) or (status == "no_violations_found" and findings):
            errors.append("Requirement status disagrees with verified findings")
        if len(errors) != error_count:
            status, coverage_complete = "inconclusive", False
        if status in ("no_violations_found", "violated") and not coverage_complete:
            status = "inconclusive"
        result.append({
            "requirement_id": requirement_id,
            "title": definitions.get(requirement_id, {}).get("title", requirement_id),
            "requirement_text": definitions.get(requirement_id, {}).get("text", ""),
            "status": status, "coverage_complete": coverage_complete,
            "rationale": check.get("rationale", "Required analysis was not completed."),
            "findings": findings,
            "limitations": check.get("limitations", []),
            "included_paths": deepcopy(check.get("included_paths", [])),
            "context_selection": deepcopy(check.get("context_selection", {})),
            "semantic_validation": check.get("semantic_validation", "Not provided"),
            "analysis_methods": list(check.get("analysis_methods", ["llm"])),
        })
    return result


def _md_text(value: object) -> str:
    text = str(value if value is not None else "unknown")
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _md_cell(value: object) -> str:
    return _md_text(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _code_block(text: str) -> str:
    # A source quotation can itself contain Markdown fences.
    fence = "```"
    while fence in text:
        fence += "`"
    return f"{fence}\n{text}\n{fence}"


STATUS_RU = {'violated': 'нарушено', 'no_violations_found': 'нарушений не выявлено',
             'inconclusive': 'не установлено', 'error': 'ошибка проверки'}
RESULT_RU = {'violations_found': 'выявлены нарушения — пайплайн блокируется',
             'no_violations_found': 'нарушений не выявлено — пайплайн продолжается',
             'incomplete': 'проверка не завершена'}
SEVERITY_RU = {'critical': 'критическая', 'high': 'высокая', 'medium': 'средняя', 'low': 'низкая'}
METHOD_RU = {'static_rule': 'детерминированное правило', 'llm': 'LLM-анализ'}


def _evidence_md(evidence: dict) -> list:
    start, end = evidence['start_line'], evidence['end_line']
    single = start == end
    if evidence.get('location_kind') == 'extracted_document_lines':
        unit = 'абзац извлечённого текста' if single else 'абзацы извлечённого текста'
    else:
        unit = 'строка' if single else 'строки'
    where = f"{start}" if single else f"{start}–{end}"
    return [f"`{_md_cell(evidence['path'])}`, {unit} {where}:", "", _code_block(evidence["quote"]), ""]


def _markdown(report: dict) -> str:
    diagnostic = report["report_type"] == "run_diagnostics"
    timing = report["timing"]
    lines = ["# Отчёт проверки требований ИБ" + (" — диагностика незавершённого запуска" if diagnostic else ""), ""]
    if diagnostic:
        lines += ["Сбой внешнего сервиса не позволил завершить проверку. Это не заключение о соответствии.", ""]
    lines += [
        "## Сводка", "",
        "| Параметр | Значение |", "|---|---|",
        f"| Коммит | `{_md_cell(report['target'].get('commit'))}` |",
        f"| Начало | {_md_cell(timing.get('started_at'))} |",
        f"| Завершение | {_md_cell(timing.get('finished_at'))} |",
        f"| Длительность, с | {_md_cell(timing.get('duration_seconds'))} |",
        f"| Режим анализа | {_md_cell(report['metadata'].get('mode', 'llm'))} |",
        f"| Модель | {_md_cell(report['model'] or 'не использовалась')} |",
        f"| **Общий результат** | **{_md_cell(RESULT_RU.get(report['result'], report['result']))}** |",
        f"| Код завершения | **{report['exit_code']}** |",
        f"| Нарушений ИБ | **{report['finding_count']}** |",
        f"| Нарушенные требования | {_md_cell(', '.join(report['violated_requirement_ids']) or 'нет')} |",
        f"| Дополнительные замечания (не блокируют) | {len(report.get('additional_findings', []))} |",
        "", "## Статус по требованиям", "",
        "| Требование | Наименование | Статус | Находок | Методы |", "|---|---|---|---|---|",
    ]
    for check in report["requirements"]:
        count = sum(1 for f in report['findings'] if f['requirement_id'] == check['requirement_id'])
        methods = ', '.join(check.get('analysis_methods', [])) or '—'
        lines.append(f"| {check['requirement_id']} | {_md_cell(check['title'])} | {_md_cell(STATUS_RU.get(check['status'], check['status']))} | {count} | {_md_cell(methods)} |")
    lines += ["", "## Нарушения требований ИБ", ""]
    if not report["findings"]:
        lines.append("Подтверждённых нарушений нет." if report['exit_code'] == 0 else
                     "Подтверждённых нарушений нет; незавершённая проверка не является доказательством соответствия.")
    for number, finding in enumerate(report["findings"], 1):
        definition = next((c for c in report['requirements'] if c['requirement_id'] == finding['requirement_id']), {})
        lines += [
            f"### {number}. [{finding['requirement_id']}] {_md_text(finding['title'])}", "",
            f"- **Требование:** {finding['requirement_id']} — {_md_text(definition.get('title', ''))}",
            f"- **Критичность:** {SEVERITY_RU.get(finding['severity'], finding['severity'])}",
            f"- **Метод выявления:** {METHOD_RU.get(finding.get('detected_by'), 'LLM-анализ')}",
            f"- **Идентификатор:** `{finding['id']}`", "",
            f"**Обоснование.** {_md_text(finding['explanation'])}", "",
            f"**Рекомендация.** {_md_text(finding['recommendation'])}", "",
            "**Доказательства:**", "",
        ]
        for evidence in finding["evidence"]:
            lines += _evidence_md(evidence)
    lines += ["## Прочие дефекты (несоответствия технической спецификации, не блокируют пайплайн)", ""]
    extra = report.get('additional_findings', [])
    if not extra:
        lines += ["Не выявлено.", ""]
    for number, item in enumerate(extra, 1):
        lines += [f"### Д{number}. {_md_text(item['title'])}", "",
                  f"- **Пункт спецификации:** {_md_text(item.get('spec_reference', '—'))}",
                  f"- **Критичность:** {SEVERITY_RU.get(item.get('severity'), item.get('severity'))}", "",
                  _md_text(item['explanation']), "", f"**Рекомендация.** {_md_text(item['recommendation'])}", ""]
        for evidence in item['evidence']:
            lines += _evidence_md(evidence)
    for key, heading in (("additional_observations", "Прочие наблюдения"), ("errors", "Ошибки"), ("limitations", "Ограничения проверки")):
        if report.get(key):
            lines += [f"## {heading}", ""]
            for item in report[key]:
                lines.append(f"- {_md_text(item)}")
            lines.append("")
    lines += ["## Обоснование по требованиям", ""]
    for check in report["requirements"]:
        lines += [f"**{check['requirement_id']}.** {_md_text(check['rationale'])}", ""]
    lines += ["## Ресурсы и покрытие", "", _code_block(json.dumps({'usage': report['usage'], 'coverage': report['metadata'].get('coverage')},
                                                                 ensure_ascii=False, indent=2)), "",
              "Полный перечень файлов и причин исключения — в manifest.json.", ""]
    return "\n".join(lines)


def _write(path: Path, content: str) -> None:
    # Each file is replaced only once it has been fully written.
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def write_results(
    output: Path,
    metadata: dict,
    checks: list[dict],
    manifest: dict,
    usage: dict,
    errors: list[str],
    limitations: list[str],
    redactor: Callable[[str], str],
    external_error: bool = False,
) -> dict:
    errors = list(errors)
    if external_error and not errors:
        errors.append("External service failure prevented completion of the analysis")
    normalized = _normalize_checks(checks, errors)
    code = decide(normalized, errors)
    findings = deduplicate([finding for check in normalized for finding in check["findings"]])
    target = metadata.get("target", {})
    if not isinstance(target, dict):
        target = {}
    report = {
        "schema_version": SCHEMA_VERSION,
        "report_type": "run_diagnostics" if external_error else "compliance",
        "run_id": metadata.get("run_id"),
        "metadata": deepcopy(metadata),
        "target": deepcopy(target),
        "agent_version": metadata.get("agent_version"),
        "model": metadata.get("model"),
        "timing": {key: metadata.get(key) for key in ("started_at", "finished_at", "duration_seconds")},
        "result": {0: "no_violations_found", 1: "violations_found", 2: "incomplete"}[code],
        "exit_code": code,
        "requirements": normalized,
        "findings": findings,
        "finding_count": len(findings),
        "violated_requirement_ids": sorted({finding["requirement_id"] for finding in findings}),
        "additional_observations": metadata.get("additional_observations", []),
        "additional_findings": deepcopy(metadata.get("additional_findings", [])),
        "errors": list(dict.fromkeys(errors)),
        "limitations": list(limitations),
        "usage": deepcopy(usage),
        "coverage": {"manifest": "manifest.json", "requirements_complete": sum(check["coverage_complete"] for check in normalized)},
    }
    safe_report = _redact(report, redactor)
    safe_manifest = _redact(manifest, redactor)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    base = "run-status" if external_error else "report"
    _write(output / f"{base}.json", json.dumps(safe_report, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    _write(output / f"{base}.md", redactor(_markdown(safe_report)))
    from .html_report import render
    _write(output / f"{base}.html", redactor(render(safe_report)))
    _write(output / "manifest.json", json.dumps(safe_manifest, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    log = [
        f"result={safe_report['result']} exit_code={code}",
        f"verified_findings={safe_report['finding_count']}",
        "requirements_with_findings=" + ",".join(safe_report["violated_requirement_ids"]),
    ]
    log.extend(f"error={error}" for error in safe_report["errors"])
    _write(output / "run.log", redactor("\n".join(log) + "\n"))
    return safe_report
