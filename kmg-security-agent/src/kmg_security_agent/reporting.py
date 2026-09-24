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


def _markdown(report: dict) -> str:
    diagnostic = report["report_type"] == "run_diagnostics"
    title = "KMG Security Agent — incomplete run diagnostics" if diagnostic else "KMG Security Agent — analysis report"
    lines = [f"# {title}", "", f"Result: **{report['result']}**; exit code: **{report['exit_code']}**.", ""]
    if diagnostic:
        lines += ["External service failure prevented completion. This is not a completed compliance report.", ""]
    lines += [
        f"Target commit: `{_md_cell(report['target'].get('commit'))}`.",
        f"Model: {_md_text(report['model'])}. Duration: {_md_text(report['timing'].get('duration_seconds'))} seconds.",
        f"Verified findings: {report['finding_count']}.", "",
        "## Requirements", "", "| Requirement | Status | Coverage complete |", "|---|---|---|",
    ]
    for check in report["requirements"]:
        lines.append(f"| {_md_cell(check['requirement_id'])} | {_md_cell(check['status'])} | {check['coverage_complete']} |")
    for check in report["requirements"]:
        lines += ["", f"### {check['requirement_id']}: {_md_text(check['title'])}", "", _md_text(check["rationale"])]
        for limitation in check["limitations"]:
            lines += ["", f"Limitation: {_md_text(limitation)}"]
    lines += ["", "## Verified findings", ""]
    if not report["findings"]:
        lines.append("No verified findings are available. Incomplete checks are not evidence of compliance.")
    for finding in report["findings"]:
        lines += [
            f"### {finding['id']} — {_md_text(finding['title'])}", "",
            f"Requirement: {finding['requirement_id']}. Severity: {finding['severity']}.", "",
            _md_text(finding["explanation"]), "",
            f"Recommendation: {_md_text(finding['recommendation'])}", "",
        ]
        for evidence in finding["evidence"]:
            unit = "extracted document text lines (not page coordinates)" if evidence.get("location_kind") == "extracted_document_lines" else "source lines"
            lines += [f"{_md_text(evidence['path'])}, {unit} {evidence['start_line']}–{evidence['end_line']}:", "", _code_block(evidence["quote"]), ""]
        lines += ["Evidence verification checks source locations and quotations; it is not a formal proof of the semantic conclusion.", ""]
    for key, heading in (("additional_observations", "Additional observations (non-blocking)"), ("errors", "Errors"), ("limitations", "Limitations")):
        if report[key]:
            lines += [f"## {heading}", ""]
            for item in report[key]:
                lines.append(f"- {_md_text(item)}")
            lines.append("")
    lines += ["## Resources and coverage", "", _code_block(json.dumps(report["usage"], ensure_ascii=False, indent=2)), "", "See manifest.json for file/chunk coverage and exclusions.", ""]
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
    _write(output / "manifest.json", json.dumps(safe_manifest, ensure_ascii=False, indent=2, allow_nan=False) + "\n")
    log = [
        f"result={safe_report['result']} exit_code={code}",
        f"verified_findings={safe_report['finding_count']}",
        "requirements_with_findings=" + ",".join(safe_report["violated_requirement_ids"]),
    ]
    log.extend(f"error={error}" for error in safe_report["errors"])
    _write(output / "run.log", redactor("\n".join(log) + "\n"))
    return safe_report
