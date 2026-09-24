"""Verify source quotations and deduplicate identical evidence, not prose."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import json

from .schemas import SEVERITIES, valid_relative_path


def validate_review(review: dict, documents: dict) -> list[str]:
    errors = []
    findings = review.get("findings", [])
    if not isinstance(findings, list):
        return ["Review findings are not an array"]
    # A repeated validation must not leave an earlier success marker behind.
    for finding in findings:
        if isinstance(finding, dict):
            finding.pop("evidence_validation", None)
            for item in finding.get("evidence", []) if isinstance(finding.get("evidence"), list) else []:
                if isinstance(item, dict):
                    item.pop("location_kind", None)
    annotations = []
    for finding_number, finding in enumerate(findings, 1):
        if not isinstance(finding, dict) or not isinstance(finding.get("evidence"), list) or not finding["evidence"]:
            errors.append(f"Finding {finding_number}: no source evidence")
            continue
        for evidence_number, item in enumerate(finding["evidence"], 1):
            prefix = f"Finding {finding_number}, evidence {evidence_number}"
            if not isinstance(item, dict) or not valid_relative_path(item.get("path")):
                errors.append(f"{prefix}: invalid repository-relative path")
                continue
            document = documents.get(item["path"])
            if not isinstance(document, dict) or not isinstance(document.get("lines"), list):
                errors.append(f"{prefix}: source document is unavailable")
                continue
            start, end = item.get("start_line"), item.get("end_line")
            if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(document["lines"]):
                errors.append(f"{prefix}: source range is outside the document")
                continue
            quote = item.get("quote")
            source = "\n".join(document["lines"][start - 1:end])
            if not isinstance(quote, str) or not quote.strip() or quote.strip() != source.strip():
                errors.append(f"{prefix}: quotation does not match the full cited source range")
                continue
            location_kind = "extracted_document_lines" if document.get("kind") == "docx" or item["path"].lower().endswith(".docx") else "source_lines"
            annotations.append((item, location_kind))
    # Do not turn a partially valid review into a set of confirmed findings.
    if not errors:
        for item, location_kind in annotations:
            item["location_kind"] = location_kind
        for finding in findings:
            finding["evidence_validation"] = {
                "method": "source_quote_match",
                "scope": "locations_and_quotes_only",
                "semantic_proof": False,
            }
    return errors


def _evidence_key(item: dict) -> tuple:
    return (item["path"], item["start_line"], item["end_line"], item["quote"].strip())


def deduplicate(findings: list[dict]) -> list[dict]:
    grouped = {}
    for original in findings:
        finding = deepcopy(original)
        evidence = {_evidence_key(item): item for item in finding["evidence"]}
        finding["evidence"] = [evidence[key] for key in sorted(evidence)]
        key = (finding["requirement_id"], tuple(sorted(evidence)))
        grouped.setdefault(key, []).append(finding)
    result = []
    for key, alternatives in grouped.items():
        # Deterministic even if asynchronous model replies arrive in a new order.
        alternatives.sort(key=lambda item: (
            SEVERITIES.index(item["severity"]),
            json.dumps(item, ensure_ascii=False, sort_keys=True),
        ))
        item = alternatives[0]
        digest = hashlib.sha256(json.dumps(key, ensure_ascii=False).encode()).hexdigest()[:16]
        item["id"] = f"F-{item['requirement_id'][3:]}-{digest}"
        result.append(item)
    return sorted(result, key=lambda item: (
        SEVERITIES.index(item["severity"]), item["requirement_id"], item["id"],
    ))
