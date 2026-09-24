"""Strict, dependency-free contracts for untrusted model replies."""

from __future__ import annotations

import json
from pathlib import PurePosixPath


REQUIREMENT_IDS = tuple(f"ИБ-{number:02d}" for number in range(1, 9))
SEVERITIES = ("critical", "high", "medium", "low")
REVIEW_STATUSES = ("no_violations_found", "violated", "inconclusive")


class ValidationError(ValueError):
    """An invalid model reply; messages never include its untrusted contents."""


def _string_schema(max_length: int = 40000) -> dict:
    return {"type": "string", "minLength": 1, "maxLength": max_length}


EVIDENCE_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["path", "start_line", "end_line", "quote"],
    "properties": {
        "path": _string_schema(2048),
        "start_line": {"type": "integer", "minimum": 1},
        "end_line": {"type": "integer", "minimum": 1},
        "quote": _string_schema(200000),
    },
}
FINDING_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["requirement_id", "title", "severity", "explanation", "recommendation", "evidence"],
    "properties": {
        "requirement_id": {"type": "string", "enum": list(REQUIREMENT_IDS)},
        "title": _string_schema(1000),
        "severity": {"type": "string", "enum": list(SEVERITIES)},
        "explanation": _string_schema(),
        "recommendation": _string_schema(),
        "evidence": {"type": "array", "minItems": 1, "maxItems": 100, "items": EVIDENCE_SCHEMA},
    },
}
BATCH_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["reviewed_chunk_ids", "summary", "candidates", "related_paths"],
    "properties": {
        "reviewed_chunk_ids": {"type": "array", "uniqueItems": True, "items": _string_schema(2048)},
        "summary": _string_schema(),
        "candidates": {"type": "array", "maxItems": 500, "items": FINDING_SCHEMA},
        "related_paths": {"type": "array", "uniqueItems": True, "items": _string_schema(2048)},
    },
}
REVIEW_SCHEMA = {
    "type": "object",
    "additionalProperties": False,
    "required": ["requirement_id", "status", "rationale", "findings", "limitations"],
    "properties": {
        "requirement_id": {"type": "string", "enum": list(REQUIREMENT_IDS)},
        "status": {"type": "string", "enum": list(REVIEW_STATUSES)},
        "rationale": _string_schema(),
        "findings": {"type": "array", "maxItems": 500, "items": FINDING_SCHEMA},
        "limitations": {"type": "array", "maxItems": 500, "items": _string_schema()},
    },
}


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError("Model JSON contains duplicate object keys")
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValidationError("Model JSON contains a non-finite number")


def _load(text: str) -> dict:
    if not isinstance(text, str) or len(text) > 4_000_000:
        raise ValidationError("Model reply is not text or exceeds the response limit")
    try:
        return json.loads(text, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError):
        raise ValidationError("Model reply is not a valid JSON document") from None


def _validate(value: object, schema: dict, context: str = "reply") -> None:
    """Validate the deliberately small JSON Schema subset used above."""
    kind = schema["type"]
    if kind == "object":
        if not isinstance(value, dict):
            raise ValidationError(f"{context}: expected an object")
        if set(value) != set(schema["required"]):
            raise ValidationError(f"{context}: missing or unknown fields")
        for key, child_schema in schema["properties"].items():
            _validate(value[key], child_schema, f"{context}.{key}")
    elif kind == "array":
        if not isinstance(value, list):
            raise ValidationError(f"{context}: expected an array")
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 10000):
            raise ValidationError(f"{context}: invalid number of items")
        for item in value:
            _validate(item, schema["items"], f"{context}[]")
        if schema.get("uniqueItems") and len(value) != len(set(value)):
            raise ValidationError(f"{context}: duplicate items")
    elif kind == "string":
        if not isinstance(value, str) or not value.strip():
            raise ValidationError(f"{context}: expected non-empty text")
        if len(value) > schema.get("maxLength", 200000):
            raise ValidationError(f"{context}: text exceeds the allowed length")
        if "enum" in schema and value not in schema["enum"]:
            raise ValidationError(f"{context}: unsupported value")
    elif kind == "integer":
        if type(value) is not int or value < schema.get("minimum", 0):
            raise ValidationError(f"{context}: expected a positive integer")


def valid_relative_path(path: object) -> bool:
    if not isinstance(path, str) or not path or "\\" in path or any(ord(char) < 32 or ord(char) == 127 for char in path):
        return False
    parsed = PurePosixPath(path)
    return not parsed.is_absolute() and path == str(parsed) and all(
        part not in ("..", ".", "") and ":" not in part for part in path.split("/")
    )


def _validate_findings(findings: list[dict], requirement_id: str | None = None) -> None:
    for finding in findings:
        if requirement_id is not None and finding["requirement_id"] != requirement_id:
            raise ValidationError("Finding refers to a different requirement")
        for item in finding["evidence"]:
            if not valid_relative_path(item["path"]):
                raise ValidationError("Evidence path must be a canonical repository-relative path")
            if item["end_line"] < item["start_line"]:
                raise ValidationError("Evidence line range is reversed")


def parse_batch(text: str, expected_chunk_ids: list[str]) -> dict:
    value = _load(text)
    _validate(value, BATCH_SCHEMA)
    if len(expected_chunk_ids) != len(set(expected_chunk_ids)):
        raise ValidationError("Expected batch coverage contains duplicate IDs")
    if set(value["reviewed_chunk_ids"]) != set(expected_chunk_ids):
        raise ValidationError("Batch coverage does not match the expected chunk IDs")
    _validate_findings(value["candidates"])
    if not all(valid_relative_path(path) for path in value["related_paths"]):
        raise ValidationError("Related paths must be canonical repository-relative paths")
    return value


def parse_review(text: str, requirement_id: str) -> dict:
    if requirement_id not in REQUIREMENT_IDS:
        raise ValidationError("Unknown requested requirement")
    value = _load(text)
    _validate(value, REVIEW_SCHEMA)
    if value["requirement_id"] != requirement_id:
        raise ValidationError("Review refers to a different requirement")
    _validate_findings(value["findings"], requirement_id)
    if value["status"] == "violated" and not value["findings"]:
        raise ValidationError("A violated review must include a finding")
    if value["status"] == "no_violations_found" and value["findings"]:
        raise ValidationError("A clean review cannot include findings")
    return value
