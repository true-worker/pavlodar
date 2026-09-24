"""The model never supplies the CI exit code."""

from __future__ import annotations

from .schemas import REQUIREMENT_IDS


def decide(checks: list[dict], errors: list[str]) -> int:
    if errors or not isinstance(checks, list) or len(checks) != len(REQUIREMENT_IDS):
        return 2
    seen = set()
    violated = False
    for check in checks:
        if not isinstance(check, dict):
            return 2
        requirement = check.get("requirement_id")
        if requirement not in REQUIREMENT_IDS or requirement in seen:
            return 2
        seen.add(requirement)
        if check.get("coverage_complete") is not True:
            return 2
        status, findings = check.get("status"), check.get("findings")
        if not isinstance(findings, list):
            return 2
        if status == "violated":
            if not findings:
                return 2
            violated = True
        elif status == "no_violations_found":
            if findings:
                return 2
        else:
            return 2
    return 1 if violated else 0
