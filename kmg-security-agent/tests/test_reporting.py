"""Tests of trust boundaries and deterministic CI/report behavior, without LLM I/O."""

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from kmg_security_agent import decision, evidence, reporting, schemas


def finding(requirement_id="ИБ-01", path="app.py", line=1, quote="allow()"):
    return {
        "requirement_id": requirement_id, "title": "Unprotected operation", "severity": "high",
        "explanation": "A reachable operation has no required role check.",
        "recommendation": "Enforce the required role in a shared server-side guard.",
        "evidence": [{"path": path, "start_line": line, "end_line": line, "quote": quote}],
    }


def review(requirement_id="ИБ-01", violated=False):
    return {
        "requirement_id": requirement_id,
        "status": "violated" if violated else "no_violations_found",
        "rationale": "The active implementation and shared controls were reviewed.",
        "findings": [finding(requirement_id)] if violated else [], "limitations": [],
    }


def completed_checks(violated=False):
    checks = [review(rid, violated and rid == "ИБ-01") for rid in schemas.REQUIREMENT_IDS]
    for check in checks:
        check["coverage_complete"] = True
        evidence.validate_review(check, {"app.py": {"lines": ["allow()"], "kind": "python"}})
    return checks


class SchemaTests(unittest.TestCase):
    def test_all_eight_ids_have_valid_review_contracts(self):
        for rid in schemas.REQUIREMENT_IDS:
            self.assertEqual(schemas.parse_review(json.dumps(review(rid)), rid)["requirement_id"], rid)

    def test_duplicate_keys_and_non_json_envelopes_are_rejected(self):
        for text in ('{"status":"violated","status":"no_violations_found"}', '```json\n{}\n```', '{"x": NaN}'):
            with self.subTest(text=text), self.assertRaises(schemas.ValidationError):
                schemas.parse_review(text, "ИБ-01")

    def test_unknown_fields_ids_and_boolean_lines_are_rejected(self):
        variants = []
        item = review(violated=True)
        item["exit_code"] = 0
        variants.append(item)
        item = review(violated=True)
        item["findings"][0]["requirement_id"] = "ИБ-09"
        variants.append(item)
        item = review(violated=True)
        item["findings"][0]["evidence"][0]["start_line"] = True
        variants.append(item)
        for item in variants:
            with self.subTest(item=item), self.assertRaises(schemas.ValidationError):
                schemas.parse_review(json.dumps(item), "ИБ-01")

    def test_status_and_requirement_consistency(self):
        variants = [review(), review(violated=True), review("ИБ-02")]
        variants[0]["status"] = "violated"
        variants[1]["status"] = "no_violations_found"
        for item in variants:
            with self.assertRaises(schemas.ValidationError):
                schemas.parse_review(json.dumps(item), "ИБ-01")

    def test_paths_are_canonical_and_relative(self):
        for path in ("../app.py", "/app.py", "a/../app.py", "a\\app.py", "./app.py", "C:/app.py", "a//app.py"):
            item = review(violated=True)
            item["findings"][0]["evidence"][0]["path"] = path
            with self.subTest(path=path), self.assertRaises(schemas.ValidationError):
                schemas.parse_review(json.dumps(item), "ИБ-01")

    def test_batch_requires_exact_coverage_not_just_a_count(self):
        batch = {"reviewed_chunk_ids": ["a", "b"], "summary": "Reviewed", "candidates": [], "related_paths": []}
        self.assertEqual(schemas.parse_batch(json.dumps(batch), ["b", "a"]), batch)
        for ids in (["a"], ["a", "c"], ["a", "a"]):
            batch["reviewed_chunk_ids"] = ids
            with self.assertRaises(schemas.ValidationError):
                schemas.parse_batch(json.dumps(batch), ["a", "b"])

    def test_validation_error_does_not_echo_untrusted_secrets(self):
        with self.assertRaises(schemas.ValidationError) as caught:
            schemas.parse_review('{"secret":"API-TOKEN-PRIVATE"', "ИБ-01")
        self.assertNotIn("API-TOKEN-PRIVATE", str(caught.exception))


class EvidenceTests(unittest.TestCase):
    def test_full_span_matches_with_surrounding_whitespace_only(self):
        item = review(violated=True)
        item["findings"][0]["evidence"][0].update(end_line=2, quote="  allow()\nnext()  ")
        documents = {"app.py": {"lines": ["allow()", "next()"], "kind": "python"}}
        self.assertEqual(evidence.validate_review(item, documents), [])
        self.assertEqual(item["findings"][0]["evidence_validation"]["scope"], "locations_and_quotes_only")

    def test_changed_interior_whitespace_and_partial_spans_are_rejected(self):
        documents = {"app.py": {"lines": ["allow()", "    next()"], "kind": "python"}}
        for quote in ("allow()", "allow()\nnext()", "allow()\n..."):
            item = review(violated=True)
            item["findings"][0]["evidence"][0].update(end_line=2, quote=quote)
            self.assertTrue(evidence.validate_review(item, documents))
            self.assertNotIn("evidence_validation", item["findings"][0])

    def test_missing_document_and_range_errors_are_safe(self):
        item = review(violated=True)
        item["findings"][0]["evidence"][0]["quote"] = "PRIVATE-VALUE"
        errors = evidence.validate_review(item, {})
        self.assertTrue(errors)
        self.assertNotIn("PRIVATE-VALUE", " ".join(errors))
        item["findings"][0]["evidence"][0]["start_line"] = 0
        self.assertTrue(evidence.validate_review(item, {"app.py": {"lines": ["allow()"]}}))

    def test_revalidation_clears_previous_success_before_rejecting_a_changed_quote(self):
        item = review(violated=True)
        documents = {"app.py": {"lines": ["allow()"]}}
        self.assertFalse(evidence.validate_review(item, documents))
        item["findings"][0]["evidence"][0]["quote"] = "fabricated()"
        self.assertTrue(evidence.validate_review(item, documents))
        self.assertNotIn("evidence_validation", item["findings"][0])

    def test_docx_locations_are_explicitly_extracted_text(self):
        item = review(violated=True)
        item["findings"][0]["evidence"][0]["path"] = "requirements.docx"
        self.assertEqual(evidence.validate_review(item, {"requirements.docx": {"lines": ["allow()"], "kind": "docx"}}), [])
        self.assertEqual(item["findings"][0]["evidence"][0]["location_kind"], "extracted_document_lines")

    def test_one_invalid_citation_prevents_entire_review_annotation(self):
        item = review(violated=True)
        item["findings"].append(finding(line=9))
        self.assertTrue(evidence.validate_review(item, {"app.py": {"lines": ["allow()"]}}))
        self.assertNotIn("evidence_validation", item["findings"][0])

    def test_deduplication_uses_exact_evidence_and_is_order_independent(self):
        first = finding()
        repeated = deepcopy(first)
        repeated["title"] = "Different model wording"
        second_site = finding(path="other.py")
        second_rule = finding("ИБ-02")
        items = [first, repeated, second_site, second_rule]
        result = evidence.deduplicate(items)
        self.assertEqual(len(result), 3)
        self.assertEqual(result, evidence.deduplicate(list(reversed(items))))
        self.assertEqual(len({item["id"] for item in result}), 3)
        self.assertNotIn("id", first)


class DecisionTests(unittest.TestCase):
    def test_success_violation_and_error_precedence(self):
        self.assertEqual(decision.decide(completed_checks(), []), 0)
        self.assertEqual(decision.decide(completed_checks(True), []), 1)
        self.assertEqual(decision.decide(completed_checks(True), ["unread source"]), 2)

    def test_each_incomplete_status_and_coverage_prevent_success(self):
        for status in ("inconclusive", "error", "unknown"):
            checks = completed_checks()
            checks[-1]["status"] = status
            self.assertEqual(decision.decide(checks, []), 2)
        checks = completed_checks()
        checks[-1]["coverage_complete"] = False
        self.assertEqual(decision.decide(checks, []), 2)

    def test_missing_duplicate_or_contradictory_check_is_an_error(self):
        checks = completed_checks()
        self.assertEqual(decision.decide(checks[:-1], []), 2)
        self.assertEqual(decision.decide(checks[:-1] + [checks[0]], []), 2)
        checks[0]["status"] = "violated"
        self.assertEqual(decision.decide(checks, []), 2)


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name)

    def write(self, checks=None, **kwargs):
        options = {
            "output": self.output,
            "metadata": {"target": {"commit": "abc", "dirty": False, "content_hash": "123"}, "model": "demo", "duration_seconds": 1.2},
            "checks": completed_checks() if checks is None else checks,
            "manifest": {"files": []}, "usage": {"requests": 9, "tokens": None},
            "errors": [], "limitations": [], "redactor": lambda text: text,
        }
        options.update(kwargs)
        return reporting.write_results(**options)

    def test_json_is_source_of_truth_for_markdown_counts_and_log(self):
        result = self.write(completed_checks(True))
        persisted = json.loads((self.output / "report.json").read_text())
        self.assertEqual(result, persisted)
        self.assertEqual(result["exit_code"], 1)
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(len(result["requirements"]), 8)
        markdown = (self.output / "report.md").read_text()
        self.assertIn(result["findings"][0]["id"], markdown)
        self.assertIn("| Код завершения | **1** |", markdown)
        self.assertIn("ИБ-01", (self.output / "run.log").read_text())

    def test_internal_failure_has_report_and_all_eight_statuses(self):
        result = self.write([], errors=["analysis deadline reached"])
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual([check["requirement_id"] for check in result["requirements"]], list(schemas.REQUIREMENT_IDS))
        self.assertTrue(all(check["status"] == "inconclusive" for check in result["requirements"]))
        self.assertTrue((self.output / "report.json").exists())

    def test_external_failure_produces_diagnostics_only_preserving_findings(self):
        result = self.write(completed_checks(True), external_error=True)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["report_type"], "run_diagnostics")
        self.assertEqual(result["finding_count"], 1)
        self.assertFalse((self.output / "report.json").exists())
        self.assertFalse((self.output / "report.md").exists())
        self.assertEqual({path.name for path in self.output.iterdir()}, {"run-status.json", "run-status.md", "run-status.html", "manifest.json", "run.log"})

    def test_every_written_artifact_and_returned_data_are_redacted(self):
        secret = "DEMO-SECRET-VALUE"
        checks = completed_checks(True)
        checks[0]["findings"][0]["explanation"] += secret
        result = self.write(checks, metadata={"model": secret, "target": {"commit": secret}},
                            manifest={"files": [{"path": secret}]}, errors=[secret], limitations=[secret],
                            usage={"provider": secret}, redactor=lambda text: text.replace(secret, "[REDACTED]"))
        self.assertNotIn(secret, json.dumps(result))
        for path in self.output.iterdir():
            self.assertNotIn(secret, path.read_text())

    def test_unverified_candidate_is_not_published_or_converted_to_success(self):
        checks = completed_checks(True)
        del checks[0]["findings"][0]["evidence_validation"]
        result = self.write(checks)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["requirements"][0]["status"], "inconclusive")

    def test_context_provenance_survives_reporting(self):
        checks = completed_checks()
        checks[0]["included_paths"] = ["app.py"]
        checks[0]["context_selection"] = {"included_chunk_ids": ["c1"]}
        result = self.write(checks)
        self.assertEqual(result["requirements"][0]["context_selection"]["included_chunk_ids"], ["c1"])

    def test_duplicate_requirement_and_incomplete_coverage_are_reported(self):
        checks = completed_checks()
        checks[-1] = deepcopy(checks[0])
        result = self.write(checks)
        self.assertEqual(result["exit_code"], 2)
        self.assertEqual(len(result["requirements"]), 8)

    def test_additional_observations_do_not_block_clean_analysis(self):
        result = self.write(metadata={"additional_observations": ["Non-IB usability issue"]})
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("Non-IB usability issue", (self.output / "report.md").read_text())


if __name__ == "__main__":
    unittest.main()
