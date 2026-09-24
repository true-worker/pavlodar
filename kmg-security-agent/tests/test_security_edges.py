"""Offline regressions for credential masking and incomplete live-evaluation results."""
from argparse import Namespace
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from kmg_security_agent.cli import _run_evaluate
from kmg_security_agent.config import Config
from kmg_security_agent.security import Redactor


class SecretSourceMaskingTests(unittest.TestCase):
    def test_common_source_credentials_are_masked_without_line_shift(self):
        marker = 'synthetic-credential-593'
        samples = {
            'plain_yaml': f'password: {marker}\n',
            'prefixed_yaml': f'database_password: {marker} # service setting\n',
            'prefixed_assignment': f'DATABASE_PASSWORD = "{marker}"\n',
            'service_api_key': f'SERVICE_API_KEY = "{marker}"\n',
            'set_password': f'user.set_password("{marker}")\n',
            'make_password': f'encoded = make_password("{marker}")\n',
            'check_password': f'user.check_password("{marker}")\n',
        }
        for name, source in samples.items():
            with self.subTest(name=name):
                masked = Redactor()(source)
                self.assertNotIn(marker, masked)
                self.assertIn('[REDACTED]', masked)
                self.assertEqual(source.count('\n'), masked.count('\n'))

    def test_variable_values_and_authorization_predicates_remain_visible(self):
        source = ('password = request.password\n'
                  'if user.password == expected:\n'
                  '    return token\n'
                  'user.set_password(form.cleaned_data["password"])\n')
        self.assertEqual(Redactor()(source), source)


class EvaluationCoverageTests(unittest.TestCase):
    def evaluate(self, review, expected_status):
        with tempfile.TemporaryDirectory(prefix='kmg-evaluation-edge-') as directory:
            root = Path(directory)
            fixtures = root / 'fixtures'
            case = fixtures / 'one-case'
            case.mkdir(parents=True)
            (case / 'source.py').write_text('def route():\n    return 200\n', encoding='utf-8')
            labels = {'cases': [{
                'id': 'one-case', 'repo': 'one-case', 'requirement_id': 'ИБ-01',
                'expected_status': expected_status, 'expected_evidence_paths': [],
            }]}
            (fixtures / 'labels.json').write_text(json.dumps(labels), encoding='utf-8')
            args = Namespace(fixtures=fixtures, output=root / 'reports', timeout=5,
                             request_timeout=2, max_requests=1)
            with patch('kmg_security_agent.analysis.review_requirement', return_value=review), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = _run_evaluate(args, Config('synthetic-unused-api-key'), Redactor())
            output = next((root / 'reports').glob('*/evaluation.json'))
            return code, json.loads(output.read_text(encoding='utf-8'))

    def test_inconclusive_review_is_incomplete_not_a_completed_mismatch(self):
        review = {'requirement_id': 'ИБ-01', 'status': 'inconclusive',
                  'rationale': 'Required context is missing', 'findings': [],
                  'limitations': ['Missing protection chain'], 'coverage_complete': False}
        code, result = self.evaluate(review, 'violated')
        self.assertEqual(code, 2)
        self.assertFalse(result['complete'])
        self.assertTrue(result['metrics_are_partial'])
        self.assertTrue(result['errors'])

    def test_partial_coverage_cannot_pass_even_when_status_matches(self):
        review = {'requirement_id': 'ИБ-01', 'status': 'no_violations_found',
                  'rationale': 'No issue in inspected route', 'findings': [],
                  'limitations': ['Another required route omitted'], 'coverage_complete': False}
        code, result = self.evaluate(review, 'no_violations_found')
        self.assertEqual(code, 2)
        self.assertFalse(result['complete'])
        self.assertTrue(result['metrics_are_partial'])

    def test_complete_matching_review_still_passes(self):
        review = {'requirement_id': 'ИБ-01', 'status': 'no_violations_found',
                  'rationale': 'Protection chain inspected', 'findings': [],
                  'limitations': [], 'coverage_complete': True}
        code, result = self.evaluate(review, 'no_violations_found')
        self.assertEqual(code, 0)
        self.assertTrue(result['complete'])
        self.assertFalse(result['metrics_are_partial'])
        self.assertEqual(result['correct_cases'], 1)


if __name__ == '__main__':
    unittest.main()
