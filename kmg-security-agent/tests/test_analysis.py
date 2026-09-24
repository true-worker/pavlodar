import json
from pathlib import Path
import tempfile
import unittest
from kmg_security_agent import analysis, inventory, reporting
from kmg_security_agent.llm import ExternalError, BudgetError
from kmg_security_agent.security import Redactor

class FakeClient:
    """A protocol fixture, not a security model or a model-quality test."""
    max_requests = 100
    def __init__(self, mode='clean'):
        self.mode = mode
        self.usage = {'requests': 0}
        self.progress = lambda _:None
    def complete(self, system, user, **kwargs):
        self.usage['requests'] += 1
        if self.mode == 'external': raise ExternalError('API HTTP 429: лимит запросов')
        if self.mode == 'timeout': raise BudgetError('Исчерпан лимит времени')
        if kwargs['name'] == 'source_overview':
            ids = json.loads(user.split('EXPECTED_CHUNK_IDS:\n')[1].split('\nSOURCE:')[0])
            if self.mode == 'missing_chunk': ids=[]
            return json.dumps({'reviewed_chunk_ids':ids,'summary':'All source inspected.','candidates':[],'related_paths':['app.py']})
        rid = user.split('Check requirement ')[1].split('.')[0]
        finding = {'requirement_id':rid, 'title':'Synthetic defect', 'severity':'high', 'explanation':'Fixture only',
                   'recommendation':'Fixture only', 'evidence':[{'path':'app.py','start_line':1,'end_line':1,'quote':'FLAG = False'}]}
        if self.mode == 'bad_quote': finding['evidence'][0]['quote']='fabricated()'
        violated = self.mode in ('violation','bad_quote') and rid == 'ИБ-01'
        return json.dumps({'requirement_id':rid,'status':'violated' if violated else 'no_violations_found',
                           'rationale':'Synthetic response for infrastructure test', 'findings':[finding] if violated else [],'limitations':[]})

class PipelineTests(unittest.TestCase):
    def run_case(self, mode):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            repo=root/'repo'
            repo.mkdir()
            (repo/'app.py').write_text('FLAG = False\n')
            redactor=Redactor('private-key-value')
            data=inventory.collect(repo,redactor)
            self.assertEqual(data['errors'], [])
            client=FakeClient(mode)
            result=analysis.scan(client,data)
            output=root/'output'
            report=reporting.write_results(output,{'run_id':'test','target':data['target'],'model':'fake'},result['checks'],
                   inventory.public_manifest(data),client.usage,result['errors'],[],redactor,external_error=result['external_error'])
            files={p.name:p.read_text() for p in output.iterdir() if p.is_file()}
            return result,report,files
    def test_all_eight_completed_clean_exit_zero(self):
        result,report,files=self.run_case('clean')
        self.assertEqual(report['exit_code'],0)
        self.assertEqual(len(result['checks']),8)
        self.assertIn('report.json',files)
    def test_confirmed_violation_exit_one(self):
        result,report,files=self.run_case('violation')
        self.assertEqual(report['exit_code'],1)
        self.assertEqual(len(report['findings']),1)
        self.assertIn('source_quote_match',files['report.json'])
    def test_false_quote_never_becomes_clean(self):
        result,report,files=self.run_case('bad_quote')
        self.assertEqual(report['exit_code'],2)
        self.assertEqual(len(report['findings']),0)
        self.assertTrue(result['errors'])
    def test_missing_overview_chunk_blocks_scan(self):
        result,report,files=self.run_case('missing_chunk')
        self.assertEqual(report['exit_code'],2)
        self.assertEqual(result['coverage']['completed_chunk_ids'],[])
    def test_api_error_diagnostics_not_compliance_report(self):
        result,report,files=self.run_case('external')
        self.assertEqual(report['exit_code'],2)
        self.assertIn('run-status.json',files)
        self.assertNotIn('report.json',files)
    def test_timeout_keeps_incomplete_report(self):
        result,report,files=self.run_case('timeout')
        self.assertEqual(report['exit_code'],2)
        self.assertIn('report.json',files)
        self.assertNotIn('run-status.json',files)

if __name__ == '__main__': unittest.main()
