import argparse
import ast
from contextlib import redirect_stdout,redirect_stderr
import io
import json
from pathlib import Path
import signal
import tempfile
import time
import unittest
from unittest.mock import patch
from kmg_security_agent import cli,schemas
from kmg_security_agent.config import Config
from kmg_security_agent.llm import LLMClient,transport_schema
from kmg_security_agent.security import Redactor
from test_runtime import Opener

class HardeningTests(unittest.TestCase):
    def test_escaped_quotes_in_secret_do_not_expose_tail_or_break_python(self):
        source = 'password = "prefix \\"synthetic-tail"\nuser.set_password("start \\"other-secret")\n'
        ast.parse(source)
        masked=Redactor()(source)
        ast.parse(masked)
        self.assertNotIn('synthetic-tail',masked)
        self.assertNotIn('other-secret',masked)
        self.assertEqual(source.count('\n'),masked.count('\n'))
    def test_missing_usage_is_explicit_not_zero_claim(self):
        client=LLMClient(Config('fake'))
        client.opener=Opener({'choices':[{'message':{'content':'OK'},'finish_reason':'stop'}],'usage':{}})
        client.complete('s','u')
        self.assertFalse(client.usage['tokens_complete'])
        self.assertEqual(client.usage['usage_missing_responses'],1)
    def test_transport_schema_does_not_weaken_local_validation(self):
        remote=transport_schema(schemas.BATCH_SCHEMA)
        self.assertNotIn('uniqueItems',remote['properties']['reviewed_chunk_ids'])
        self.assertTrue(schemas.BATCH_SCHEMA['properties']['reviewed_chunk_ids']['uniqueItems'])
        self.assertFalse(remote['additionalProperties'])
        self.assertEqual(remote['required'],schemas.BATCH_SCHEMA['required'])
    @unittest.skipUnless(hasattr(signal,'setitimer'),'POSIX deadline test')
    def test_inventory_is_inside_wall_clock_budget_and_writes_partial_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); repo=root/'repo'; repo.mkdir()
            args=argparse.Namespace(repo=repo,output=root/'reports',timeout=0.04,request_timeout=10,max_requests=20)
            def slow_inventory(*a,**kw): time.sleep(1)
            start=time.monotonic()
            with patch('kmg_security_agent.inventory.collect',side_effect=slow_inventory),redirect_stdout(io.StringIO()),redirect_stderr(io.StringIO()):
                code=cli._run_scan(args,Config('fake'),Redactor())
            self.assertEqual(code,2)
            self.assertLess(time.monotonic()-start,0.8)
            reports=list((root/'reports').glob('*/report.json'))
            self.assertEqual(len(reports),1)
            self.assertEqual(json.loads(reports[0].read_text())['exit_code'],2)

if __name__=='__main__': unittest.main()
