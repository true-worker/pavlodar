import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error
from kmg_security_agent.config import Config, ConfigError, load_config
from kmg_security_agent.security import Redactor
from kmg_security_agent.llm import LLMClient, AgentError, BudgetError, ExternalError, NoRedirect

class Response(io.BytesIO):
    pass

class Opener:
    def __init__(self, response):
        self.response = response
        self.requests = []
    def open(self, request, timeout):
        self.requests.append((request, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return Response(json.dumps(self.response).encode())

class ConfigTests(unittest.TestCase):
    def test_env_precedence_and_no_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = Path(tmp)/'.env'
            env.write_text('OPENROUTER_API_KEY="$(not-executed)"\nOPENROUTER_MODEL=qwen/test:free\n')
            with patch.dict(os.environ, {'OPENROUTER_MODEL':'qwen/env:free'}, clear=True):
                config = load_config(env)
            self.assertEqual(config.api_key, '$(not-executed)')
            self.assertEqual(config.model, 'qwen/env:free')
            self.assertNotIn('$(not-executed)', repr(config))
    def test_paid_model_requires_explicit_setting(self):
        with patch.dict(os.environ, {'OPENROUTER_API_KEY':'fake', 'OPENROUTER_MODEL':'paid/model'}, clear=True):
            with self.assertRaises(ConfigError): load_config(Path('/does-not-exist'))
    def test_remote_http_rejected(self):
        with patch.dict(os.environ, {'OPENROUTER_API_KEY':'fake','OPENROUTER_BASE_URL':'http://evil.test/api'}, clear=True):
            with self.assertRaises(ConfigError): load_config(Path('/does-not-exist'))
    def test_secrets_redacted_without_line_shift(self):
        source = 'API_KEY = "private-token"\nsecret_key="inline-value"\n-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n'
        masked = Redactor('private-token')(source)
        self.assertNotIn('private-token', masked)
        self.assertNotIn('inline-value', masked)
        self.assertNotIn('abc', masked)
        self.assertEqual(source.count('\n'), masked.count('\n'))
        self.assertEqual(Redactor()('if user.password == expected:\n    return token'), 'if user.password == expected:\n    return token')

class LLMTests(unittest.TestCase):
    def make_client(self, response, **kwargs):
        client = LLMClient(Config('fake-key'), **kwargs)
        client.opener = Opener(response)
        return client
    def test_usage_and_zero_price_payload(self):
        client = self.make_client({'choices':[{'message':{'content':'OK'},'finish_reason':'stop'}], 'usage':{'prompt_tokens':3,'completion_tokens':1,'total_tokens':4}})
        self.assertEqual(client.complete('system','user'), 'OK')
        self.assertEqual(client.usage['total_tokens'], 4)
        body = json.loads(client.opener.requests[0][0].data)
        self.assertEqual(body['provider']['max_price'], {'prompt':0,'completion':0})
        self.assertNotIn('models', body)
        self.assertEqual(body['messages'][0]['role'], 'system')
    def test_truncated_output_is_never_success(self):
        client = self.make_client({'choices':[{'message':{'content':'partial'},'finish_reason':'length'}]})
        with self.assertRaises(AgentError): client.complete('s','u')
    def test_401_does_not_leak_error_body(self):
        err = urllib.error.HTTPError('https://example.test',401,'fake-key',{},io.BytesIO(b'fake-key'))
        client = self.make_client(err)
        with self.assertRaises(ExternalError) as raised: client.complete('s','u')
        self.assertNotIn('fake-key', str(raised.exception))
        self.assertEqual(client.usage['requests'], 1)
    def test_retry_after_cannot_exceed_deadline(self):
        err = urllib.error.HTTPError('https://example.test',429,'',{'Retry-After':'90'},io.BytesIO())
        client = self.make_client(err, timeout=10)
        with self.assertRaises(BudgetError): client.complete('s','u')
        self.assertEqual(client.usage['requests'], 1)
    def test_max_requests_counts_failed_attempts(self):
        client = self.make_client({'choices':[{'message':{'content':'OK'},'finish_reason':'stop'}]}, max_requests=1)
        client.complete('s','u')
        with self.assertRaises(BudgetError): client.complete('s','u')
        self.assertEqual(len(client.opener.requests), 1)
    def test_redirect_is_not_followed_with_secret(self):
        self.assertIsNone(NoRedirect().redirect_request(None,None,302,'',{},'https://other.test'))

if __name__ == '__main__': unittest.main()
