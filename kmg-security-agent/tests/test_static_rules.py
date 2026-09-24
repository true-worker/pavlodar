"""Deterministic rules on a synthetic Django project: every rule must fire on the
unsafe variant and stay silent on the corrected one (false-positive control)."""
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from kmg_security_agent import analysis, cli, inventory, readers, static_rules
from kmg_security_agent.security import Redactor

REFERENCES = '''## Нормативные источники
1. Закон РК от 24.11.2015 № 418-V «О кибербезопасности».
2. Закон РК от 21.05.2013 № 94-V «О персональных данных и их защите».
3. Постановление Правительства РК от 20.12.2016 № 832.
4. СТ РК ISO/IEC 27001-2023. 5. СТ РК ISO/IEC 27002-2023. 6. СТ РК 1073-2007.
'''


def project(safe: bool) -> dict:
    files = {}
    files['app/settings.py'] = f'''
from pathlib import Path
RUNTIME = Path('runtime')
LOG_KEY_FILE = RUNTIME / {"'keys'" if safe else "'journal'"} / 'journal.key'
INSTALLED_APPS = ['django.contrib.auth', 'accounts']
MIDDLEWARE = ['django.contrib.sessions.middleware.SessionMiddleware', 'accounts.middleware.AuditMiddleware' if {safe} else 'accounts.middleware.Noop']
ROOT_URLCONF = 'app.urls'
AUTH_USER_MODEL = 'accounts.User'
DATABASES = {{'default': {{'ENGINE': 'django.db.backends.sqlite3', 'NAME': 'db.sqlite3'}}}}
PASSWORD_HASHERS = [{"'django.contrib.auth.hashers.Argon2PasswordHasher'" if safe else "'django.contrib.auth.hashers.MD5PasswordHasher'"}]
SESSION_COOKIE_SECURE = {safe}
CSRF_COOKIE_SECURE = {safe}
SECURE_SSL_REDIRECT = {safe}
SECURE_HSTS_SECONDS = {31536000 if safe else 0}
'''
    files['app/urls.py'] = '''
from django.urls import path
from django.contrib.auth import views as auth
from accounts import views as v
urlpatterns = [
    path('login/', auth.LoginView.as_view(), name='login'),
    path('manage/users/', v.manage_users),
    path('api/manage/queues/<int:pk>/', v.rename_queue),
    path('exports/people.json', v.export_json),
    path('api/catalog/', v.catalog),
    path('tickets/bulk/', v.bulk),
    path('api/tickets/', v.ticket_api),
]
'''
    files['accounts/__init__.py'] = ''
    files['accounts/access.py'] = f'''
from functools import wraps
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required

def administrator(user):
    return user.is_authenticated and user.role == 'administrator'

def admin_required(view):
    @login_required
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not {"administrator(request.user)" if safe else "request.user.is_staff"}: raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapped
'''
    files['accounts/audit.py'] = '''
def record(action, obj, **details):
    return {'action': action, 'object': obj, 'details': details}
'''
    files['accounts/middleware.py'] = '''
from . import audit
from django.db.backends.signals import connection_created
connection_created.connect(lambda **kw: audit.record('db_connect', 'default'))
class AuditMiddleware:
    def __init__(self, get_response): self.get_response = get_response
    def __call__(self, request):
        response = self.get_response(request)
        audit.record('request', request.path, status=response.status_code)
        return response
class Noop:
    def __init__(self, get_response): self.get_response = get_response
    def __call__(self, request): return self.get_response(request)
''' if safe else '''
class Noop:
    def __init__(self, get_response): self.get_response = get_response
    def __call__(self, request): return self.get_response(request)
'''
    files['accounts/fields.py'] = '''
from django.db import models
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
class EncryptedCharField(models.CharField):
    def get_prep_value(self, value):
        return AESGCM(b'k' * 32).encrypt(b'n' * 12, value.encode(), None)
'''
    field = 'EncryptedCharField' if safe else 'CharField'
    files['accounts/models.py'] = f'''
from django.contrib.auth.models import AbstractUser
from django.db.models import CharField
from .fields import EncryptedCharField
class User(AbstractUser):
    first_name = {field}(max_length=150)
    last_name = {field}(max_length=150)
    email = {field}(max_length=254)
'''
    guard = '@access.admin_required' if safe else '@login_required'
    files['accounts/views.py'] = f'''
from django.contrib.auth.decorators import login_required
from django.core import signing
from django.http import JsonResponse
from . import access, audit
from .models import User

@access.admin_required
def manage_users(request):
    return JsonResponse({{'users': list(User.objects.values('username'))}})

{guard}
def rename_queue(request, pk):
    return JsonResponse({{'ok': True}})

{guard}
def export_json(request):
    rows = list(User.objects.values('username', 'email'))
    {"audit.record('export', 'people:json', count=len(rows))" if safe else "pass"}
    return JsonResponse({{'people': rows}})

{"@login_required" if safe else ""}
def catalog(request):
    return JsonResponse({{'items': []}})

@login_required
def bulk(request):
    User.objects.filter(pk__in=[1]).update(is_active=False)
    return JsonResponse({{}})

def ticket_api(request):
    header = request.headers.get('Authorization', '')
    data = signing.loads(header[7:], salt='api'{", max_age=900" if safe else ""})
    return JsonResponse(data)
'''
    files['proxy.json'] = json.dumps({
        'minimum_tls': 'TLSv1_2' if safe else 'TLSv1',
        'ciphers': 'ECDHE-RSA-AES256-GCM-SHA384' if safe else 'ECDHE-RSA-AES256-GCM-SHA384:AES128-SHA',
        'http_redirect': safe}, indent=2)
    files['README.md'] = '# Demo\n\n' + (REFERENCES if safe else REFERENCES.replace('СТ РК 1073-2007', ''))
    return files


class StaticRuleTests(unittest.TestCase):
    def scan(self, safe):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, text in project(safe).items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(text, encoding='utf-8')
            data = inventory.collect(root, Redactor())
            self.assertEqual(data['errors'], [])
            return data, analysis.static_checks(data)

    def test_unsafe_project_violates_every_requirement(self):
        _, result = self.scan(False)
        status = {c['requirement_id']: c['status'] for c in result['checks']}
        self.assertEqual(set(status.values()), {'violated'}, status)
        titles = ' '.join(f['title'] for c in result['checks'] for f in c['findings'])
        for fragment in ('is_staff', 'без проверки сессии', 'без ограничения срока', 'нестойкие', 'перенаправления',
                         'не bcrypt', 'открытым текстом', 'каталоге журнала', 'Пакетные', 'СУБД', 'Выгрузка'):
            self.assertIn(fragment, titles)

    def test_corrected_project_has_no_findings(self):
        _, result = self.scan(True)
        findings = {c['requirement_id']: [f['title'] for f in c['findings']] for c in result['checks'] if c['findings']}
        self.assertEqual(findings, {})

    def test_findings_carry_verified_quotes(self):
        data, result = self.scan(False)
        for check in result['checks']:
            for finding in check['findings']:
                self.assertEqual(finding['evidence_validation']['method'], 'source_quote_match')
                for item in finding['evidence']:
                    lines = data['documents'][item['path']]['lines'][item['start_line'] - 1:item['end_line']]
                    self.assertEqual('\n'.join(lines).strip(), item['quote'].strip())

    def test_shared_guard_is_one_finding(self):
        _, result = self.scan(False)
        ib01 = next(c for c in result['checks'] if c['requirement_id'] == 'ИБ-01')
        staff = [f for f in ib01['findings'] if 'is_staff' in f['title']]
        self.assertEqual(len(staff), 1)

    def test_weak_cipher_classifier(self):
        self.assertEqual(static_rules.weak_ciphers('ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305'), [])
        self.assertEqual(static_rules.weak_ciphers('ECDHE-RSA-AES128-SHA:AES128-GCM-SHA256:HIGH:!aNULL'),
                         ['ECDHE-RSA-AES128-SHA', 'AES128-GCM-SHA256', 'HIGH'])


class CombineTests(unittest.TestCase):
    def test_llm_findings_are_merged_without_duplicates(self):
        static = {'checks': [{'requirement_id': rid, 'status': 'no_violations_found', 'rationale': 'r', 'findings': [],
                              'limitations': [], 'coverage_complete': True} for rid in static_rules.REQUIREMENT_IDS]}
        static['checks'][0] = dict(static['checks'][0], status='violated', findings=[
            {'requirement_id': 'ИБ-01', 'title': 's', 'severity': 'high', 'explanation': 'e', 'recommendation': 'r',
             'evidence': [{'path': 'a.py', 'start_line': 3, 'end_line': 3, 'quote': 'x'}]}])
        def llm_finding(rid, line):
            return {'requirement_id': rid, 'title': 'm', 'severity': 'high', 'explanation': 'e', 'recommendation': 'r',
                    'evidence': [{'path': 'a.py', 'start_line': line, 'end_line': line, 'quote': 'y'}]}
        llm = {'checks': [
            {'requirement_id': 'ИБ-01', 'status': 'violated', 'coverage_complete': True, 'rationale': 'm',
             'findings': [llm_finding('ИБ-01', 3)], 'limitations': []},
            {'requirement_id': 'ИБ-02', 'status': 'violated', 'coverage_complete': True, 'rationale': 'm',
             'findings': [llm_finding('ИБ-02', 9)], 'limitations': []},
            {'requirement_id': 'ИБ-03', 'status': 'inconclusive', 'coverage_complete': False, 'rationale': 'timeout',
             'findings': [], 'limitations': []}]}
        checks = {c['requirement_id']: c for c in analysis.combine(static, llm)}
        self.assertEqual(len(checks['ИБ-01']['findings']), 1)
        self.assertEqual(checks['ИБ-02']['status'], 'violated')
        self.assertEqual(checks['ИБ-02']['findings'][0]['detected_by'], 'llm')
        self.assertEqual(checks['ИБ-02']['analysis_methods'], ['static_rules', 'llm'])
        self.assertEqual(checks['ИБ-03']['status'], 'no_violations_found')
        self.assertTrue(any('не завершён' in item for item in checks['ИБ-03']['limitations']))
        self.assertTrue(all(c['coverage_complete'] for c in checks.values()))


class HybridModeTests(unittest.TestCase):
    def run_cli(self, safe, *extra):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            for name, text in project(safe).items():
                (repo / name).parent.mkdir(parents=True, exist_ok=True)
                (repo / name).write_text(text, encoding='utf-8')
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.dict('os.environ', {}, clear=False) as env, redirect_stdout(out), redirect_stderr(err):
                env.pop('OPENROUTER_API_KEY', None)
                env.pop('LLM_API_KEY', None)
                code = cli.main(['--env-file', str(root / 'missing.env'), 'scan', '--repo', str(repo),
                                 '--output', str(root / 'reports'), *extra])
            reports = list((root / 'reports').glob('*/report.json'))
            report = json.loads(reports[0].read_text(encoding='utf-8')) if reports else None
            return code, report, err.getvalue()

    def test_missing_model_key_falls_back_to_rules(self):
        code, report, log = self.run_cli(False)
        self.assertEqual(code, 1)
        self.assertEqual(report['exit_code'], 1)
        self.assertIn('Нарушений ИБ:', log)
        self.assertTrue(any('LLM-анализ не завершён' in item for item in report['limitations']))

    def test_clean_project_exit_zero_without_model(self):
        code, report, _ = self.run_cli(True, '--mode', 'static')
        self.assertEqual((code, report['result']), (0, 'no_violations_found'))

    def test_strict_llm_turns_missing_model_into_error(self):
        code, _, _ = self.run_cli(True, '--strict-llm')
        self.assertEqual(code, 2)


class PortableReaderTests(unittest.TestCase):
    """The Windows code path (no dir_fd/O_NOFOLLOW) must read exactly the same inventory."""

    def test_portable_walker_matches_posix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, text in project(False).items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(text, encoding='utf-8')
            (root / '.env').write_text('SECRET=1')
            first = inventory.collect(root, Redactor())
            with mock.patch.object(readers, 'SECURE_FS', False), mock.patch.object(inventory, 'SECURE_FS', False):
                second = inventory.collect(root, Redactor())
                self.assertEqual(inventory.check_unchanged(second), [])
            self.assertEqual(first['target']['content_hash'], second['target']['content_hash'])
            self.assertNotIn('.env', second['documents'])

    def test_portable_reader_refuses_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'real.py').write_text('x = 1\n')
            try:
                (root / 'link.py').symlink_to(root / 'real.py')
            except (OSError, NotImplementedError):
                self.skipTest('symlinks unavailable')
            with mock.patch.object(readers, 'SECURE_FS', False):
                with self.assertRaises(readers.ReadError):
                    readers.read_bytes(root, 'link.py', 1000)


class WindowsLineEndingTests(unittest.TestCase):
    @unittest.skipUnless(__import__('shutil').which('git'), 'git not installed')
    def test_crlf_checkout_is_not_reported_dirty(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'app.py').write_bytes(b'x = 1\r\ny = 2\r\n')
            def git(*args):
                subprocess.run(['git', '-c', 'core.autocrlf=true', '-c', 'core.safecrlf=false', '-c', 'commit.gpgsign=false',
                                '-c', 'user.name=t', '-c', 'user.email=t@example.test', '-C', str(root), *args],
                               check=True, capture_output=True)
            git('init', '-q'); git('add', '.'); git('commit', '-qm', 'crlf')
            self.assertIs(inventory.collect(root, Redactor())['target']['dirty'], False)
            (root / 'app.py').write_bytes(b'x = 1\r\ny = 3\r\n')
            self.assertIs(inventory.collect(root, Redactor())['target']['dirty'], True)


if __name__ == '__main__':
    unittest.main()
