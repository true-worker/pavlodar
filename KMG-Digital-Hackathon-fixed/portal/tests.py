from django.test import TestCase
from django.core.management import call_command
from helpdesk.models import Ticket
class WorkflowTests(TestCase):
    @classmethod
    def setUpTestData(cls): call_command('seed_demo',verbosity=0)
    def test_support_workflow(self):
        self.assertTrue(self.client.login(username='applicant',password='Training-2026!applicant'))
        self.assertEqual(self.client.get('/tickets/',secure=True).status_code,200)
        queue=Ticket.objects.first().queue_id
        response=self.client.post('/tickets/new/',{'title':'Учебный запрос','description':'Тест обращения','queue':queue},secure=True)
        self.assertEqual(response.status_code,302)
        response=self.client.get(response.url,secure=True)
        self.assertContains(response,'Учебный запрос')


class SecurityRegressionTests(TestCase):
    """Behavioural checks of the ИБ fixes in this corrected copy."""

    @classmethod
    def setUpTestData(cls):
        call_command('seed_demo', verbosity=0)

    def login(self, name):
        self.assertTrue(self.client.login(username=name, password='Training-2026!' + name))

    def test_ib01_operator_has_no_admin_interface(self):
        self.login('operator')
        self.assertEqual(self.client.get('/manage/', secure=True).status_code, 403)
        from portal.models import User
        target = User.objects.get(username='operator')
        self.assertEqual(self.client.post(f'/manage/users/{target.pk}/role/', {'role': 'administrator'}, secure=True).status_code, 403)
        target.refresh_from_db()
        self.assertEqual(target.role, 'operator')
        self.assertEqual(self.client.post('/api/manage/queues/1/', '{"title":"x"}', content_type='application/json', secure=True).status_code, 403)

    def test_ib01_administrator_has_admin_interface(self):
        self.login('administrator')
        self.assertEqual(self.client.get('/manage/', secure=True).status_code, 200)

    def test_ib02_catalog_requires_login_and_token_expires(self):
        self.assertEqual(self.client.get('/api/catalog/tickets/', secure=True).status_code, 302)
        self.login('applicant')
        token = self.client.post('/api/token/', secure=True).json()['token']
        auth = {'HTTP_AUTHORIZATION': 'Bearer ' + token}
        self.assertEqual(self.client.get('/api/v1/tickets/', secure=True, **auth).status_code, 200)
        from unittest import mock
        import time
        with mock.patch('time.time', return_value=time.time() + 901):
            self.assertEqual(self.client.get('/api/v1/tickets/', secure=True, **auth).status_code, 401)

    def test_ib02_password_change_revokes_token(self):
        self.login('applicant')
        token = self.client.post('/api/token/', secure=True).json()['token']
        from portal.models import User
        user = User.objects.get(username='applicant')
        user.set_password('Another-Training-2026!'); user.save()
        self.assertEqual(self.client.get('/api/v1/tickets/', secure=True, HTTP_AUTHORIZATION='Bearer ' + token).status_code, 401)

    def test_ib04_personal_data_is_ciphertext_in_database(self):
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute('SELECT username, email, last_name FROM portal_user')
            rows = cursor.fetchall()
        self.assertTrue(rows)
        self.assertTrue(all(value.startswith('enc1:') for row in rows for value in row if value))
        from portal.models import User
        self.assertEqual(User.objects.get(username='applicant').username, 'applicant')

    def test_ib08_export_requires_admin_and_is_audited(self):
        self.login('operator')
        self.assertEqual(self.client.get('/exports/people.json', secure=True).status_code, 403)
        self.client.logout()
        self.login('administrator')
        from unittest import mock
        with mock.patch('portal.views.audit.record') as record:
            self.assertEqual(self.client.get('/exports/people.json', secure=True).status_code, 200)
        self.assertTrue(any(call.args[:2] == ('export', 'people:json') for call in record.call_args_list))

    def test_ib07_reads_and_bulk_changes_are_audited(self):
        self.login('operator')
        from unittest import mock
        with mock.patch('portal.middleware.record') as record:
            self.client.get('/tickets/', secure=True)
        self.assertTrue(any(call.args[0] == 'request' for call in record.call_args_list))
        with mock.patch('portal.views.audit.record') as record, self.captureOnCommitCallbacks(execute=True):
            self.client.post('/tickets/bulk/', {'ids': ['1'], 'status': '1'}, secure=True)
        self.assertTrue(any(call.args[0] == 'bulk_status' for call in record.call_args_list))
