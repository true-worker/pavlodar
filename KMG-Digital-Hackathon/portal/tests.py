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
