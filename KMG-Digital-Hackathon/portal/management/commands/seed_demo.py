from django.core.management.base import BaseCommand
from django.contrib.auth.models import Permission
from django.contrib.auth import get_user_model
from helpdesk.models import Queue, Ticket, FollowUp
from portal.models import Ownership
class Command(BaseCommand):
    help = 'Создать синтетические учебные данные; существующие записи не изменяются'
    def handle(self,*args,**options):
        User=get_user_model()
        entries=[('applicant','Ирина','Тестовая','applicant'),('operator','Олег','Учебный','operator'),('administrator','Анна','Демонстрационная','administrator')]
        users={}
        for login,first,last,role in entries:
            u,created=User.objects.get_or_create(username=login,defaults={'first_name':first,'last_name':last,'middle_name':'Макетовна' if login!='operator' else 'Макетович','email':login+'@example.test','role':role,'is_staff':role!='applicant'})
            if created: u.set_password('Training-2026!'+login); u.save()
            users[login]=u
        general,_=Queue.objects.get_or_create(slug='service',defaults={'title':'Рабочие места','allow_public_submission':True,'email_address':'support@example.test'})
        internal,_=Queue.objects.get_or_create(slug='network',defaults={'title':'Сетевая инфраструктура','allow_public_submission':False,'email_address':'network@example.test'})
        permission=Permission.objects.get(codename=general.permission_name.split('.')[1],content_type__app_label='helpdesk')
        users['operator'].user_permissions.add(permission)
        if not Ticket.objects.exists():
            for title,description,queue,owner in [('Не подключается учебный VPN','После обновления клиента отсутствует подключение к тестовому стенду.',general,users['applicant']),('Настроить принтер в лаборатории','Нужна помощь с очередью печати для синтетического отчёта.',general,users['applicant']),('Проверка коммутатора стенда','Проверить доступность учебного сегмента.',internal,users['administrator'])]:
                t=Ticket.objects.create(title=title,description=description,queue=queue,submitter_email=owner.email)
                Ownership.objects.create(ticket=t,user=owner)
                FollowUp.objects.create(ticket=t,user=owner,title='Обращение зарегистрировано',public=True,comment='Ожидает обработки специалистом.')
        self.stdout.write('Учебные данные готовы: 3 роли, 2 очереди, 3 сценария.')
