from django.core.management.base import BaseCommand
from django.conf import settings
from portal.local_acl import set_reader_access
class Command(BaseCommand):
    help='Изменить доступ локального читателя к файлу SQLite'
    def add_arguments(self,parser): parser.add_argument('access',choices=['none','read'])
    def handle(self,*args,**options):
        set_reader_access(settings.DATABASES['default']['NAME'],options['access'])
        self.stdout.write('Database file access updated')
