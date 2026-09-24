from django.contrib.auth.models import AbstractUser
from django.db import models
from django.db.models import CharField, EmailField

class User(AbstractUser):
    username = CharField(max_length=150, unique=True)
    first_name = CharField(max_length=150, blank=True)
    last_name = CharField(max_length=150, blank=True)
    middle_name = CharField(max_length=150, blank=True)
    email = EmailField(blank=True)
    role = models.CharField(max_length=20, choices=[('applicant','Заявитель'),('operator','Оператор'),('administrator','Администратор')], default='applicant')

class Ownership(models.Model):
    ticket = models.OneToOneField('helpdesk.Ticket', on_delete=models.CASCADE, related_name='ownership')
    user = models.ForeignKey(User, on_delete=models.PROTECT)
