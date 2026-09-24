from django.contrib.auth.models import AbstractUser
from django.db import models
from .fields import EncryptedCharField, EncryptedEmailField

class User(AbstractUser):
    # ИБ-04: login, full name and e-mail are stored encrypted (see portal/fields.py)
    username = EncryptedCharField(max_length=150, unique=True)
    first_name = EncryptedCharField(max_length=150, blank=True)
    last_name = EncryptedCharField(max_length=150, blank=True)
    middle_name = EncryptedCharField(max_length=150, blank=True)
    email = EncryptedEmailField(blank=True)
    role = models.CharField(max_length=20, choices=[('applicant','Заявитель'),('operator','Оператор'),('administrator','Администратор')], default='applicant')

class Ownership(models.Model):
    ticket = models.OneToOneField('helpdesk.Ticket', on_delete=models.CASCADE, related_name='ownership')
    user = models.ForeignKey(User, on_delete=models.PROTECT)
