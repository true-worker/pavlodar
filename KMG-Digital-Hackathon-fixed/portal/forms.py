from django import forms
from .models import User
from helpdesk.models import Ticket
class TicketForm(forms.Form):
    title = forms.CharField(label='Тема', max_length=200)
    description = forms.CharField(label='Описание', widget=forms.Textarea)
    queue = forms.ModelChoiceField(label='Очередь', queryset=None)
    def __init__(self, *args, queues, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['queue'].queryset = queues
class UpdateForm(forms.Form):
    status = forms.ChoiceField(label='Статус', choices=Ticket.STATUS_CHOICES)
    comment = forms.CharField(label='Комментарий', widget=forms.Textarea, required=False, max_length=20000)
    public = forms.BooleanField(label='Виден заявителю', required=False, initial=True)
    attachment = forms.FileField(label='Вложение (txt, pdf, png, jpg, до 1 МБ)', required=False)
    def clean_attachment(self):
        from pathlib import Path
        f = self.cleaned_data.get('attachment')
        if f and (f.size > 1024*1024 or Path(f.name).suffix.lower() not in ('.txt','.pdf','.png','.jpg')):
            raise forms.ValidationError('Недопустимый тип или размер файла')
        return f
class PersonForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['username','first_name','last_name','middle_name','email','role']
    password = forms.CharField(label='Начальный пароль', widget=forms.PasswordInput, min_length=12)
