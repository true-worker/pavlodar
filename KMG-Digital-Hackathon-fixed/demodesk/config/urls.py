from django.urls import path, include
from django.contrib.auth import views as auth
from django.contrib.auth.decorators import login_required
from portal import views as v
patterns = [
    path('',login_required(v.ticket_list),name='home'),
    path('login/',auth.LoginView.as_view(template_name='portal/login.html'),name='login'),
    path('logout/',login_required(auth.LogoutView.as_view()),name='logout'),
    path('accounts/password/',login_required(auth.PasswordChangeView.as_view(template_name='portal/form.html',success_url='/tickets/')),name='password_change'),
    path('tickets/',login_required(v.ticket_list),name='list'),
    path('tickets/new/',login_required(v.ticket_new),name='submit'),
    path('tickets/bulk/',login_required(v.bulk_status),name='bulk'),
    path('tickets/<int:ticket_id>/',login_required(v.ticket_detail),name='view'),
    path('tickets/<int:ticket_id>/delete/',login_required(v.ticket_delete),name='delete'),
    path('attachments/<int:attachment_id>/',login_required(v.attachment),name='attachment'),
    path('attachments/<int:attachment_id>/delete/',login_required(v.attachment_delete),name='attachment_delete'),
    path('manage/',login_required(v.manage),name='manage'),
    path('manage/users/<int:user_id>/role/',login_required(v.change_role),name='role'),
    path('manage/users/<int:user_id>/queue/',login_required(v.grant_queue),name='queue'),
    path('manage/users/<int:user_id>/password/',login_required(v.reset_password),name='reset_password'),
    path('exports/people.csv',login_required(v.export_csv),name='csv'),
    path('exports/people.json',login_required(v.export_json),name='json'),
    path('api/token/',v.token_issue,name='token'),
    path('api/v1/tickets/',v.ticket_api,name='api_tickets'),
    path('api/v1/tickets/<int:ticket_id>/',v.ticket_api,name='api_ticket'),
    path('api/catalog/tickets/',v.catalog_api,name='catalog'),
    path('api/manage/queues/<int:queue_id>/',v.queue_api,name='api_queue'),
]
urlpatterns = [path('',include((patterns,'helpdesk'),namespace='helpdesk'))]
