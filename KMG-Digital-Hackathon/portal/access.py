from functools import wraps
from django.core.exceptions import PermissionDenied
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from helpdesk.models import Queue, Ticket

def administrator(user):
    return user.is_authenticated and user.is_active and user.role == 'administrator'

def admin_required(view):
    @login_required
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not administrator(request.user): raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapped

def manage_required(view):
    @login_required
    @wraps(view)
    def wrapped(request, *args, **kwargs):
        if not request.user.is_staff: raise PermissionDenied
        return view(request, *args, **kwargs)
    return wrapped

def queues(user):
    if administrator(user): return Queue.objects.all()
    if user.role == 'operator':
        permissions = user.get_all_permissions()
        return Queue.objects.filter(permission_name__in=permissions)
    return Queue.objects.filter(allow_public_submission=True)

def tickets(user):
    if administrator(user): return Ticket.objects.all()
    if user.role == 'operator': return Ticket.objects.filter(queue__in=queues(user))
    return Ticket.objects.filter(ownership__user=user)

def operator_required(user):
    if user.role not in ('operator', 'administrator'): raise PermissionDenied
