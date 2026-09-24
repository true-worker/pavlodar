import csv, io, json, time
from pathlib import Path
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import SetPasswordForm
from django.core import signing
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.http import JsonResponse, HttpResponse, FileResponse
from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_POST, require_GET
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.models import Permission
from helpdesk.models import Ticket, Queue, FollowUp, TicketChange, FollowUpAttachment
from .models import Ownership
from . import access, audit
from .forms import TicketForm, UpdateForm, PersonForm

User = get_user_model()

@login_required
def ticket_list(request):
    rows = list(access.tickets(request.user).select_related('queue').order_by('-modified'))
    query = request.GET.get('q', '').strip().lower()
    if query: rows = [r for r in rows if query in r.title.lower() or query in (r.description or '').lower()]

    return render(request, 'portal/list.html', {'tickets':rows})

@login_required
def ticket_new(request):
    form = TicketForm(request.POST or None, queues=access.queues(request.user))
    if request.method == 'POST' and form.is_valid():
        with transaction.atomic():
            ticket = Ticket.objects.create(**form.cleaned_data, submitter_email=request.user.email)
            Ownership.objects.create(ticket=ticket, user=request.user)
            FollowUp.objects.create(ticket=ticket, user=request.user, title='Обращение создано', public=True)
        return redirect('helpdesk:view', ticket.pk)
    return render(request,'portal/form.html', {'form':form,'title':'Новое обращение'})

@login_required
def ticket_detail(request, ticket_id):
    ticket = get_object_or_404(access.tickets(request.user), pk=ticket_id)
    form = UpdateForm(request.POST or None, request.FILES or None, initial={'status':ticket.status})
    if request.method == 'POST' and form.is_valid():
        with transaction.atomic():
            status = int(form.cleaned_data['status'])
            if request.user.role == 'applicant' and status != ticket.status: raise PermissionDenied
            before = ticket.status
            ticket.status = status
            ticket.save()
            followup = FollowUp.objects.create(ticket=ticket, user=request.user, title='Обновление обращения', comment=form.cleaned_data['comment'], public=True if request.user.role=='applicant' else form.cleaned_data['public'], new_status=status)
            if before != status:
                TicketChange.objects.create(followup=followup, field='status', old_value=str(before), new_value=str(status))
            f = form.cleaned_data['attachment']
            if f:
                FollowUpAttachment.objects.create(followup=followup, file=f, filename=Path(f.name).name, size=f.size, mime_type='application/octet-stream')
        return redirect('helpdesk:view', ticket.pk)
    followups = ticket.followup_set.all()
    if request.user.role == 'applicant': followups = followups.filter(public=True)

    return render(request,'portal/detail.html', {'ticket':ticket,'followups':followups,'form':form})

@login_required
@require_POST
def ticket_delete(request, ticket_id):
    access.operator_required(request.user)
    ticket = get_object_or_404(access.tickets(request.user), pk=ticket_id)
    ticket.delete()
    return redirect('helpdesk:list')

@login_required
@require_POST
def bulk_status(request):
    access.operator_required(request.user)
    try:
        ids = [int(i) for i in request.POST.getlist('ids')]
        status = int(request.POST['status'])
        if status not in dict(Ticket.STATUS_CHOICES): raise ValueError
    except (ValueError, KeyError): return HttpResponse('Некорректные параметры', status=400)
    selected = access.tickets(request.user).filter(pk__in=ids)
    selected.update(status=status)
    return redirect('helpdesk:list')

@login_required
def attachment(request, attachment_id):
    f = get_object_or_404(FollowUpAttachment, pk=attachment_id, followup__ticket__in=access.tickets(request.user))
    if request.user.role == 'applicant' and not f.followup.public: raise PermissionDenied

    return FileResponse(f.file.open('rb'), as_attachment=True, filename=f.filename, content_type='application/octet-stream')

@login_required
@require_POST
def attachment_delete(request, attachment_id):
    access.operator_required(request.user)
    f = get_object_or_404(FollowUpAttachment, pk=attachment_id, followup__ticket__in=access.tickets(request.user))
    ticket_id = f.followup.ticket_id
    f.file.delete(save=False)
    f.delete()
    return redirect('helpdesk:view',ticket_id)

@access.manage_required
def manage(request):
    form = PersonForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        user = form.save(commit=False)
        user.set_password(form.cleaned_data['password'])
        user.is_staff = user.role != 'applicant'
        user.save()
        return redirect('helpdesk:manage')

    return render(request,'portal/manage.html', {'form':form,'people':User.objects.all(),'queues':Queue.objects.all()})

@access.manage_required
@require_POST
def change_role(request, user_id):
    person = get_object_or_404(User, pk=user_id)
    role = request.POST.get('role')
    if role not in ('applicant','operator','administrator'): return HttpResponse(status=400)
    person.role = role
    person.is_staff = role != 'applicant'
    person.save()
    audit.record('permissions',f'user:{person.pk}',role=role)
    return redirect('helpdesk:manage')

@access.manage_required
@require_POST
def grant_queue(request, user_id):
    person = get_object_or_404(User, pk=user_id)
    queue = get_object_or_404(Queue, pk=request.POST.get('queue'))
    perm = Permission.objects.get(content_type__app_label='helpdesk',codename=queue.permission_name.split('.')[1])
    person.user_permissions.add(perm)
    return redirect('helpdesk:manage')

@access.manage_required
def reset_password(request, user_id):
    person = get_object_or_404(User, pk=user_id)
    form = SetPasswordForm(person, request.POST or None)
    if request.method == 'POST' and form.is_valid():
        form.save()
        return redirect('helpdesk:manage')
    return render(request,'portal/form.html',{'form':form,'title':'Сброс пароля'})

def people_rows():
    return [{'id':u.pk,'login':u.username,'last_name':u.last_name,'first_name':u.first_name,'middle_name':u.middle_name,'email':u.email,'role':u.role} for u in User.objects.all()]

@access.admin_required
@require_GET
def export_csv(request):
    rows = people_rows()
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=['id','login','last_name','first_name','middle_name','email','role'])
    writer.writeheader()
    for row in rows:
        writer.writerow({k: "'"+v if isinstance(v,str) and v.startswith(('=','+','-','@')) else v for k,v in row.items()})
    audit.record('export','people:csv',count=len(rows))
    response = HttpResponse(out.getvalue(), content_type='text/csv; charset=utf-8')
    response['Content-Disposition'] = 'attachment; filename="people.csv"'
    response['Cache-Control'] = 'no-store'
    return response

@login_required
@require_GET
def export_json(request):
    rows = people_rows()
    response = JsonResponse({'people':rows,'generated_at':int(time.time())})
    response['Content-Disposition'] = 'attachment; filename="people.json"'
    response['Cache-Control'] = 'no-store'
    return response

@login_required
@require_POST
def token_issue(request):
    return JsonResponse({'token':signing.dumps({'uid':request.user.pk,'exp':int(time.time())+900},salt='support-api'), 'expires_in':900})

def token_user(request):
    header = request.headers.get('Authorization','')
    if not header.startswith('Bearer '): raise signing.BadSignature('Missing token')
    data = signing.loads(header[7:],salt='support-api')
    return User.objects.get(pk=data['uid'],is_active=True)

def serialize_ticket(ticket):
    return {'id':ticket.pk,'title':ticket.title,'description':ticket.description,'status':ticket.status,'queue':ticket.queue_id,'submitter_email':ticket.submitter_email}

@csrf_exempt
def ticket_api(request, ticket_id=None):
    try: user = token_user(request)
    except (signing.BadSignature, KeyError, ValueError, User.DoesNotExist): return JsonResponse({'error':'authentication required'},status=401)
    token = audit.actor.set(user.pk)
    try:
        if request.method != 'GET': return JsonResponse({'error':'method not allowed'},status=405)
        qs = access.tickets(user)
        if ticket_id is not None:
            row = get_object_or_404(qs,pk=ticket_id)

            return JsonResponse(serialize_ticket(row))
        rows = list(qs)

        return JsonResponse({'tickets':[serialize_ticket(t) for t in rows]})
    finally: audit.actor.reset(token)

@require_GET
def catalog_api(request):
    rows = list(Ticket.objects.all())

    return JsonResponse({'tickets':[serialize_ticket(t) for t in rows]})

@login_required
@require_POST
def queue_api(request, queue_id):
    queue = get_object_or_404(Queue,pk=queue_id)
    try:
        data = json.loads(request.body)
        title = str(data['title']).strip()
        if not title or len(title)>100: raise ValueError
    except (ValueError, KeyError): return JsonResponse({'error':'invalid title'},status=400)
    queue.title = title
    queue.save()
    return JsonResponse({'id':queue.pk,'title':queue.title})
