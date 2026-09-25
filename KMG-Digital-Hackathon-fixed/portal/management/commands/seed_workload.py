"""Populate a local instance with a repeatable synthetic support workload."""
import json
import os
import random
from contextlib import contextmanager
from datetime import date, datetime, time, timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import salted_hmac

from helpdesk.models import Queue, Ticket, FollowUp, TicketChange, FollowUpAttachment
from portal import access
from portal.models import Ownership
from portal.workload_data import QUEUES, DEPARTMENTS, NAMES, attachment_sample


@contextmanager
def exclusive_run(folder):
    folder.mkdir(parents=True, exist_ok=True)
    with (folder / 'workload.lock').open('a+b') as handle:
        handle.seek(0, 2)
        if not handle.tell():
            handle.write(b'0')
            handle.flush()
        handle.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise CommandError('Заполнение уже выполняется для этого runtime.') from exc
        try:
            yield
        finally:
            handle.seek(0)
            if os.name == 'nt':
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(handle, fcntl.LOCK_UN)


class Command(BaseCommand):
    help = 'Добавить синтетическую историю службы поддержки без перезаписи существующих обращений.'

    def add_arguments(self, parser):
        parser.add_argument('--tickets', type=int, default=600, help='Целевое число обращений набора: 1–3000 (не число добавляемых).')
        parser.add_argument('--seed', type=int, default=None, help='Число для воспроизводимой генерации, по умолчанию 2026.')
        parser.add_argument('--days', type=int, default=None, help='Глубина истории: 30–730 дней, по умолчанию 180.')
        parser.add_argument('--as-of', default=None, help='Конечная дата истории YYYY-MM-DD; по умолчанию сегодня.')

    def handle(self, *args, **options):
        if not 1 <= options['tickets'] <= 3000:
            raise CommandError('--tickets должен быть от 1 до 3000.')
        with exclusive_run(settings.RUNTIME / 'seeds'):
            self.populate(options)

    def parameters(self, options):
        path = settings.RUNTIME / 'seeds' / 'workload.json'
        previous = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
        config = {key: options[key] if options[key] is not None else previous.get(key, default)
                  for key, default in [('seed', 2026), ('days', 180), ('as_of', timezone.localdate().isoformat())]}
        try:
            end = date.fromisoformat(config['as_of'])
        except (ValueError, TypeError) as exc:
            raise CommandError('--as-of должен иметь формат YYYY-MM-DD.') from exc
        if end > timezone.localdate():
            raise CommandError('--as-of не может быть в будущем.')
        if not 30 <= config['days'] <= 730:
            raise CommandError('--days должен быть от 30 до 730.')
        if previous and config != previous:
            raise CommandError('Параметры существующего набора отличаются. Используйте прежние параметры или новый HELPDESK_RUNTIME.')
        if not previous:
            temporary = path.with_suffix('.tmp')
            temporary.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding='utf-8')
            os.replace(temporary, path)
        self.config = config
        self.end = timezone.make_aware(datetime.combine(end, time.min))

    def ticket_key(self, number):
        return salted_hmac('support-workload-v1', str(number), algorithm='sha256').hexdigest()[:36]

    def populate(self, options):
        self.parameters(options)
        User = get_user_model()
        planned = [(f'sample.requester{i:02d}', 'applicant', i - 1) for i in range(1, 73)]
        planned += [(f'sample.operator{i:02d}', 'operator', i + 2) for i in range(1, 13)]
        planned += [('sample.admin01', 'administrator', 6)]
        existing = {u.username: u for u in User.objects.filter(username__in=[x[0] for x in planned])}
        for login, role, _ in planned:
            if login in existing and (existing[login].role != role or not existing[login].is_active):
                raise CommandError(f'У {login} изменена роль или активность. Набор не меняет существующие учётные записи.')
        if User.objects.count() + len(planned) - len(existing) > getattr(settings, 'MAX_USERS', 500):
            raise CommandError('Недостаточно места в лимите пользователей для набора.')
        keys = [self.ticket_key(i) for i in range(1, options['tickets'] + 1)]
        found = set(Ticket.objects.filter(secret_key__in=keys).values_list('secret_key', flat=True))
        missing = len(keys) - len(found)
        if Ticket.objects.count() + missing > getattr(settings, 'MAX_TICKETS', 5000):
            raise CommandError('Недостаточно места в лимите обращений для набора.')
        queues = []
        for slug, title, public, _ in QUEUES:
            with transaction.atomic():
                queue, _ = Queue.objects.get_or_create(slug=slug, defaults={
                    'title': title, 'allow_public_submission': public, 'email_address': slug + '@example.test'})
                queues.append(queue)
        users = {}
        new_users = 0
        for login, role, name_index in planned:
            with transaction.atomic():
                if login in existing:
                    user = existing[login]
                else:
                    first, last, middle = NAMES[name_index % len(NAMES)]
                    user = User(username=login, first_name=first, last_name=last, middle_name=middle,
                                email=login + '@example.test', role=role, is_staff=role != 'applicant', is_superuser=False)
                    user.set_password('Service-2026!' + login)
                    user.save()
                    if role == 'operator':
                        index = int(login[-2:]) - 1
                        assigned = [queues[index % 8], queues[(index + 1) % 8]]
                        for queue in assigned:
                            user.user_permissions.add(Permission.objects.get(
                                content_type__app_label='helpdesk', codename=queue.permission_name.split('.')[1]))
                    new_users += 1
                users[login] = user
        operators = [users[f'sample.operator{i:02d}'] for i in range(1, 13)]
        allowed = {q.pk: [u for u in operators if access.queues(u).filter(pk=q.pk).exists()] for q in queues}
        if any(not group for group in allowed.values()):
            raise CommandError('Одна из очередей не назначена ни одному оператору набора. Восстановите назначения или используйте новый runtime.')
        applicants = [users[f'sample.requester{i:02d}'] for i in range(1, 73)]
        default_applicant = User.objects.filter(username='applicant', role='applicant', is_active=True).first()
        counters = {'tickets': 0, 'followups': 0, 'changes': 0, 'attachments': 0}
        for number, key in enumerate(keys, 1):
            if key in found:
                continue
            rng = random.Random(f"{self.config['seed']}:{number}")
            qi = (number - 1) % len(queues)
            queue = queues[qi]
            topic, description, resolution = QUEUES[qi][3][rng.randrange(4)]
            department = DEPARTMENTS[rng.randrange(len(DEPARTMENTS))]
            operator = rng.choice(allowed[queue.pk])
            if queue.allow_public_submission:
                owner = default_applicant if default_applicant and number % 17 == 0 else applicants[(number - 1) % 72]
            else:
                owner = operator
            stage = number % 20
            status = (Ticket.OPEN_STATUS if stage < 6 else Ticket.REOPENED_STATUS if stage < 8 else
                      Ticket.RESOLVED_STATUS if stage < 13 else Ticket.CLOSED_STATUS if stage < 19 else Ticket.DUPLICATE_STATUS)
            created = self.end - timedelta(days=1 + (number * 37 % self.config['days']), hours=rng.randrange(8), minutes=rng.randrange(60))
            last = min(created + timedelta(hours=rng.randint(6, 240)), self.end - timedelta(minutes=1))
            priority = rng.choices([1, 2, 3, 4, 5], [8, 17, 45, 22, 8])[0]
            assigned = not (status == Ticket.OPEN_STATUS and number % 3 == 0)
            due = created + timedelta(hours=[4, 24, 72, 120, 240][priority - 1])
            saved_files = []
            try:
                with transaction.atomic():
                    ticket = Ticket.objects.create(
                        secret_key=key, title=f'{topic} · {department} · {number:04d}', queue=queue,
                        description=(f'{description}\n\nПодразделение: {department}. '
                                     f'Площадка: офис {1 + number % 4}, кабинет {100 + number % 80}.\n'
                                     f'Рабочее устройство: WS-{number % 120 + 1:03d}. '
                                     'Просьба согласовать время диагностики в комментариях. Данные обращения синтетические.'),
                        submitter_email=owner.email, assigned_to=operator if assigned else None,
                        status=status, priority=priority, due_date=due,
                        on_hold=status in Ticket.OPEN_STATUSES and number % 5 == 0,
                        resolution=resolution if status in (Ticket.RESOLVED_STATUS, Ticket.CLOSED_STATUS) else '')
                    Ownership.objects.create(ticket=ticket, user=owner)
                    events = [(owner, True, 'Обращение зарегистрировано', description, Ticket.OPEN_STATUS)]
                    if assigned:
                        events += [(operator, False, 'Первичная диагностика',
                                    f'Ответственный назначен. Проверяем устройство WS-{number % 120 + 1:03d}; согласуем окно с подразделением «{department}».', None),
                                   (operator, True, 'Уточнение обстоятельств', 'Уточните время возникновения и подтвердите возможность подключения специалиста.', None),
                                   (owner, True, 'Ответ заявителя', 'Проблема повторяется после входа. Можно подключиться в рабочее время, результат проверки сообщу здесь.', None)]
                    if status in (Ticket.RESOLVED_STATUS, Ticket.CLOSED_STATUS, Ticket.REOPENED_STATUS):
                        events.append((operator, True, 'Решение предоставлено', resolution, Ticket.RESOLVED_STATUS))
                    if status == Ticket.CLOSED_STATUS:
                        events.append((owner, True, 'Работа подтверждена', 'Проверка выполнена, всё работает. Обращение можно закрыть.', Ticket.CLOSED_STATUS))
                    elif status == Ticket.REOPENED_STATUS:
                        events.append((owner, True, 'Повторное обращение', 'После повторного входа проблема вернулась. Прошу продолжить диагностику.', Ticket.REOPENED_STATUS))
                    elif status == Ticket.DUPLICATE_STATUS:
                        original = Ticket.objects.filter(queue=queue).exclude(pk=ticket.pk).order_by('pk').first()
                        ticket.merged_to = original
                        ticket.save(update_fields=['merged_to'])
                        text = f'Та же проблема рассматривается в обращении #{original.pk}.' if original else 'Повторная регистрация; работа продолжится в основном обращении.'
                        events.append((operator, True, 'Повторная регистрация', text, Ticket.DUPLICATE_STATUS))
                    followups = []
                    old_status = Ticket.OPEN_STATUS
                    for index, (author, public, title, comment, new_status) in enumerate(events):
                        event_date = created + (last - created) * index / max(1, len(events) - 1)
                        followup = FollowUp.objects.create(ticket=ticket, user=author, public=public, title=title,
                                                          comment=comment, date=event_date, new_status=new_status,
                                                          time_spent=timedelta(minutes=rng.randrange(5, 46)) if author == operator else None)
                        followups.append(followup)
                        counters['followups'] += 1
                        if new_status is not None and new_status != old_status:
                            TicketChange.objects.create(followup=followup, field='status', old_value=str(old_status), new_value=str(new_status))
                            old_status = new_status
                            counters['changes'] += 1
                        if index == 1 and assigned:
                            TicketChange.objects.create(followup=followup, field='assigned_to', old_value='', new_value=operator.username)
                            counters['changes'] += 1
                    attachments = []
                    if number % 3 == 0:
                        attachments.append((followups[0], (number // 3) % 3))
                    if assigned and number % 10 == 0:
                        attachments.append((followups[1], 0))
                    for followup, kind in attachments:
                        filename, mime, payload = attachment_sample(kind, number, topic, department)
                        item = FollowUpAttachment(followup=followup, filename=filename, mime_type=mime, size=len(payload))
                        item.file.save(filename, ContentFile(payload), save=False)
                        saved_files.append((item.file.storage, item.file.name))
                        item.save()
                        counters['attachments'] += 1
                    # auto_now fields otherwise describe import time, not the imported history.
                    Ticket.objects.filter(pk=ticket.pk).update(created=created, modified=followups[-1].date)
                    counters['tickets'] += 1
            except BaseException:
                for storage, name in saved_files:
                    if not FollowUpAttachment.objects.filter(file=name).exists():
                        storage.delete(name)
                raise
            if counters['tickets'] % 100 == 0:
                self.stdout.write(f"Создано обращений: {counters['tickets']} / {missing}")
        self.stdout.write(self.style.SUCCESS(
            f"Готово. Новых пользователей: {new_users}; обращений: {counters['tickets']}; "
            f"комментариев: {counters['followups']}; изменений: {counters['changes']}; "
            f"вложений: {counters['attachments']}. Пропущено существующих обращений: {len(found)}."))
