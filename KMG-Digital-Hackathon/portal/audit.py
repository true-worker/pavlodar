import json, os, uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from django.conf import settings
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
actor = ContextVar('actor', default='system')

def record(action, obj, **details):
    event = {'id':uuid.uuid4().hex, 'time':datetime.now(timezone.utc).isoformat(), 'actor':str(actor.get()), 'action':action, 'object':str(obj), 'details':details}
    nonce = os.urandom(12)
    payload = nonce + AESGCM(settings.LOG_KEY_FILE.read_bytes()).encrypt(nonce, json.dumps(event, sort_keys=True).encode(), b'journal')
    folder = settings.RUNTIME / 'journal' / 'pending'
    folder.mkdir(parents=True, exist_ok=True)
    staging = folder / (event['id'] + '.tmp')
    staging.write_bytes(payload)
    staging.rename(folder / (event['id'] + '.evt'))
    return event

def read_event(path):
    raw = path.read_bytes()
    return json.loads(AESGCM(settings.LOG_KEY_FILE.read_bytes()).decrypt(raw[:12], raw[12:], b'journal'))

def mutation(sender, instance, created=False, **kwargs):
    if sender._meta.app_label in ('helpdesk', 'portal'):
        record('create' if created else 'update', f'{sender._meta.label}:{instance.pk}')

def deletion(sender, instance, **kwargs):
    if sender._meta.app_label in ('helpdesk', 'portal'):
        record('delete', f'{sender._meta.label}:{instance.pk}')

def relations(sender, instance, action, pk_set=None, **kwargs):
    if action.startswith('post_'):
        record('permissions', f'{instance._meta.label}:{instance.pk}', operation=action, ids=sorted(pk_set or []))

def signed_in(sender, request, user, **kwargs):
    token = actor.set(user.pk)
    try: record('login', f'user:{user.pk}')
    finally: actor.reset(token)

def signed_out(sender, request, user, **kwargs):
    record('logout', f'user:{user.pk if user else 0}')

def login_failed(sender, credentials, request, **kwargs):
    record('login_refused', 'authentication')
