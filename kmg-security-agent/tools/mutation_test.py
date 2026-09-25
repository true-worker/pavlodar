"""Mutation test: inject one ИБ violation at a time into the corrected project and check detection.

TUNING — mutations used while writing the rules; HOLDOUT — written afterwards, never used for tuning
(an honest estimate for violations the rules have not seen). Mode: deterministic rules only.

    python tools/mutation_test.py [--base ../KMG-Digital-Hackathon-fixed]
"""
import argparse, json, shutil, subprocess, sys, tempfile, os
from pathlib import Path

AGENT = Path(__file__).resolve().parents[1]
TUNING=[
 ('ИБ-01','админ-декоратор проверяет is_superuser','portal/access.py',"if not administrator(request.user): raise PermissionDenied\n        return view(request, *args, **kwargs)\n    return wrapped\n\ndef queues","if not request.user.is_superuser: raise PermissionDenied\n        return view(request, *args, **kwargs)\n    return wrapped\n\ndef queues"),
 ('ИБ-01','админ-view только с login_required','portal/views.py',"@access.manage_required\ndef manage(request):","@login_required\ndef manage(request):"),
 ('ИБ-01','роль берётся из параметра запроса','portal/access.py',"def administrator(user):\n    return user.is_authenticated and user.is_active and user.role == 'administrator'","def administrator(user):\n    from django.http import HttpRequest\n    return user.is_authenticated and user.is_active and getattr(user, 'claimed_role', user.role) == 'administrator'"),
 ('ИБ-01','админ-роль проверяется только в шаблоне','portal/views.py',"@access.manage_required\n@require_POST\ndef change_role(","@login_required\n@require_POST\ndef change_role("),
 ('ИБ-02','API берёт пользователя из параметра uid','portal/views.py',"    try: user = token_user(request)\n","    try: user = User.objects.get(pk=int(request.GET.get('uid', 0)))\n"),
 ('ИБ-02','сессия живёт сутки','demodesk/config/settings.py',"SESSION_COOKIE_AGE = 3600","SESSION_COOKIE_AGE = 86400"),
 ('ИБ-02','max_age токена = сутки','portal/views.py',"TOKEN_TTL = 900","TOKEN_TTL = 86400"),
 ('ИБ-02','cookie сессии доступна JS','demodesk/config/settings.py',"SESSION_COOKIE_HTTPONLY = True","SESSION_COOKIE_HTTPONLY = False"),
 ('ИБ-03','минимальная версия TLS 1.1','proxy.json','"minimum_tls": "TLSv1_2"','"minimum_tls": "TLSv1_1"'),
 ('ИБ-03','шифры в serve.py заданы строкой','serve.py',"context.set_ciphers(config['ciphers'])","context.set_ciphers('HIGH:!aNULL')"),
 ('ИБ-03','отключён только SESSION_COOKIE_SECURE','demodesk/config/settings.py',"SESSION_COOKIE_SECURE = True","SESSION_COOKIE_SECURE = False"),
 ('ИБ-04','хешер паролей MD5','demodesk/config/settings.py',"PASSWORD_HASHERS = ['portal.hashers.PasswordHasher']","PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']"),
 ('ИБ-04','собственный хешер на PBKDF2','portal/hashers.py',"from django.contrib.auth.hashers import Argon2PasswordHasher\nclass PasswordHasher(Argon2PasswordHasher):","from django.contrib.auth.hashers import PBKDF2PasswordHasher\nclass PasswordHasher(PBKDF2PasswordHasher):"),
 ('ИБ-04','email снова обычным полем','portal/models.py',"    email = EncryptedEmailField(blank=True)","    email = models.EmailField(blank=True)"),
 ('ИБ-04','пароль сохраняется в открытом виде','portal/views.py',"        user.set_password(form.cleaned_data['password'])","        user.password = form.cleaned_data['password']"),
 ('ИБ-05','ключ журнала снова в journal/','setup_local.py',"for filename,size in [('data.key',64),('journal.key',32)]:\n    path=RUNTIME/'keys'/filename","for filename,size in [('data.key',64),('journal.key',32)]:\n    path=RUNTIME/('journal' if filename=='journal.key' else 'keys')/filename"),
 ('ИБ-05','журнал пишется без шифрования','portal/audit.py',"    payload = nonce + AESGCM(settings.LOG_KEY_FILE.read_bytes()).encrypt(nonce, json.dumps(event, sort_keys=True).encode(), b'journal')","    payload = json.dumps(event, sort_keys=True).encode()"),
 ('ИБ-06','в README нет СТ РК 1073-2007','README.md',"6. [СТ РК 1073-2007](https://new-shop.ksm.kz/catalog/document/40340/).\n",""),
 ('ИБ-07','удалён AuditMiddleware','demodesk/config/settings.py',"'portal.middleware.AuditMiddleware', ",""),
 ('ИБ-07','нет событий СУБД','portal/apps.py',"        connection_created.connect(audit.db_connected, dispatch_uid='portal_db_connect')\n",""),
 ('ИБ-07','пакетная смена без аудита','portal/views.py',"        transaction.on_commit(lambda: audit.record('bulk_status','tickets',status=status,ids=affected))\n",""),
 ('ИБ-08','CSV-выгрузка без записи аудита','portal/views.py',"    audit.record('export','people:csv',count=len(rows))\n",""),
 ('ИБ-08','JSON-выгрузка для любого вошедшего','portal/views.py',"@access.admin_required\n@require_GET\ndef export_json(","@login_required\n@require_GET\ndef export_json("),
 ('ИБ-08','выгрузка через API без роли','portal/views.py',"@access.admin_required\n@require_POST\ndef queue_api(","@access.admin_required\n@require_POST\ndef queue_api("),
]
HOLDOUT=[
 ('ИБ-01','доступ по группе admins','portal/access.py',"        if not administrator(request.user): raise PermissionDenied\n        return view(request, *args, **kwargs)\n    return wrapped\n\ndef queues","        if not request.user.groups.filter(name='admins').exists(): raise PermissionDenied\n        return view(request, *args, **kwargs)\n    return wrapped\n\ndef queues"),
 ('ИБ-01','user_passes_test(is_staff)','portal/views.py',"@access.manage_required\n@require_POST\ndef change_role(","@user_passes_test(lambda u: u.is_staff)\n@require_POST\ndef change_role("),
 ('ИБ-02','новый API без аутентификации','portal/views.py',"@require_GET\ndef catalog_api(","@csrf_exempt\ndef open_feed(request):\n    return JsonResponse({'tickets':[serialize_ticket(t) for t in Ticket.objects.all()]})\n\n@require_GET\ndef catalog_api("),
 ('ИБ-02','ошибка токена → анонимный доступ','portal/views.py',"    try: user = token_user(request)\n    except (signing.BadSignature, KeyError, ValueError, User.DoesNotExist): return JsonResponse({'error':'authentication required'},status=401)","    try: user = token_user(request)\n    except (signing.BadSignature, KeyError, ValueError, User.DoesNotExist): user = User.objects.filter(role='administrator').first()"),
 ('ИБ-02','TTL токена 60*60*24','portal/views.py',"TOKEN_TTL = 900","TOKEN_TTL = 60 * 60 * 24"),
 ('ИБ-03','TLSv1 в serve.py','serve.py',"    context.minimum_version=getattr(ssl.TLSVersion,config['minimum_tls'])","    context.minimum_version=ssl.TLSVersion.TLSv1"),
 ('ИБ-03','шифр CBC-SHA256','proxy.json','"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"','"ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256"'),
 ('ИБ-04','«шифрование» = base64','portal/fields.py',"        return PREFIX + base64.urlsafe_b64encode(_cipher().encrypt(str(value).encode(), self._aad())).decode()","        return PREFIX + base64.urlsafe_b64encode(str(value).encode()).decode()"),
 ('ИБ-04','seed создаёт пользователя с паролем как есть','portal/management/commands/seed_demo.py',"            if created: u.set_password('Training-2026!'+login); u.save()","            if created: User.objects.filter(pk=u.pk).update(password='Training-2026!'+login)"),
 ('ИБ-05','ключ журнала в logs/','demodesk/config/settings.py',"LOG_KEY_FILE = RUNTIME / 'keys' / 'journal.key'","LOG_KEY_FILE = RUNTIME / 'logs' / 'audit.key'"),
 ('ИБ-05','журнал через json.dump','portal/audit.py',"    staging.write_bytes(payload)","    import json as _j\n    with open(staging, 'w') as fh: _j.dump(event, fh)"),
 ('ИБ-07','аудит только изменяющих запросов','portal/middleware.py',"        if match is not None and not request.path.startswith(settings.STATIC_URL):","        if match is not None and request.method != 'GET' and not request.path.startswith(settings.STATIC_URL):"),
 ('ИБ-08','выгрузка xlsx без роли','portal/views.py',"@access.admin_required\n@require_GET\ndef export_csv(","@login_required\n@require_GET\ndef export_xlsx(request):\n    rows = people_rows()\n    audit.record('export','people:xlsx',count=len(rows))\n    return HttpResponse(str(rows), content_type='application/vnd.ms-excel')\n\n@access.admin_required\n@require_GET\ndef export_csv("),
 ('ИБ-06','нет постановления № 832','README.md',"3. [Постановление Правительства РК от 20.12.2016 № 832](https://old.adilet.zan.kz/rus/docs/P1600000832), [история редакций](https://www.adilet.zan.kz/rus/docs/P1600000832/history).\n",""),
]
ROUTES={'новый API без аутентификации':"    path('api/feed/',v.open_feed,name='feed'),\n",'выгрузка xlsx без роли':"    path('exports/people.xlsx',v.export_xlsx,name='xlsx'),\n"}


def run(base, items):
    results = []
    for rid, name, rel, old, new in items:
        work = Path(tempfile.mkdtemp())
        target = work / 't'
        shutil.copytree(base, target, ignore=shutil.ignore_patterns('__pycache__', 'runtime*'))
        path = target / rel
        text = path.read_text(encoding='utf-8').replace('\r\n', '\n')
        if old not in text:
            results.append((rid, name, 'SKIP', [])); continue
        path.write_text(text.replace(old, new, 1), encoding='utf-8')
        if name in ROUTES:
            urls = target / 'demodesk/config/urls.py'
            urls.write_text(urls.read_text(encoding='utf-8').replace("    path('api/token/'", ROUTES[name] + "    path('api/token/'"), encoding='utf-8')
        if 'user_passes_test' in new:
            views = target / 'portal/views.py'
            views.write_text('from django.contrib.auth.decorators import user_passes_test\n' + views.read_text(encoding='utf-8'), encoding='utf-8')
        if name == 'выгрузка через API без роли':
            views = target / 'portal/views.py'
            views.write_text(views.read_text(encoding='utf-8') + "\n@login_required\ndef people_api(request):\n    return JsonResponse({'people':people_rows()})\n", encoding='utf-8')
            urls = target / 'demodesk/config/urls.py'
            urls.write_text(urls.read_text(encoding='utf-8').replace("    path('api/token/'", "    path('api/people/',v.people_api,name='people_api'),\n    path('api/token/'"), encoding='utf-8')
        env = dict(os.environ, PYTHONPATH=str(AGENT / 'src'), PYTHONUTF8='1')
        out = subprocess.run([sys.executable, '-m', 'kmg_security_agent', 'scan', '--mode', 'static', '--repo', str(target),
                              '--output', str(work / 'r')], cwd=AGENT, env=env, capture_output=True, text=True, encoding='utf-8')
        found = json.loads(out.stdout.strip().splitlines()[-1])['violated_requirements']
        results.append((rid, name, 'OK' if rid in found else 'MISS', found))
        shutil.rmtree(work, ignore_errors=True)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--base', type=Path, default=AGENT.parent / 'KMG-Digital-Hackathon-fixed')
    args = parser.parse_args()
    for title, items in (('TUNING', TUNING), ('HOLDOUT', HOLDOUT)):
        results = run(args.base.resolve(), items)
        print(f'== {title}')
        for rid, name, status, found in results:
            print(f'{status:5} {rid} {name} -> {", ".join(found) or "нет"}')
        applied = [r for r in results if r[2] != 'SKIP']
        print(f'detected {sum(r[2] == "OK" for r in applied)}/{len(applied)}\n')


if __name__ == '__main__':
    main()
