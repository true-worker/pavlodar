# Исправления относительно версии организатора

| Требование | Было | Стало | Файлы |
|---|---|---|---|
| ИБ-01 | Административный интерфейс защищён признаком `is_staff` (есть у операторов); переименование очереди доступно любому вошедшему | Проверка `role == "administrator"` в общем декораторе; `queue_api` под `admin_required` | `portal/access.py`, `portal/views.py` |
| ИБ-02 | `/api/catalog/tickets/` без аутентификации; токен API без проверки срока | `login_required` и область доступа пользователя; `signing.loads(max_age=900)`, токен отзывается при смене пароля, роли и прав | `portal/views.py` |
| ИБ-03 | Шифронабор `AES128-SHA`; HTTP без перенаправления; cookie без `Secure`; HSTS отключён | Только ECDHE+AES-GCM; перенаправление HTTP→HTTPS; `Secure` cookie; HSTS 1 год; `SECURE_SSL_REDIRECT` | `proxy.json`, `demodesk/config/settings.py` |
| ИБ-04 | ФИО, логин, email в БД открытым текстом | AES-256-SIV (аутентифицированное шифрование) для полей ПД, ключ из `runtime/keys`; миграция шифрует существующие записи | `portal/fields.py`, `portal/models.py`, `portal/migrations/0002_*` |
| ИБ-05 | Ключ журнала в `runtime/journal/`, доступном локальному читателю | Ключ журнала в `runtime/keys/` (доступ только у службы) | `demodesk/config/settings.py`, `setup_local.py` |
| ИБ-07 | Чтение данных и пакетные изменения не журналируются; нет журнала событий СУБД | `AuditMiddleware` — событие на каждый запрос (операция, объект, результат, ID запроса, хеш источника); аудит пакетной смены статусов; события подключения к БД, миграций и изменения прав на файл БД | `portal/middleware.py`, `portal/audit.py`, `portal/apps.py`, `portal/views.py`, `portal/management/commands/db_access.py` |
| ИБ-08 | JSON-выгрузка доступна любому вошедшему и не журналируется | Та же проверка администратора, что и у CSV, и запись аудита | `portal/views.py` |
| Спец. 4.3.5, 4.4.8 | Смена роли не снимает права на очереди; нет проверки распространённых паролей | Права на очереди снимаются; добавлены `CommonPasswordValidator`, `NumericPasswordValidator` | `portal/views.py`, `demodesk/config/settings.py` |

Проверка: `python manage.py test portal` — 8 тестов, из них 6 тестов безопасности падают на версии организатора и проходят здесь.
