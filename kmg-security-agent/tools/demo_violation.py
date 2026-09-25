"""Live demo: add or remove one clear ИБ-08 violation in the corrected project.

    python kmg-security-agent/tools/demo_violation.py break     # JSON export open to any logged-in user
    python kmg-security-agent/tools/demo_violation.py restore   # back to administrator-only

Run from the repository root. Only KMG-Digital-Hackathon-fixed/portal/views.py changes (line endings kept).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGET = ROOT / 'KMG-Digital-Hackathon-fixed' / 'portal' / 'views.py'
SAFE = '@access.admin_required\n@require_GET\ndef export_json(request):'
BROKEN = '@login_required\n@require_GET\ndef export_json(request):'


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else ''
    if action not in ('break', 'restore'):
        print(__doc__)
        return 2
    raw = TARGET.read_bytes().decode('utf-8')
    crlf = '\r\n' in raw
    text = raw.replace('\r\n', '\n')
    old, new = (SAFE, BROKEN) if action == 'break' else (BROKEN, SAFE)
    if old not in text:
        print('Уже в нужном состоянии: ' + ('нарушение внесено' if action == 'break' else 'нарушения нет'))
        return 0
    text = text.replace(old, new, 1)
    TARGET.write_bytes((text.replace('\n', '\r\n') if crlf else text).encode('utf-8'))
    if action == 'break':
        print('Внесено нарушение ИБ-08: выгрузка /exports/people.json доступна любому вошедшему пользователю.')
        print('  было:  @access.admin_required\n  стало: @login_required')
    else:
        print('Нарушение убрано: выгрузка снова только для администратора (@access.admin_required).')
    print(f'Файл: {TARGET.relative_to(ROOT)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
