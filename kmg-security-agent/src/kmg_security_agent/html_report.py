"""Self-contained HTML view of report.json: no external resources, safe escaping, light/dark."""
from __future__ import annotations

from html import escape

STATUS = {'violated': ('нарушено', 'bad'), 'no_violations_found': ('выполнено', 'ok'),
          'inconclusive': ('не установлено', 'warn'), 'error': ('ошибка', 'warn')}
RESULT = {'violations_found': ('Выявлены нарушения — пайплайн блокируется', 'bad'),
          'no_violations_found': ('Нарушений не выявлено — пайплайн продолжается', 'ok'),
          'incomplete': ('Проверка не завершена', 'warn')}
SEVERITY = {'critical': 'критическая', 'high': 'высокая', 'medium': 'средняя', 'low': 'низкая'}
METHOD = {'static_rule': 'правило', 'llm': 'LLM'}

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--ink:#16181d;--muted:#5d6470;--line:#e2e5ea;--code:#f1f3f6;
--ok:#1a7f4b;--ok-bg:#e6f4ec;--bad:#b42318;--bad-bg:#fdecea;--warn:#9a6700;--warn-bg:#fff4d6;--accent:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--ink:#e8eaed;--muted:#9aa3ae;--line:#2a2f3a;
--code:#11141a;--ok:#4ac486;--ok-bg:#12291d;--bad:#ff7b72;--bad-bg:#3a1512;--warn:#e3b341;--warn-bg:#342a0c;--accent:#7aa2ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:28px 16px 60px}h1{font-size:26px;margin:0 0 4px}h2{font-size:19px;margin:34px 0 12px}
.sub{color:var(--muted);margin:0 0 20px}.banner{border-radius:12px;padding:16px 20px;font-weight:600;font-size:18px;margin:0 0 18px}
.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
.banner.ok{background:var(--ok-bg)}.banner.bad{background:var(--bad-bg)}.banner.warn{background:var(--warn-bg)}
.tw{overflow-x:auto;border-radius:10px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.stat b{display:block;font-size:24px}.stat span{color:var(--muted);font-size:13px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}th{font-size:13px;color:var(--muted);font-weight:600}
tr:last-child td{border-bottom:0}.pill{display:inline-block;border-radius:99px;padding:1px 10px;font-size:13px;font-weight:600}
.pill.ok{background:var(--ok-bg)}.pill.bad{background:var(--bad-bg)}.pill.warn{background:var(--warn-bg)}
.filters{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 14px}.filters button{border:1px solid var(--line);background:var(--card);color:var(--ink);
border-radius:99px;padding:5px 12px;cursor:pointer;font:inherit;font-size:13px}.filters button.on{border-color:var(--accent);color:var(--accent);font-weight:600}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:0 0 14px}
.card h3{margin:0 0 8px;font-size:16px}.meta{display:flex;flex-wrap:wrap;gap:8px;margin:0 0 10px;font-size:13px;color:var(--muted)}
.sev-critical,.sev-high{background:var(--bad-bg);color:var(--bad)}.sev-medium{background:var(--warn-bg);color:var(--warn)}.sev-low{background:var(--code);color:var(--muted)}
.label{font-weight:600}.loc{font:13px ui-monospace,Consolas,monospace;color:var(--muted);margin:10px 0 4px}
pre{margin:0;background:var(--code);border:1px solid var(--line);border-radius:8px;padding:10px 12px;overflow-x:auto;font:13px/1.5 ui-monospace,Consolas,monospace}
details{margin-top:8px}summary{cursor:pointer;color:var(--accent)}ul{margin:6px 0;padding-left:20px}.muted{color:var(--muted)}
@media print{.filters{display:none}.card{break-inside:avoid}}
"""

JS = """
document.querySelectorAll('.filters button').forEach(b=>b.addEventListener('click',()=>{
document.querySelectorAll('.filters button').forEach(x=>x.classList.toggle('on',x===b));
const r=b.dataset.req;document.querySelectorAll('.finding').forEach(c=>{c.style.display=(r==='all'||c.dataset.req===r)?'':'none'})}));
"""


def _e(value) -> str:
    return escape('' if value is None else str(value))


def _when(value) -> str:
    text = '' if value is None else str(value)
    return text[:16].replace('T', ' ') + ' UTC' if len(text) >= 16 and text[10:11] == 'T' else text


def _evidence(items) -> str:
    out = []
    for item in items:
        start, end = item['start_line'], item['end_line']
        where = f'строка {start}' if start == end else f'строки {start}–{end}'
        if item.get('location_kind') == 'extracted_document_lines':
            where = where.replace('строк', 'абзац')
        out.append(f'<div class="loc">{_e(item["path"])} · {where}</div><pre><code>{_e(item["quote"])}</code></pre>')
    return ''.join(out)


def render(report: dict) -> str:
    meta, timing = report.get('metadata', {}), report.get('timing', {})
    result_text, result_cls = RESULT.get(report['result'], (report['result'], 'warn'))
    extra = report.get('additional_findings', [])
    commit = (report.get('target') or {}).get('commit') or '—'
    parts = [f'<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
             f'<title>Отчёт ИБ-проверки</title><style>{CSS}</style></head><body><div class="wrap">',
             '<h1>Отчёт проверки требований ИБ</h1>',
             f'<p class="sub">KMG Security Agent {_e(report.get("agent_version"))} · коммит <code>{_e(commit[:12])}</code> · '
             f'{_e(_when(timing.get("finished_at")))}</p>',
             f'<div class="banner {result_cls}">{_e(result_text)} · код завершения {report["exit_code"]}</div>',
             '<div class="stats">']
    for value, label in ((report['finding_count'], 'нарушений ИБ'),
                         (len(report.get('violated_requirement_ids', [])), 'требований нарушено из 8'),
                         (len(extra), 'прочих замечаний'),
                         (f'{timing.get("duration_seconds")} с', 'длительность'),
                         (meta.get('mode', 'llm'), 'режим анализа'),
                         ((report.get('usage') or {}).get('requests', 0), 'запросов к модели')):
        parts.append(f'<div class="stat"><b>{_e(value)}</b><span>{_e(label)}</span></div>')
    parts.append('</div><h2>Статус по требованиям</h2><div class="tw"><table><thead><tr><th>ID</th><th>Требование</th><th>Статус</th><th>Находок</th><th>Методы</th></tr></thead><tbody>')
    for check in report['requirements']:
        text, cls = STATUS.get(check['status'], (check['status'], 'warn'))
        count = sum(1 for f in report['findings'] if f['requirement_id'] == check['requirement_id'])
        methods = ', '.join(check.get('analysis_methods', [])) or '—'
        parts.append(f'<tr><td><b>{_e(check["requirement_id"])}</b></td><td>{_e(check["title"])}</td>'
                     f'<td><span class="pill {cls}">{_e(text)}</span></td><td>{count}</td><td class="muted">{_e(methods)}</td></tr>')
    parts.append('</tbody></table></div><h2>Нарушения требований ИБ</h2>')
    if report['findings']:
        parts.append('<div class="filters"><button class="on" data-req="all">Все</button>')
        for rid in report.get('violated_requirement_ids', []):
            parts.append(f'<button data-req="{_e(rid)}">{_e(rid)}</button>')
        parts.append('</div>')
    else:
        parts.append('<p class="muted">Подтверждённых нарушений нет.</p>')
    titles = {c['requirement_id']: c['title'] for c in report['requirements']}
    for number, finding in enumerate(report['findings'], 1):
        parts.append(
            f'<div class="card finding" data-req="{_e(finding["requirement_id"])}"><h3>{number}. {_e(finding["title"])}</h3>'
            f'<div class="meta"><span class="pill bad">{_e(finding["requirement_id"])}</span>'
            f'<span class="pill sev-{_e(finding["severity"])}">{_e(SEVERITY.get(finding["severity"], finding["severity"]))}</span>'
            f'<span>{_e(titles.get(finding["requirement_id"], ""))}</span><span>· {_e(METHOD.get(finding.get("detected_by"), "LLM"))}</span></div>'
            f'<p><span class="label">Обоснование.</span> {_e(finding["explanation"])}</p>'
            f'<p><span class="label">Рекомендация.</span> {_e(finding["recommendation"])}</p>'
            f'<details open><summary>Доказательства ({len(finding["evidence"])})</summary>{_evidence(finding["evidence"])}</details></div>')
    parts.append('<h2>Прочие дефекты <span class="muted" style="font-weight:400;font-size:15px">— несоответствия технической спецификации, пайплайн не блокируют</span></h2>')
    if not extra:
        parts.append('<p class="muted">Не выявлено.</p>')
    for item in extra:
        parts.append(f'<div class="card"><h3>{_e(item["title"])}</h3><div class="meta"><span class="pill warn">п. {_e(item.get("spec_reference"))}</span>'
                     f'<span class="pill sev-{_e(item.get("severity"))}">{_e(SEVERITY.get(item.get("severity"), item.get("severity")))}</span></div>'
                     f'<p>{_e(item["explanation"])}</p><p><span class="label">Рекомендация.</span> {_e(item["recommendation"])}</p>'
                     f'<details><summary>Доказательства</summary>{_evidence(item["evidence"])}</details></div>')
    for key, heading in (('errors', 'Ошибки'), ('limitations', 'Ограничения проверки')):
        if report.get(key):
            parts.append(f'<h2>{heading}</h2><ul>' + ''.join(f'<li>{_e(x)}</li>' for x in report[key]) + '</ul>')
    parts.append('<h2>Сведения о проверке</h2><table><tbody>')
    for label, value in (('Коммит', commit), ('Начало', _when(timing.get('started_at'))), ('Завершение', _when(timing.get('finished_at'))),
                         ('Модель', report.get('model') or 'не использовалась'),
                         ('Прочитано файлов', (meta.get('coverage') or {}).get('files_read')),
                         ('Режим чтения ФС', (report.get('target') or {}).get('filesystem_mode')),
                         ('Машиночитаемый отчёт', 'report.json'), ('Состав проекта и исключения', 'manifest.json')):
        parts.append(f'<tr><td class="muted">{_e(label)}</td><td>{_e(value)}</td></tr>')
    parts.append(f'</tbody></table></div><script>{JS}</script></body></html>')
    return ''.join(parts)
