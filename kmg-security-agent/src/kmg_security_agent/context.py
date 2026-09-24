"""Bounded source batches and generic requirement-oriented retrieval."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import PurePosixPath

# Security concepts, not names of files/functions in any particular target.
CUES = {
    'ИБ-01': ('permission', 'role', 'admin', 'staff', 'superuser', 'authorize', 'access', 'group', 'доступ', 'администратор'),
    'ИБ-02': ('auth', 'login', 'token', 'session', 'password', 'active', 'signature', 'expire', 'signing', 'authenticate', 'аутентифика'),
    'ИБ-03': ('https', 'tls', 'ssl', 'cipher', 'certificate', 'redirect', 'secure', 'proxy', 'http', 'шифр'),
    'ИБ-04': ('encrypt', 'decrypt', 'aes', 'fernet', 'argon', 'hash', 'password', 'storage', 'database', 'email', 'first_name', 'last_name', 'персональ'),
    'ИБ-05': ('journal', 'audit', 'log', 'integrity', 'nonce', 'key', 'encrypt', 'decrypt', 'acl', 'chmod', 'collect', 'буфер'),
    'ИБ-06': ('iso', 'гост', 'сертиф', 'certificate', 'стандарт', 'ст рк', 'ссылка', 'норматив', 'https://', 'http://'),
    'ИБ-07': ('audit', 'record', 'signal', 'post_save', 'post_delete', 'bulk', 'update', 'delete', 'read', 'query', 'denied', 'export', 'журнал'),
    'ИБ-08': ('export', 'csv', 'json', 'download', 'attachment', 'person', 'email', 'role', 'admin', 'audit', 'выгруз', 'экспорт'),
}
DOC_SUFFIXES = {'.md', '.rst', '.txt', '.docx'}


def _render(chunk: dict) -> str:
    metadata = {key: chunk[key] for key in ('id', 'path', 'start_line', 'end_line')}
    metadata['line_semantics'] = chunk.get('line_semantics', 'source_lines')
    lines = chunk['text'].split('\n')
    if len(lines) != chunk['end_line'] - chunk['start_line'] + 1:
        raise ValueError(f'Chunk {chunk["id"]} does not match its declared line range')
    numbered = '\n'.join(f'{number}: {line}' for number, line in enumerate(lines, chunk['start_line']))
    return ('BEGIN_UNTRUSTED_SOURCE ' + json.dumps(metadata, ensure_ascii=False) + '\n'
            + numbered + '\nEND_UNTRUSTED_SOURCE\n')


def build_batches(inventory: dict, max_chars: int = 80000) -> list[dict]:
    if max_chars < 1:
        raise ValueError('Context budget must be positive')
    chunks = inventory['chunks']
    ids = [chunk['id'] for chunk in chunks]
    if len(set(ids)) != len(ids):
        raise ValueError('Duplicate chunk IDs prevent reliable coverage tracking')
    batches, current, blocks, size = [], [], [], 0

    def flush():
        batches.append({'id': f'batch-{len(batches) + 1:04d}', 'chunks': list(current), 'text': ''.join(blocks)})
    for chunk in chunks:
        rendered = _render(chunk)
        if len(rendered) > max_chars:
            raise ValueError(f'Chunk {chunk["id"]} from {chunk["path"]} exceeds the full rendered batch budget; no source was truncated')
        if current and size + len(rendered) > max_chars:
            flush()
            current, blocks, size = [], [], 0
        current.append(chunk)
        blocks.append(rendered)
        size += len(rendered)
    if current:
        flush()
    assignments = {chunk['id']: batch['id'] for batch in batches for chunk in batch['chunks']}
    for record in inventory.get('files', []):
        record['review_batch_ids'] = sorted({assignments[cid] for cid in record.get('chunk_ids', [])})
    return batches


def _score(text: str, requirement_id: str) -> int:
    text = text.lower()
    return sum(1 for cue in CUES[requirement_id] if cue in text)


def requirement_context(inventory: dict, index: dict, batch_reviews: list[dict],
                        requirement_id: str, max_chars: int = 180000) -> dict:
    """Retrieve complete chunks, preserving every explicitly required evidence site.

    Overview batches cover the full source. This second pass is a bounded,
    ranked retrieval, not a claim to repeat the entire repository in one prompt.
    Required evidence/linked definitions that do not fit are returned explicitly.
    Optional ranking candidates not selected are reported separately from errors.
    """
    if requirement_id not in CUES:
        raise ValueError('Unknown requirement ID')
    if max_chars < 1:
        raise ValueError('Context budget must be positive')
    chunks = inventory['chunks']
    by_path = defaultdict(list)
    by_id = {}
    for chunk in chunks:
        by_path[chunk['path']].append(chunk)
        by_id[chunk['id']] = chunk
    rendered = {cid: _render(chunk) for cid, chunk in by_id.items()}
    required = set()
    evidence_paths = set()
    linked_paths = set()
    selection_reasons = defaultdict(set)
    unavailable = set()

    def add(parts: list[dict], reason: str):
        for part in parts:
            required.add(part['id'])
            selection_reasons[part['path']].add(reason)

    def relevant_parts(path: str, limit: int = 2) -> list[dict]:
        parts = by_path.get(path, [])
        return sorted(parts, key=lambda part: (-_score(part['text'], requirement_id), part['start_line']))[:limit]

    def add_linked(path: str, source_path: str | None = None):
        if path not in inventory['documents']:
            unavailable.add(path)
            return
        parts = by_path.get(path, [])
        if sum(len(rendered[part['id']]) for part in parts) <= 24000:
            add(parts, 'complete small dependency or related document')
            return
        # Resolve specifically imported definitions in large dependencies. The
        # definitions plus their decorators are retained as whole source chunks.
        imported_names = set()
        if source_path:
            dependency_module = index.get(path, {}).get('module')
            for entry in index.get(source_path, {}).get('imports', []):
                if entry['module'] == dependency_module:
                    imported_names.update(entry['names'])
        symbols = [symbol for symbol in index.get(path, {}).get('symbols', []) if symbol['name'] in imported_names]
        matching = []
        for symbol in symbols:
            start = symbol['start_line'] - len(symbol.get('decorators', []))
            end = symbol['end_line']
            matching.extend(part for part in parts if part['end_line'] >= start and part['start_line'] <= end)
        add(matching or relevant_parts(path), 'linked definition or highest-ranked chunks of large dependency')

    for review in batch_reviews:
        candidates = [candidate for candidate in review.get('candidates', [])
                      if candidate.get('requirement_id') == requirement_id]
        if not candidates:
            continue
        linked_paths.update(review.get('related_paths', []))
        for candidate in candidates:
            for evidence in candidate.get('evidence', []):
                path = evidence.get('path', '')
                if path not in inventory['documents']:
                    unavailable.add(path)
                    continue
                evidence_paths.add(path)
                start, end = evidence.get('start_line'), evidence.get('end_line')
                if type(start) is not int or type(end) is not int:
                    add(by_path[path], 'candidate with unspecified source range')
                else:
                    matching = [part for part in by_path[path] if part['end_line'] >= start and part['start_line'] <= end]
                    if not matching:
                        unavailable.add(path)
                    add(matching, 'candidate evidence')
    for path in sorted(evidence_paths):
        add_linked(path)
        for dependency in index.get(path, {}).get('dependencies', []):
            add_linked(dependency, path)
        # Route/settings call sites establish reachability and global protection.
        for dependent in index.get(path, {}).get('dependents', []):
            entry = index.get(dependent, {})
            if entry.get('routes') or any(item['name'] in {'MIDDLEWARE', 'ROOT_URLCONF', 'AUTHENTICATION_BACKENDS', 'STORAGES'}
                                           for item in entry.get('assignments', [])):
                add_linked(dependent)
    for path in sorted(linked_paths - evidence_paths):
        add_linked(path)
    if requirement_id == 'ИБ-06':
        # Documentation compliance cannot be based on just the best matching
        # paragraph: all authored documentation is required for this check.
        for path, parts in by_path.items():
            if PurePosixPath(path).suffix.lower() in DOC_SUFFIXES:
                add(parts, 'documentation requirement: all authored documents')

    note = ('The full source was assigned to overview batches. This is a second-pass retrieval of complete '
            'numbered chunks, candidate evidence, direct dependencies and related route/settings sites. '
            'Optional context is ranked by requirement concepts; unselected content is not silently claimed '
            'as part of this context. If a necessary protection/reachability chain is absent, conclude inconclusive. '
            'DOCX numbers refer to extracted paragraphs, not Word page lines.\n')
    resources = inventory.get('files', [])
    resource_count = sum(record.get('decision') == 'resource' for record in resources)
    if resource_count:
        note += f'{resource_count} static/third-party/binary resources were inventoried separately; their contents were not audited as source. Consult source references and manifest; do not infer dependency safety.\n'
    if len(note) > max_chars:
        raise ValueError('Context budget is too small for the mandatory scope description')
    included, omitted, blocks, size = [], [], [note], len(note)
    for chunk in chunks:
        if chunk['id'] not in required:
            continue
        text = rendered[chunk['id']]
        if size + len(text) > max_chars:
            omitted.append(chunk['id'])
        else:
            included.append(chunk['id'])
            blocks.append(text)
            size += len(text)
    # Optional retrieval is selected to fit. Failure to fit an explicit required
    # chunk above is still fatal; optional candidates are never called required.
    ranked = []
    for chunk in chunks:
        if chunk['id'] in required:
            continue
        entry = index.get(chunk['path'], {})
        score = _score(chunk['text'], requirement_id)
        if requirement_id in {'ИБ-01', 'ИБ-02', 'ИБ-07', 'ИБ-08'} and entry.get('routes'):
            score += 3
        if entry.get('assignments') and any(item['name'] in {'MIDDLEWARE', 'ROOT_URLCONF', 'AUTHENTICATION_BACKENDS', 'STORAGES', 'PASSWORD_HASHERS'} for item in entry['assignments']):
            score += 2
        if score:
            ranked.append((score, chunk))
    ranked.sort(key=lambda pair: (-pair[0], pair[1]['path'], pair[1]['start_line']))
    unselected_ids = []
    for _, chunk in ranked:
        text = rendered[chunk['id']]
        if size + len(text) <= max_chars:
            included.append(chunk['id'])
            blocks.append(text)
            size += len(text)
            selection_reasons[chunk['path']].add('ranked optional context')
        else:
            unselected_ids.append(chunk['id'])
    included_paths = sorted({by_id[cid]['path'] for cid in included})
    return {'text': ''.join(blocks), 'included_paths': included_paths,
            'omitted_paths': sorted({by_id[cid]['path'] for cid in omitted} | unavailable),
            'included_chunk_ids': included, 'omitted_chunk_ids': omitted,
            'unselected_optional_chunk_ids': unselected_ids,
            'unselected_paths': sorted(set(by_path) - set(included_paths)),
            'selection_reasons': {path: sorted(reasons) for path, reasons in selection_reasons.items()},
            'selection_note': note.strip()}
