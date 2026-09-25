"""Complete scoped inventory: exclude secrets before opening files, read target only."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path, PurePosixPath
from typing import Callable

from .readers import SECURE_FS, FS_MODE, ReadError, is_link_like, open_directory, read_bytes, read_document, stat_signature

# A directory entry represents the complete excluded subtree. It is deliberately
# not enumerated: enumerating .git/objects or a virtualenv is not source coverage.
EXCLUDED_DIRS = {
    '.git', '.hg', '.svn', '.venv', 'venv', 'env', '__pycache__', 'runtime',
    'node_modules', '.tox', '.nox', '.pytest_cache', '.mypy_cache', '.ruff_cache',
    '.cache', '.next', '.nuxt', '.idea', '.vscode', 'dist', 'build', 'htmlcov',
    'reports', 'logs', 'journal', 'media', 'coverage', '.ssh', '.gnupg',
}
SECRET_SUFFIXES = {'.key', '.pem', '.p12', '.pfx', '.jks', '.keystore', '.kdbx',
                   '.sqlite', '.sqlite3', '.db', '.log', '.evt', '.dat', '.pyc', '.pyo',
                   '.bak', '.dump', '.sql', '.crt', '.cer', '.der'}
SECRET_NAMES = {'.env', '.netrc', '.npmrc', '.pypirc', '.git-credentials',
                'credentials', 'credentials.json', 'secrets.json', 'secrets.yaml',
                'secrets.yml', 'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519'}
RESOURCE_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.svg', '.bmp',
                     '.avif', '.woff', '.woff2', '.ttf', '.eot', '.otf', '.mp3', '.mp4',
                     '.ogg', '.wav', '.pdf', '.zip', '.tar', '.gz', '.7z', '.rar',
                     '.mo', '.po', '.css', '.map', '.exe', '.dll', '.so', '.dylib'}
TEXT_SUFFIXES = {'.py', '.pyi', '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.html',
                 '.htm', '.jinja', '.jinja2', '.j2', '.xml', '.yaml', '.yml', '.json',
                 '.toml', '.ini', '.cfg', '.conf', '.md', '.rst', '.txt', '.sh', '.bash',
                 '.zsh', '.ps1', '.bat', '.cmd', '.properties', '.lock', '.csv', '.tsv',
                 '.service', '.socket', '.rules', '.policy', '.dockerignore', '.gitignore',
                 '.gitattributes', '.editorconfig', '.example', '.sample', '.c', '.h',
                 '.cpp', '.hpp', '.java', '.go', '.rs', '.rb', '.php'}


def classify(path: str, directory: bool = False) -> tuple[str, str, str]:
    parts = PurePosixPath(path).parts
    lower_parts = tuple(part.lower() for part in parts)
    name = lower_parts[-1]
    suffix = PurePosixPath(name).suffix
    if any(part in EXCLUDED_DIRS for part in lower_parts):
        return 'exclude', 'excluded_subtree' if directory else 'working_data', 'working data, VCS metadata, dependencies or generated output'
    if name == '.ds_store' or name.startswith('._') or name.endswith(('~', '.swp', '.swo')):
        return 'exclude', 'generated', 'OS/editor-generated artifact'
    # .env.example is excluded too; a file's claimed example status is not a
    # reliable promise that it contains no working credentials.
    if (name in SECRET_NAMES or name.startswith('.env') or suffix in SECRET_SUFFIXES
            or name.endswith(('.sqlite-wal', '.sqlite-shm', '.sqlite3-wal', '.sqlite3-shm', '.db-wal', '.db-shm'))):
        return 'exclude', 'secret_or_working_data', 'potential secret, database, log or working data; content never opened'
    if directory:
        return 'traverse', 'directory', ''
    if ('vendor' in lower_parts and (('static' in lower_parts) or suffix in RESOURCE_SUFFIXES or suffix in {'.js', '.json', '.md', '.txt'})) or 'licenses' in lower_parts:
        return 'resource', 'third_party_resource', 'bundled third-party resource; inventoried separately, no full dependency audit'
    if suffix in RESOURCE_SUFFIXES:
        return 'resource', 'static_or_binary_resource', 'static/binary/localization resource; hash and references only'
    if suffix == '.docx':
        return 'analyze', 'docx', ''
    if suffix in TEXT_SUFFIXES or not suffix or name in {'dockerfile', 'makefile', 'procfile'}:
        return 'analyze', 'python' if suffix == '.py' else 'text', ''
    # Unknown files may be source/configuration under a new name. Try a bounded
    # strict text read, and surface failure rather than silently excluding it.
    return 'analyze', 'unknown_text', ''


def _walk(root: Path) -> tuple[list[dict], list[str], tuple[int, ...] | None]:
    if not SECURE_FS:
        return _walk_portable(root)
    records, errors = [], []
    root_identity = None
    try:
        with open_directory(root) as root_fd:
            root_identity = stat_signature(os.fstat(root_fd))[:2]

            def visit(fd: int, prefix: str = '', depth: int = 0):
                if depth > 64:
                    errors.append(f'{prefix}: directory depth exceeds safe inventory limit')
                    return
                try:
                    with os.scandir(fd) as iterator:
                        entries = sorted(iterator, key=lambda entry: entry.name)
                except OSError:
                    errors.append(f'{prefix or "."}: directory cannot be enumerated')
                    return
                for entry in entries:
                    if len(records) >= 100_000:
                        errors.append('Inventory exceeds 100000 entries; coverage is incomplete')
                        return
                    path = f'{prefix}/{entry.name}' if prefix else entry.name
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        records.append({'path': path, 'decision': 'analyze', 'kind': 'unknown',
                                        'status': 'error', 'reason': 'Cannot stat filesystem entry', 'size': None, 'sha256': None, 'chunk_ids': []})
                        errors.append(f'{path}: filesystem metadata is inaccessible')
                        continue
                    if stat.S_ISLNK(info.st_mode):
                        records.append({'path': path, 'decision': 'exclude', 'kind': 'symlink',
                                        'status': 'excluded', 'reason': 'Symbolic links are never followed',
                                        'size': info.st_size, 'sha256': None, 'chunk_ids': [], '_stat': stat_signature(info)})
                        continue
                    is_dir = stat.S_ISDIR(info.st_mode)
                    decision, kind, reason = classify(path, is_dir)
                    if not is_dir and not stat.S_ISREG(info.st_mode):
                        decision, kind, reason = 'exclude', 'special_file', 'Socket, FIFO or device; never opened'
                    if decision == 'traverse':
                        try:
                            child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                            try:
                                if stat_signature(os.fstat(child_fd))[:2] != stat_signature(info)[:2]:
                                    raise ReadError('Directory replaced during inventory')
                                visit(child_fd, path, depth + 1)
                            finally:
                                os.close(child_fd)
                        except (OSError, ReadError):
                            errors.append(f'{path}: directory changed or cannot be opened without following links')
                        continue
                    record = {'path': path, 'kind': kind, 'size': info.st_size,
                              'decision': decision, 'reason': reason, 'sha256': None, 'chunk_ids': [],
                              'status': 'excluded' if decision == 'exclude' else 'pending',
                              '_stat': stat_signature(info)}
                    if is_dir:
                        record['scope'] = 'subtree'
                    records.append(record)

            visit(root_fd)
    except (OSError, ReadError) as exc:
        errors.append(f'Cannot safely enumerate repository: {type(exc).__name__}')
    return records, errors, root_identity


def _walk_portable(root: Path) -> tuple[list[dict], list[str], tuple[int, ...] | None]:
    """Windows walker: same classification, never descends into links/junctions."""
    records, errors = [], []
    try:
        root_identity = stat_signature(os.stat(root))[:2]
    except OSError as exc:
        return [], [f'Cannot safely enumerate repository: {type(exc).__name__}'], None

    def visit(directory: Path, prefix: str = '', depth: int = 0):
        if depth > 64:
            errors.append(f'{prefix}: directory depth exceeds safe inventory limit')
            return
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda entry: entry.name)
        except OSError:
            errors.append(f'{prefix or "."}: directory cannot be enumerated')
            return
        for entry in entries:
            if len(records) >= 100_000:
                errors.append('Inventory exceeds 100000 entries; coverage is incomplete')
                return
            path = f'{prefix}/{entry.name}' if prefix else entry.name
            try:
                info = os.lstat(entry.path)
            except OSError:
                records.append({'path': path, 'decision': 'analyze', 'kind': 'unknown',
                                'status': 'error', 'reason': 'Cannot stat filesystem entry', 'size': None, 'sha256': None, 'chunk_ids': []})
                errors.append(f'{path}: filesystem metadata is inaccessible')
                continue
            if is_link_like(info):
                records.append({'path': path, 'decision': 'exclude', 'kind': 'symlink',
                                'status': 'excluded', 'reason': 'Symbolic links, junctions and reparse points are never followed',
                                'size': info.st_size, 'sha256': None, 'chunk_ids': [], '_stat': stat_signature(info)})
                continue
            is_dir = stat.S_ISDIR(info.st_mode)
            decision, kind, reason = classify(path, is_dir)
            if not is_dir and not stat.S_ISREG(info.st_mode):
                decision, kind, reason = 'exclude', 'special_file', 'Socket, FIFO or device; never opened'
            if decision == 'traverse':
                visit(Path(entry.path), path, depth + 1)
                continue
            record = {'path': path, 'kind': kind, 'size': info.st_size,
                      'decision': decision, 'reason': reason, 'sha256': None, 'chunk_ids': [],
                      'status': 'excluded' if decision == 'exclude' else 'pending',
                      '_stat': stat_signature(info)}
            if is_dir:
                record['scope'] = 'subtree'
            records.append(record)

    visit(Path(root))
    return records, errors, root_identity


def _git(root: Path, records: list[dict]) -> dict:
    """Read Git metadata and included bytes only, scoped to the target subtree.

    The commit belongs to the enclosing repository, while dirty describes only
    the requested target. Git never inspects working files: staged changes are
    derived from HEAD/index object IDs and working changes from our safe reader.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_OPTIONAL_LOCKS='0', GIT_TERMINAL_PROMPT='0', GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL=os.devnull)
    base = ['git', '-c', 'core.fsmonitor=false', '-c', f'core.hooksPath={os.devnull}', '-C', str(root)]

    def run(*args):
        return subprocess.run(base + list(args), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              env=env, timeout=10, check=True).stdout
    result = {'commit': None, 'dirty': None, 'dirty_scope': 'unavailable', 'git_available': False,
              'git_root': None, 'target_subpath': None, 'commit_scope': 'enclosing_repository'}
    try:
        top = Path(os.fsdecode(run('rev-parse', '--show-toplevel').strip())).resolve()
        subpath = root.relative_to(top).as_posix()
        prefix = '' if subpath == '.' else subpath + '/'
        # Force all Git output to use repository-relative paths. Running some
        # commands in root and others in top mixes two different path bases.
        base[-1] = str(top)
        result.update(git_available=True, git_root=str(top), target_subpath=subpath)

        def target_path(raw_path: bytes) -> str | None:
            path = os.fsdecode(raw_path)
            if prefix and not path.startswith(prefix):
                return None
            relative = path[len(prefix):]
            return relative or None

        try:
            result['commit'] = run('rev-parse', '--verify', 'HEAD').decode('ascii').strip()
        except subprocess.CalledProcessError:
            pass  # A repository with no commits still has a useful content hash.
        try:
            algorithm = run('rev-parse', '--show-object-format').decode('ascii').strip()
        except subprocess.CalledProcessError:
            algorithm = 'sha1'
        tracked, committed = {}, {}
        conflicts = set()
        # Only metadata is returned, including for excluded files. A literal
        # pathspec avoids treating bracket/asterisk characters in a target name
        # as glob syntax. Python still checks the directory boundary explicitly.
        scope = ['--', f':(top,literal){prefix}'] if prefix else []
        for item in run('ls-files', '--stage', '--full-name', '-z', *scope).split(b'\x00'):
            if not item:
                continue
            fields, raw_path = item.split(b'\t', 1)
            path = target_path(raw_path)
            if path is None:
                continue
            mode, digest, stage = fields.split()
            if stage != b'0':
                conflicts.add(path)
            tracked[path] = (mode.decode('ascii'), digest.decode('ascii'))
        if result['commit']:
            # ls-tree is metadata only; unlike a working-tree diff it cannot
            # hash .env or invoke a clean/smudge filter on an excluded file.
            for item in run('ls-tree', '-r', '-z', '--full-tree', 'HEAD', *scope).split(b'\x00'):
                if not item:
                    continue
                fields, raw_path = item.split(b'\t', 1)
                path = target_path(raw_path)
                if path is None:
                    continue
                mode, _kind, digest = fields.split()
                committed[path] = (mode.decode('ascii'), digest.decode('ascii'))
        observed = {record['path']: record for record in records if record['decision'] != 'exclude'}
        excluded = {record['path'] for record in records if record['decision'] == 'exclude'}
        dirty, unknown = False, False
        for path in sorted(tracked.keys() | committed.keys()):
            decision, _, _ = classify(path)
            if decision == 'exclude' or path in excluded:
                unknown = True
                continue
            staged = tracked.get(path)
            if staged != committed.get(path) or path in conflicts:
                dirty = True
            record = observed.get(path)
            if record is None:
                if staged is not None:
                    dirty = True
                continue
            if staged is None:
                dirty = True
                continue
            mode, digest = staged
            if record.get('_git_blob', {}).get(algorithm) is None:
                unknown = True
            elif digest not in (record['_git_blob'][algorithm], record.get('_git_blob_lf', {}).get(algorithm)):
                dirty = True
            if os.name != 'nt' and record.get('_stat') and mode in {'100644', '100755'}:
                executable = bool(record['_stat'][2] & 0o111)
                if executable != (mode == '100755'):
                    dirty = True
        # Untracked included source affects this target even when gitignore
        # hides it; unrelated sibling files are absent from observed entirely.
        dirty |= any(path not in tracked for path in observed)
        result['dirty'] = True if dirty else None if unknown else False
        result['dirty_scope'] = ('target subtree: included files and staged metadata; excluded tracked content unchecked'
                                 if unknown else 'target subtree: included files and staged metadata')
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeError):
        result['dirty_scope'] = 'Git metadata unavailable; content snapshot used instead'
    return result


def _chunks(path: str, lines: list[str], budget: int, line_semantics: str) -> list[dict]:
    result, block, size, start = [], [], 0, 1

    def flush(end: int):
        text = '\n'.join(block)
        digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
        chunk_id = hashlib.sha256(f'{path}\0{start}\0{end}\0{digest}'.encode()).hexdigest()[:20]
        result.append({'id': f'chunk-{chunk_id}', 'path': path, 'start_line': start,
                       'end_line': end, 'text': text, 'sha256': digest,
                       'line_semantics': line_semantics})
    for number, line in enumerate(lines, 1):
        if len(line) > budget:
            raise ReadError(f'Line {number} exceeds the {budget}-character chunk limit; file not truncated')
        addition = len(line) + bool(block)
        if block and size + addition > budget:
            flush(number - 1)
            block, size, start = [], 0, number
        block.append(line)
        size += len(line) + (1 if len(block) > 1 else 0)
    if block:
        flush(len(lines))
    return result


def collect(repo: Path, redactor: Callable[[str], str], max_file_bytes: int = 2_000_000,
            chunk_chars: int = 18000) -> dict:
    if max_file_bytes < 1 or chunk_chars < 1:
        raise ValueError('Read and chunk limits must be positive')
    requested = Path(repo).expanduser().absolute()
    if requested.is_symlink():
        raise ValueError('Repository root must not be a symbolic link')
    root = requested.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Repository root must be a directory')
    records, errors, root_identity = _walk(root)
    documents, chunks = {}, []
    for record in records:
        if record['decision'] == 'exclude' or record['status'] == 'error':
            continue
        path = record['path']
        if record['decision'] == 'resource' and record['size'] > max_file_bytes:
            record.update(status='resource_unread', reason=record['reason'] + '; exceeds resource hash budget')
            continue
        try:
            payload, info = read_bytes(root, path, max_file_bytes)
            if stat_signature(info) != record['_stat']:
                raise ReadError('File changed between enumeration and reading')
            record['sha256'] = hashlib.sha256(payload).hexdigest()
            blob = f'blob {len(payload)}\0'.encode() + payload
            record['_git_blob'] = {name: hashlib.new(name, blob).hexdigest() for name in ('sha1', 'sha256')}
            if b'\r\n' in payload:
                # Windows checkouts (core.autocrlf) keep CRLF on disk while Git stores LF.
                normalized = payload.replace(b'\r\n', b'\n')
                lf_blob = f'blob {len(normalized)}\0'.encode() + normalized
                record['_git_blob_lf'] = {name: hashlib.new(name, lf_blob).hexdigest() for name in ('sha1', 'sha256')}
            if record['decision'] == 'resource':
                record['status'] = 'resource'
                continue
            document = read_document(payload, path)
            safe_text = redactor(document['text'])
            safe_lines = (safe_text.split('\n') if document['lines'] else []) if document['kind'] == 'docx' else safe_text.splitlines()
            if len(safe_lines) != len(document['lines']):
                raise ReadError('Redaction changed source line count; accurate evidence locations unavailable')
            document.update(text=safe_text, lines=safe_lines)
            parts = _chunks(path, safe_lines, chunk_chars, document['line_semantics'])
            record.update(status='ready', chunk_ids=[part['id'] for part in parts],
                          line_count=len(safe_lines), line_semantics=document['line_semantics'])
            documents[path] = document
            chunks.extend(parts)
        except (ReadError, OSError, ValueError) as exc:
            record.update(status='error', reason=redactor(str(exc) if isinstance(exc, ReadError) else type(exc).__name__))
            errors.append(f'{path}: {record["reason"]}')
    digest_entries = [(r['path'], r['decision'], r['sha256'], r['size'], r['status'])
                      for r in records if r['decision'] != 'exclude']
    target = _git(root, records)
    target['content_hash'] = hashlib.sha256(json.dumps(digest_entries, ensure_ascii=True, separators=(',', ':')).encode()).hexdigest()
    target['content_hash_scope'] = 'all included readable bytes plus explicit unread/error records; excludes secrets'
    target['filesystem_mode'] = FS_MODE
    return {'root': str(root), 'target': target, 'files': records,
            'documents': documents, 'chunks': chunks, 'errors': [redactor(error) for error in errors],
            '_snapshot': {'root_identity': root_identity, 'max_file_bytes': max_file_bytes}}


def public_manifest(data: dict) -> dict:
    """Metadata only: document contents, secrets and raw chunks never escape here."""
    files = [{key: value for key, value in record.items() if not key.startswith('_')}
             for record in data['files']]
    chunks = [{key: value for key, value in chunk.items() if key != 'text'} for chunk in data['chunks']]
    return {'schema_version': '1.0', 'root': data['root'], 'target': dict(data['target']),
            'files': files, 'chunks': chunks, 'errors': list(data['errors']),
            'coverage_note': 'ready means fully read and chunked, not yet reviewed by the model; excluded subtree entries cover descendants',
            'resource_note': 'Resource contents do not enter source-review batches; metadata and source references remain available. No full third-party dependency audit.'}


def check_unchanged(data: dict) -> list[str]:
    root = Path(data['root'])
    records, errors, identity = _walk(root)
    if identity != data['_snapshot']['root_identity']:
        errors.append('Repository root was replaced during analysis')
    before = {r['path']: r for r in data['files'] if r['decision'] != 'exclude'}
    after = {r['path']: r for r in records if r['decision'] != 'exclude'}
    for path in sorted(before.keys() - after.keys()):
        errors.append(f'{path}: included file removed or replaced with an excluded object during analysis')
    for path in sorted(after.keys() - before.keys()):
        errors.append(f'{path}: included file added during analysis')
    for path in sorted(before.keys() & after.keys()):
        original, current = before[path], after[path]
        if original.get('sha256') is None:
            if original.get('_stat') != current.get('_stat'):
                errors.append(f'{path}: unread file changed during analysis')
            continue
        try:
            payload, _ = read_bytes(root, path, data['_snapshot']['max_file_bytes'])
            if hashlib.sha256(payload).hexdigest() != original['sha256']:
                errors.append(f'{path}: content changed during analysis')
        except (OSError, ReadError):
            errors.append(f'{path}: cannot safely verify the original source snapshot')
    if data['target'].get('commit') != _git(root, records).get('commit'):
        errors.append('Git commit changed during analysis')
    return errors
