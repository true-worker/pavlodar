"""Bounded, non-executing readers for untrusted repository files."""
from __future__ import annotations

import io
import os
import stat
import tokenize
import zipfile
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from xml.etree import ElementTree


class ReadError(ValueError):
    """A file cannot safely be read in full; never means it was truncated."""


def stat_signature(value: os.stat_result) -> tuple[int, ...]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


# POSIX (Linux/macOS): race-free openat()/O_NOFOLLOW traversal.
# Windows has no dir_fd API, so a portable path-based reader is used instead:
# links/junctions/reparse points are still never followed, and every read is
# bracketed by stat checks. The remaining check-then-open window is documented.
SECURE_FS = (hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY')
             and os.open in os.supports_dir_fd)
FS_MODE = 'posix_openat_nofollow' if SECURE_FS else 'portable_path_checks'


def is_link_like(info: os.stat_result) -> bool:
    """Symlink, junction or any other Windows reparse point."""
    if stat.S_ISLNK(info.st_mode):
        return True
    attributes = getattr(info, 'st_file_attributes', 0)
    return bool(attributes & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400))


def _portable_path(repo: Path, parts: tuple[str, ...]) -> Path:
    current = Path(repo)
    for part in parts:
        current = current / part
        info = os.lstat(current)
        if is_link_like(info):
            raise ReadError('Links and reparse points are never followed')
    return current


def _read_bytes_portable(repo: Path, parts: tuple[str, ...], limit: int) -> tuple[bytes, os.stat_result]:
    path = _portable_path(repo, parts)
    named_before = os.lstat(path)
    if not stat.S_ISREG(named_before.st_mode):
        raise ReadError('Not a regular file')
    if named_before.st_size > limit:
        raise ReadError(f'File exceeds the {limit}-byte read limit; not read')
    with open(path, 'rb') as handle:
        before = os.fstat(handle.fileno())
        if stat_signature(before)[:4] != stat_signature(named_before)[:4]:
            raise ReadError('File was replaced before reading')
        payload = handle.read(limit + 1)
        if len(payload) > limit:
            raise ReadError(f'File grew beyond the {limit}-byte read limit')
        after = os.fstat(handle.fileno())
    if stat_signature(before) != stat_signature(after):
        raise ReadError('File changed while being read')
    named_after = os.lstat(path)
    if is_link_like(named_after) or stat_signature(named_after)[:4] != stat_signature(after)[:4]:
        raise ReadError('File was replaced while being read')
    return payload, named_after


@contextmanager
def open_directory(path: Path):
    if not SECURE_FS:
        raise ReadError('open_directory requires the POSIX no-follow API; use the portable walker')
    absolute = Path(path).absolute()
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def read_bytes(repo: Path, relative: str, limit: int) -> tuple[bytes, os.stat_result]:
    """Read one regular file below an anchored root without following symlinks."""
    parts = PurePosixPath(relative).parts
    if not parts or any(part in ('', '.', '..') for part in parts) or parts[0] == '/':
        raise ReadError('Invalid repository-relative path')
    if not SECURE_FS:
        return _read_bytes_portable(Path(repo), parts, limit)
    with open_directory(repo) as root_fd:
        current = os.dup(root_fd)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                  dir_fd=current)
                os.close(current)
                current = next_fd
            fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=current)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise ReadError('Not a regular file')
                if before.st_size > limit:
                    raise ReadError(f'File exceeds the {limit}-byte read limit; not read')
                pieces, size = [], 0
                while True:
                    block = os.read(fd, min(65536, limit + 1 - size))
                    if not block:
                        break
                    pieces.append(block)
                    size += len(block)
                    if size > limit:
                        raise ReadError(f'File grew beyond the {limit}-byte read limit')
                after = os.fstat(fd)
                if stat_signature(before) != stat_signature(after):
                    raise ReadError('File changed while being read')
                # Verify that the directory still names the same file.
                named = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
                if stat_signature(after) != stat_signature(named):
                    raise ReadError('File was replaced while being read')
                return b''.join(pieces), after
            finally:
                os.close(fd)
        finally:
            os.close(current)


def text_document(payload: bytes, suffix: str = '') -> dict:
    """Decode exactly; undecodable input is reported instead of repaired."""
    try:
        if suffix == '.py':
            encoding, _ = tokenize.detect_encoding(io.BytesIO(payload).readline)
        elif payload.startswith((b'\xff\xfe', b'\xfe\xff')):
            encoding = 'utf-16'
        else:
            encoding = 'utf-8-sig'
        text = payload.decode(encoding)
    except (UnicodeError, SyntaxError, LookupError) as exc:
        raise ReadError('Cannot decode the complete file as supported text') from exc
    if '\x00' in text:
        raise ReadError('Binary content in a file selected for text analysis')
    return {'text': text, 'lines': text.splitlines(), 'kind': 'text',
            'line_semantics': 'source_lines', 'encoding': encoding}


def docx_document(payload: bytes, max_expanded_bytes: int = 16_000_000) -> dict:
    """Extract all paragraph/table text in document order, without ZIP extraction.

    Coordinates are extracted paragraph numbers, not Word page/line positions.
    Tables are included because their cells contain ordinary w:p paragraphs.
    """
    ns = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'
    paragraphs = []
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            members = archive.infolist()
            names = [entry.filename for entry in members]
            if len(names) != len(set(names)):
                raise ReadError('DOCX contains duplicate ZIP member names')
            selected = [entry for entry in members if entry.filename == 'word/document.xml'
                        or (entry.filename.startswith(('word/header', 'word/footer'))
                            and entry.filename.endswith('.xml'))
                        or entry.filename in ('word/footnotes.xml', 'word/endnotes.xml', 'word/comments.xml')]
            if 'word/document.xml' not in names:
                raise ReadError('DOCX lacks word/document.xml')
            if sum(entry.file_size for entry in selected) > max_expanded_bytes:
                raise ReadError('DOCX expanded XML exceeds the read limit; not truncated')
            selected.sort(key=lambda entry: (entry.filename != 'word/document.xml', entry.filename))
            for entry in selected:
                if entry.flag_bits & 1:
                    raise ReadError('Encrypted DOCX XML cannot be read')
                xml = archive.read(entry)
                declaration_check = xml.replace(b'\x00', b'').upper()
                if b'<!DOCTYPE' in declaration_check or b'<!ENTITY' in declaration_check:
                    raise ReadError('DTD/entity declarations are not accepted in DOCX')
                root = ElementTree.fromstring(xml)
                for paragraph in root.iter(ns + 'p'):
                    pieces = []
                    for node in paragraph.iter():
                        if node.tag in (ns + 't', ns + 'delText', ns + 'instrText'):
                            pieces.append(node.text or '')
                        elif node.tag == ns + 'tab':
                            pieces.append('\t')
                        elif node.tag in (ns + 'br', ns + 'cr'):
                            pieces.append(' ')
                    paragraphs.append(''.join(pieces).replace('\r', ' ').replace('\n', ' '))
    except ReadError:
        raise
    except (zipfile.BadZipFile, ElementTree.ParseError, RuntimeError, OSError, KeyError, NotImplementedError, ValueError, EOFError) as exc:
        raise ReadError('Invalid or unsupported DOCX container/XML') from exc
    return {'text': '\n'.join(paragraphs), 'lines': paragraphs,
            'kind': 'docx', 'line_semantics': 'extracted_paragraphs_not_page_lines'}


def read_document(payload: bytes, path: str) -> dict:
    suffix = PurePosixPath(path).suffix.lower()
    return docx_document(payload) if suffix == '.docx' else text_document(payload, suffix)
