"""Safety and coverage tests using fresh targets; never executes target code."""
from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

from kmg_security_agent import context, index, inventory, readers


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / 'target'
        self.root.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, text):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding='utf-8', newline='\n')  # identical bytes on Windows
        return destination

    def collect(self, **kwargs):
        return inventory.collect(self.root, lambda text: text.replace('SENSITIVE_VALUE', '[REDACTED]'), **kwargs)

    def test_excludes_secrets_before_open_and_keeps_library_source(self):
        paths = ['.env', '.env.local', '.env.example', 'server.pem', 'runtime/token.py',
                 '.venv/fake.py', '.git/config', 'db.sqlite3', 'journal/secret.txt']
        for path in paths:
            self.write(path, 'SENSITIVE_VALUE')
        self.write('src/helpdesk/models.py', 'SECRET_KEY = "SENSITIVE_VALUE"\nclass Domain: pass\n')
        self.write('src/vendor/service.py', 'def relevant(): pass\n')
        self.write('static/vendor/plugin.js', 'console.log("resource");\n')
        opened = []
        actual_reader = inventory.read_bytes
        def recording_reader(root, path, limit):
            opened.append(path)
            return actual_reader(root, path, limit)
        with mock.patch.object(inventory, 'read_bytes', side_effect=recording_reader):
            data = self.collect()
            self.assertEqual([], inventory.check_unchanged(data))
        self.assertFalse(set(paths) & set(opened))
        self.assertIn('src/helpdesk/models.py', data['documents'])
        self.assertIn('src/vendor/service.py', data['documents'])
        record = next(record for record in data['files'] if record['path'] == 'static/vendor/plugin.js')
        self.assertEqual('third_party_resource', record['kind'])
        self.assertEqual('resource', record['decision'])
        self.assertNotIn('static/vendor/plugin.js', data['documents'])
        manifest = inventory.public_manifest(data)
        self.assertNotIn('documents', manifest)
        self.assertTrue(all('text' not in chunk for chunk in manifest['chunks']))
        self.assertNotIn('SENSITIVE_VALUE', json.dumps(data['documents']))
        self.assertTrue(all(record['sha256'] is None for record in manifest['files'] if record['decision'] == 'exclude'))
        self.assertTrue(any(record.get('scope') == 'subtree' for record in manifest['files']))

    def test_symlinks_and_fifo_are_never_opened(self):
        outside = self.root.parent / 'outside'
        outside.mkdir()
        (outside / 'secret.py').write_text('SENSITIVE_VALUE')
        (self.root / 'linked.py').symlink_to(outside / 'secret.py')
        (self.root / 'linked-directory').symlink_to(outside, target_is_directory=True)
        if hasattr(os, 'mkfifo'):
            os.mkfifo(self.root / 'pipe.py')
        self.write('source.py', 'value = 1\n')
        data = self.collect()
        self.assertEqual({'source.py'}, set(data['documents']))
        self.assertEqual([], data['errors'])
        with self.assertRaises((OSError, readers.ReadError)):
            readers.read_bytes(self.root, 'linked-directory/secret.py', 1000)
        with self.assertRaises(ValueError):
            inventory.collect(self.root / 'linked-directory', str)

    def test_full_line_coverage_and_bounded_batches(self):
        lines = [f'value_{i} = {i}' for i in range(75)]
        self.write('new_feature.py', '\n'.join(lines) + '\n')
        data = self.collect(chunk_chars=100)
        self.assertEqual([], data['errors'])
        recovered = []
        previous_end = 0
        for chunk in data['chunks']:
            self.assertEqual(previous_end + 1, chunk['start_line'])
            self.assertEqual(lines[chunk['start_line'] - 1:chunk['end_line']], chunk['text'].split('\n'))
            recovered.extend(chunk['text'].split('\n'))
            previous_end = chunk['end_line']
        self.assertEqual(lines, recovered)
        batches = context.build_batches(data, max_chars=650)
        self.assertEqual([chunk['id'] for chunk in data['chunks']], [chunk['id'] for batch in batches for chunk in batch['chunks']])
        self.assertTrue(all(len(batch['text']) <= 650 for batch in batches))
        self.assertTrue(data['files'][0]['review_batch_ids'])
        with self.assertRaisesRegex(ValueError, 'no source was truncated'):
            context.build_batches(data, max_chars=50)

    def test_oversized_sources_report_errors_without_partial_coverage(self):
        self.write('large.py', 'x' * 300)
        data = self.collect(max_file_bytes=100)
        self.assertTrue(data['errors'])
        self.assertEqual({}, data['documents'])
        self.assertEqual([], data['chunks'])
        data = self.collect(chunk_chars=100)
        self.assertIn('Line 1 exceeds', data['errors'][0])
        self.assertEqual([], data['chunks'])
        self.write('bad.txt', 'abc')
        (self.root / 'bad.txt').write_bytes(b'\xff\x00\xff')
        self.assertTrue(any('Cannot decode' in error or 'Binary content' in error for error in self.collect()['errors']))

    def test_snapshot_detects_same_size_edit_new_file_delete_and_ignores_secrets(self):
        source = self.write('feature.py', 'answer = 1\n')
        self.write('.env', 'SENSITIVE_VALUE')
        data = self.collect()
        self.write('.env', 'changed secret')
        self.assertEqual([], inventory.check_unchanged(data))
        old = source.stat()
        source.write_text('answer = 2\n')
        os.utime(source, ns=(old.st_atime_ns, old.st_mtime_ns))
        self.assertTrue(any('content changed' in error for error in inventory.check_unchanged(data)))
        source.write_text('answer = 1\n')
        self.write('novel_endpoint.py', 'pass\n')
        self.assertTrue(any('added' in error for error in inventory.check_unchanged(data)))
        (self.root / 'novel_endpoint.py').unlink()
        source.unlink()
        self.assertTrue(any('removed' in error for error in inventory.check_unchanged(data)))

    def test_docx_paragraphs_tables_and_headers_have_explicit_coordinates(self):
        xml = '''<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>
        <w:p><w:r><w:t>Первый абзац</w:t></w:r></w:p>
        <w:tbl><w:tr><w:tc><w:p><w:r><w:t>Ячейка таблицы</w:t></w:r></w:p></w:tc></w:tr></w:tbl>
        </w:body></w:document>'''
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('word/document.xml', xml)
            archive.writestr('word/header1.xml', '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>Header</w:t></w:r></w:p></w:hdr>')
        (self.root / 'spec.docx').write_bytes(buffer.getvalue())
        data = self.collect()
        doc = data['documents']['spec.docx']
        self.assertEqual(['Первый абзац', 'Ячейка таблицы', 'Header'], doc['lines'])
        self.assertEqual('extracted_paragraphs_not_page_lines', doc['line_semantics'])
        self.assertEqual((1, 3), (data['chunks'][0]['start_line'], data['chunks'][0]['end_line']))
        with self.assertRaisesRegex(readers.ReadError, 'expanded XML'):
            readers.docx_document(buffer.getvalue(), max_expanded_bytes=20)

    def test_docx_entities_are_rejected_and_multiline_redaction_fails_closed(self):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('word/document.xml', '<!DOCTYPE x [<!ENTITY e "expanded">]><x>&e;</x>')
        with self.assertRaisesRegex(readers.ReadError, 'DTD/entity'):
            readers.docx_document(buffer.getvalue())
        self.write('source.py', 'first = 1\nsecond = 2\n')
        data = inventory.collect(self.root, lambda text: text.replace('first = 1\nsecond = 2\n', 'one line'))
        self.assertTrue(any('line count' in error for error in data['errors']))
        self.assertEqual([], data['chunks'])

    def test_generic_ast_resolves_new_names_relative_imports_and_routes(self):
        self.write('src/package/__init__.py', '')
        self.write('src/package/guard.py', 'def can_enter(user):\n    return user.is_staff\n')
        self.write('src/package/handlers.py', 'from .guard import can_enter\n@can_enter\ndef unusual_name(request):\n    return 1\n')
        self.write('src/package/mapping.py', 'from django.urls import path as endpoint\nfrom .handlers import unusual_name\nurlpatterns = [endpoint("novel/", unusual_name)]\n')
        self.write('src/package/domain.py', 'class Profile: pass\n')
        self.write('src/package/configuration.py', 'USER_MODEL = \"package.Profile\"\n')
        self.write('src/package/pages/screen.html', '<p>template</p>\n')
        self.write('src/package/display.py', 'template_name = \"pages/screen.html\"\n')
        self.write('never_run.py', 'raise RuntimeError("target must not execute")\n')
        data = self.collect()
        mapped = index.build_index(data['documents'])
        self.assertIn('src/package/handlers.py', mapped['src/package/mapping.py']['dependencies'])
        self.assertIn('src/package/guard.py', mapped['src/package/handlers.py']['dependencies'])
        self.assertEqual('unusual_name', mapped['src/package/mapping.py']['routes'][0]['target'])
        self.assertEqual(['can_enter'], mapped['src/package/handlers.py']['symbols'][0]['decorators'])
        self.assertIn('src/package/domain.py', mapped['src/package/configuration.py']['dependencies'])
        self.assertIn('src/package/pages/screen.html', mapped['src/package/display.py']['dependencies'])
        self.assertEqual([], data['errors'])

    def test_required_context_overflow_explicit_and_optional_unselected_not_error(self):
        for number in range(12):
            self.write(f'unit_{number}.py', 'def authenticate(value):\n    return value.is_active\n' * 20)
        data = self.collect(chunk_chars=200)
        mapped = index.build_index(data['documents'])
        review = {'candidates': [{'requirement_id': 'ИБ-02', 'evidence': [{'path': 'unit_0.py', 'start_line': 1, 'end_line': 2}]}], 'related_paths': []}
        selected = context.requirement_context(data, mapped, [review], 'ИБ-02', max_chars=1200)
        self.assertIn('unit_0.py', selected['omitted_paths'])
        self.assertTrue(selected['omitted_chunk_ids'])
        self.assertLessEqual(len(selected['text']), 1200)
        selected = context.requirement_context(data, mapped, [], 'ИБ-02', max_chars=1200)
        self.assertEqual([], selected['omitted_paths'])
        self.assertTrue(selected['unselected_optional_chunk_ids'])
        self.assertEqual(len(selected['included_chunk_ids']), len(set(selected['included_chunk_ids'])))

    @unittest.skipUnless(shutil.which('git'), 'git not installed')
    def test_git_dirty_metadata_does_not_read_tracked_env(self):
        def git(*args):
            return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
                                   '-c', 'user.name=Inventory test', '-c', 'user.email=test@example.test',
                                   '-C', str(self.root), *args], check=True, capture_output=True)
        self.write('source.py', 'number = 1\n')
        self.write('.env', 'SENSITIVE_VALUE')
        git('init', '-q')
        git('add', '.')
        git('commit', '-qm', 'fixture')
        with mock.patch.object(inventory, 'read_bytes', wraps=inventory.read_bytes) as opened:
            data = self.collect()
        self.assertNotIn('.env', [call.args[1] for call in opened.call_args_list])
        self.assertIsNone(data['target']['dirty'])
        self.assertIn('excluded tracked', data['target']['dirty_scope'])
        self.assertIsNotNone(data['target']['commit'])
        self.write('source.py', 'number = 2\n')
        self.assertTrue(self.collect()['target']['dirty'])


    @unittest.skipUnless(shutil.which('git'), 'git not installed')
    def test_git_monorepo_subtree_tracks_outer_commit_and_only_target_changes(self):
        outer = self.root.parent
        # Brackets/spaces expose accidental glob interpretation; a sibling with
        # the same prefix exposes missing slash-boundary checks.
        renamed = outer / 'target [app]'
        self.root.rename(renamed)
        self.root = renamed
        sibling = outer / 'target [app]-agent'
        sibling.mkdir()
        outside = sibling / 'agent.py'
        outside.write_text('agent_version = 1\n')
        (outer / '.env').write_text('SENSITIVE_VALUE')
        self.write('source.py', 'number = 1\n')
        self.write('package/child.py', 'child = 1\n')
        def git(*args):
            return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
                                   '-c', 'user.name=Inventory test', '-c', 'user.email=test@example.test',
                                   '-C', str(outer), *args], check=True, capture_output=True)
        git('init', '-q')
        git('add', '.')
        git('commit', '-qm', 'monorepo fixture')
        expected_commit = git('rev-parse', 'HEAD').stdout.decode().strip()
        data = self.collect()
        self.assertTrue(data['target']['git_available'])
        self.assertEqual(expected_commit, data['target']['commit'])
        self.assertEqual(str(outer), data['target']['git_root'])
        self.assertEqual('target [app]', data['target']['target_subpath'])
        self.assertEqual('enclosing_repository', data['target']['commit_scope'])
        self.assertIs(data['target']['dirty'], False, data['target'])
        self.assertEqual({'source.py', 'package/child.py'}, set(data['documents']))
        outside.write_text('agent_version = 2\n')
        self.assertIs(self.collect()['target']['dirty'], False)
        git('add', '--', 'target [app]-agent/agent.py')
        self.assertIs(self.collect()['target']['dirty'], False)
        self.assertEqual([], inventory.check_unchanged(data))
        self.write('source.py', 'number = 2\n')
        self.assertIs(self.collect()['target']['dirty'], True)
        git('add', '--', 'target [app]/source.py')
        # Working bytes now equal the index, but differ from committed HEAD.
        self.assertIs(self.collect()['target']['dirty'], True)
        self.write('source.py', 'number = 1\n')
        git('add', '--', 'target [app]/source.py')
        self.assertIs(self.collect()['target']['dirty'], False)
        (self.root / 'package/child.py').unlink()
        git('add', '-u', '--', 'target [app]/package/child.py')
        self.assertIs(self.collect()['target']['dirty'], True)

    @unittest.skipUnless(shutil.which('git'), 'git not installed')
    def test_git_monorepo_excluded_tracked_secret_is_unknown_without_reads(self):
        outer = self.root.parent
        self.write('source.py', 'number = 1\n')
        self.write('.env', 'SENSITIVE_VALUE')
        (outer / 'agent.py').write_text('agent = 1\n')
        def git(*args):
            return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
                                   '-c', 'user.name=Inventory test', '-c', 'user.email=test@example.test',
                                   '-C', str(outer), *args], check=True, capture_output=True)
        git('init', '-q')
        git('add', '.')
        git('commit', '-qm', 'excluded file fixture')
        self.write('.env', 'different synthetic secret')
        with mock.patch.object(inventory, 'read_bytes', wraps=inventory.read_bytes) as opened:
            data = self.collect()
            self.assertEqual([], inventory.check_unchanged(data))
        self.assertNotIn('.env', [call.args[1] for call in opened.call_args_list])
        self.assertIsNone(data['target']['dirty'])
        self.assertIn('excluded tracked', data['target']['dirty_scope'])
        self.assertEqual('target', data['target']['target_subpath'])
        # A staged secret still does not cause the excluded content to be read.
        git('add', '--', 'target/.env')
        with mock.patch.object(inventory, 'read_bytes', wraps=inventory.read_bytes) as opened:
            self.assertIsNone(self.collect()['target']['dirty'])
        self.assertNotIn('.env', [call.args[1] for call in opened.call_args_list])
        self.write('source.py', 'number = 2\n')
        self.assertIs(self.collect()['target']['dirty'], True)


if __name__ == '__main__':
    unittest.main()
