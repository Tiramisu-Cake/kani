# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Offline fixtures only: Python children, no compiler/full runner."""
import gzip
import hashlib
import json
from pathlib import Path
import random
import signal
import sys
import tempfile
import unittest
from unittest import mock
import check_package
import pack_evidence
import rich_evidence
import runner
import rustc_diagnostics as diagnostics


def unpack(root):
    pack_evidence.pack(root)
    return json.loads(gzip.decompress((root/pack_evidence.NAME).read_bytes()))


class DiagnosticsTests(unittest.TestCase):
    def test_middle_errors_both_previews_compile_failure_and_pack(self):
        blocks = ['error[E0308]: mismatched types\n --> src/a.rs:7:9\n  |\n7 | let x = café;\n  |         ^^^^ expected u8\n  = note: first note\n  = help: first help\n\n',
                  'error: second failure\n --> src/b.rs:2:1\n  = note: multiline\n    continuation\n\n']
        stdout = 'HEAD\n'+'noise\n'*14000+''.join(blocks)+'noise\n'*14000+'TAIL\n'
        stderr = 'errhead\n'+'noise\n'*1000+'\x1b[1;31merror[E9999]\x1b[0m: stderr failure\n  = help: retained\n'+'noise\n'*1000+'errtail\n'
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root/'fixture-out').write_text(stdout)
            (root/'fixture-err').write_text(stderr)
            monitor = runner.CompileMonitor(root/'compile/receipt.json', root/'export.json', ['fixture'])
            parser = rich_evidence.RegularEvidence(['fixture'], root)
            code = "import pathlib,sys;sys.stdout.buffer.write(pathlib.Path('fixture-out').read_bytes());sys.stderr.buffer.write(pathlib.Path('fixture-err').read_bytes());sys.exit(1)"
            result = runner.execute([sys.executable, '-c', code], root, root, 3,
                                    capture_tail=True, rich_parser=parser, compile_monitor=monitor)
            self.assertEqual(result['original_exit_code'], 1)
            self.assertTrue(result['rustc_diagnostics']['complete'])
            old = runner._bounded_log(root/'stdout.log', result['stdout_bytes'])
            self.assertNotIn('mismatched types', old['head']+old['tail'])
            self.assertNotIn('mismatched types', (root/'stdout.log').read_text())
            compile_receipt = json.loads((root/'compile/receipt.json').read_text())
            self.assertEqual(compile_receipt['state'], 'FAILED')
            self.assertNotIn('mismatched types', compile_receipt['stdout']['head']+compile_receipt['stdout']['tail'])
            self.assertTrue(compile_receipt['rustc_diagnostics']['complete'])
            captured = json.loads((root/'rustc-stdout-receipt.json').read_text())
            self.assertEqual([b['text'] for b in captured['blocks']], blocks)
            for block in captured['blocks']:
                original = stdout.encode()[block['start_byte']:block['end_byte']].decode()
                self.assertEqual(original, block['text'])
                self.assertTrue(block['complete'])
            err = json.loads((root/'rustc-stderr-receipt.json').read_text())
            self.assertEqual(err['blocks'][0]['stream'], 'stderr')
            self.assertIn('error[E9999]: stderr failure\n  = help: retained', err['blocks'][0]['text'])
            artifact = unpack(root)
            self.assertEqual(artifact['state'], 'PACKAGED')
            for stream, count in [('stdout', 2), ('stderr', 1)]:
                embedded = json.loads(artifact['files']['rustc-'+stream+'-receipt.json']['text'])
                self.assertEqual(len(embedded['blocks']), count)
                self.assertTrue(artifact['rustc_diagnostics']['.']['streams'][stream]['compact_payload_retained'])

    def test_single_byte_ansi_utf8_and_unterminated_eof(self):
        data = b'prefix\n\x1b[1;31merror[E0001]\x1b[0m: ' + 'ошибка\n  = note: café\n  = help: fix'.encode()
        with tempfile.TemporaryDirectory() as d:
            cap = diagnostics.Capture('stderr', 8192, Path(d)/'receipt.json')
            for byte in data:
                cap.feed(bytes([byte]))
            self.assertFalse(cap.document()['complete'])
            self.assertIn('pending_context', cap.document())
            cap.finish()
            value = cap.document()
            self.assertTrue(value['complete'])
            self.assertEqual(len(value['blocks']), 1)
            self.assertEqual(value['blocks'][0]['start_byte'], 7)
            self.assertEqual(value['blocks'][0]['end_byte'], len(data))
            self.assertIn('ошибка', value['blocks'][0]['text'])
            self.assertNotIn('\ufffd', value['blocks'][0]['text'])
            self.assertNotIn('\x1b', value['blocks'][0]['text'])

    def test_caps_count_dropped_blocks_context_and_unscanned_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            cap = diagnostics.Capture('stdout', 96, Path(d)/'receipt.json')
            data = b'error: one\n  '+b'a'*200+b'\nerror: two\n  note2\nerror: three\n  note3\n'
            cap.feed(data)
            cap.finish('stdout_cap')
            value = cap.document()
            self.assertFalse(value['complete'])
            self.assertEqual(value['error_headers_observed'], 3)
            self.assertEqual(value['dropped_blocks'], 2)
            self.assertEqual(value['dropped_bytes'], len(data)-value['retained_input_bytes'])
            self.assertGreater(value['unscanned_bytes'], 0)
            self.assertLessEqual(value['retained_input_bytes'], 96)
            self.assertFalse(value['blocks'][0]['complete'])
            self.assertIn('DIAGNOSTIC_RETENTION_CAP', value['incomplete_reasons'])
            self.assertIsNone(value['unobserved_bytes'])

    def test_success_failure_spawn_signal_timeout_output_cap_and_pack(self):
        cases = [('success', 'pass', 2, 8192),
                 ('failure', "print('error: at EOF', end='');raise SystemExit(42)", 2, 8192),
                 ('spawn', None, 2, 8192),
                 ('signal', "import os,signal;print('error: before signal',flush=True);os.kill(os.getpid(),signal.SIGTERM)", 2, 8192),
                 ('timeout', "import time;print('error: before timeout',flush=True);time.sleep(2)", .15, 8192),
                 ('cap', "print('error: before cap');print('x'*40000)", 2, 1024)]
        for name, code, seconds, cap in cases:
            with self.subTest(case=name), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                argv = ['/missing/fixture'] if code is None else [sys.executable, '-c', code]
                result = runner.execute(argv, root, root, seconds, stdout_cap=cap)
                value = result['rustc_diagnostics']
                self.assertEqual(value['complete'], name in ('success', 'failure'))
                doc = json.loads((root/'rustc-stdout-receipt.json').read_text())
                if name == 'success':
                    self.assertEqual(doc['status'], 'NO_TEXTUAL_ERRORS')
                elif name != 'spawn':
                    self.assertTrue(doc['blocks'])
                if name == 'failure': self.assertEqual(result['original_exit_code'], 42)
                if name == 'signal': self.assertEqual(result['signal'], signal.SIGTERM)
                if name == 'timeout': self.assertTrue(result['timed_out'])
                if name == 'cap': self.assertTrue(result['stdout_truncated'])
                artifact = unpack(root)
                self.assertEqual(artifact['rustc_diagnostics']['.']['complete'], value['complete'])

    def test_producer_count_gap_and_suppression(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for stream in ('stdout', 'stderr'):
                cap = diagnostics.Capture(stream, 8192, root/('rustc-'+stream+'-receipt.json'))
                cap.feed(b'error[E0001]: emitted\n' if stream == 'stdout' else b'error: aborting due to 3 previous errors\nFound 3 compilation errors\n')
                cap.finish()
            value = diagnostics.summary(root)
            self.assertFalse(value['complete'])
            self.assertIn('PRODUCER_ERROR_COUNT_EXCEEDS_OBSERVED_HEADERS', value['incomplete_reasons'])
            cap.feed(b'diagnostics omitted\n')
            cap.finish()
            self.assertIn('PRODUCER_REPORTED_OMISSION', cap.document()['incomplete_reasons'])

    def test_live_fallback_and_compact_cap(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            group = root/'groups/production-u34'
            group.mkdir(parents=True)
            here = root/'control'
            here.mkdir()
            request = {'rows': [{'id': 'row', 'selector': 'fixture', 'mode': 'Original', 'variant': 'production', 'unwind': 34}], 'budgets': {'artifact_bytes': runner.ARTIFACT_CAP_BYTES}}
            (here/'CI-REQUEST.json').write_text(json.dumps(request))
            (group/'receipt.json').write_text(json.dumps({'state': 'IN_PROGRESS', 'execution': {'original_exit_code': 42}}))
            for stream in ('stdout', 'stderr'):
                cap = diagnostics.Capture(stream, 65536, group/('rustc-'+stream+'-receipt.json'))
                noise = ''.join(random.Random(17).choices('abcdef0123456789', k=20000))
                cap.feed(('error: interrupted '+noise+'\n  = note: keep\n  = help: pending').encode())
            with mock.patch.object(check_package, 'HERE', here):
                check_package.fallback(root)
            receipt = json.loads((group/'receipt.json').read_text())
            self.assertEqual(receipt['execution']['original_exit_code'], 42)
            self.assertFalse(receipt['rustc_diagnostics']['complete'])
            artifact = unpack(root)
            key = 'groups/production-u34/rustc-stdout-receipt.json'
            self.assertIn('interrupted', artifact['files'][key]['text'])
            self.assertIn('pending', artifact['files'][key]['text'])
            before = hashlib.sha256((group/'rustc-stdout-receipt.json').read_bytes()).hexdigest()
            with mock.patch.object(pack_evidence, 'COMPRESSED_CAP', 4000):
                artifact = unpack(root)
            self.assertEqual(artifact['state'], 'INCOMPLETE')
            projected = json.loads(artifact['files'][key]['text'])
            self.assertFalse(projected['complete'])
            self.assertGreater(projected['compact_omitted_text_bytes'], 0)
            self.assertEqual(projected['compact_omitted_blocks'], 1)
            self.assertIn('COMPACT_ARTIFACT_CAP', projected['incomplete_reasons'])
            self.assertFalse(artifact['rustc_diagnostics']['groups/production-u34']['complete'])
            self.assertEqual(hashlib.sha256((group/'rustc-stdout-receipt.json').read_bytes()).hexdigest(), before)

    def test_missing_null_wrong_type_not_run_and_invalid_summary(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.assertFalse(diagnostics.summary(root)['complete'])
            path = root/'rustc-stdout-receipt.json'
            for text in ('null', '[]', '42', '{', '{"state":"NOT_RUN"}',
                         '{"schema":"ch8-rustc-diagnostics-v1","stream":"stdout","complete":true}'):
                path.write_text(text)
                self.assertFalse(diagnostics.summary(root)['complete'], text)

    def test_diagnostic_capture_precedes_rich_parser_failure(self):
        class Pipe:
            def read(self, n): return b'error: before rich failure\n  = note: retained\n'
            def close(self): pass
        class BrokenRich:
            def feed(self, data): raise ValueError('fixture rich failure')
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cap = diagnostics.Capture('stdout', 4096, root/'rustc-stdout-receipt.json')
            state = {'stdout_kept': 0, 'stdout_bytes': 0, 'stdout_cap': False}
            import threading
            runner._read_pipe(Pipe(), root/'stdout.log', 4096, state, threading.Lock(), 'stdout', True, BrokenRich(), cap)
            self.assertIn('rich failure', state['stdout_reader_error'])
            self.assertIn('before rich failure', cap.document()['blocks'][0]['text'])
            self.assertFalse(cap.document()['complete'])

    def test_diagnostic_finalization_error_preserves_native_exit(self):
        original = diagnostics.Capture.persist
        def persist(capture):
            if capture.reason is None:
                raise OSError('fixture diagnostic write failure')
            return original(capture)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(diagnostics.Capture, 'persist', persist):
            root = Path(d)
            result = runner.execute([sys.executable, '-c', "print('error: original failure');raise SystemExit(42)"], root, root, 2)
            self.assertEqual(result['original_exit_code'], 42)
            self.assertIn('fixture diagnostic write failure', result['diagnostic_errors']['stdout'])
            self.assertFalse(result['rustc_diagnostics']['complete'])
            self.assertIn('DIAGNOSTIC_FINALIZATION_ERROR', result['rustc_diagnostics']['incomplete_reasons'])

    def test_reader_error_and_impossible_pack_cap(self):
        class BrokenPipe:
            count = 0
            def read(self, n):
                self.count += 1
                if self.count == 1: return b'error: received\n  = note: context\n'
                raise OSError('fixture read failure')
            def close(self): pass
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cap = diagnostics.Capture('stdout', 4096, root/'rustc-stdout-receipt.json')
            state = {'stdout_kept': 0, 'stdout_bytes': 0, 'stdout_cap': False}
            import threading
            runner._read_pipe(BrokenPipe(), root/'stdout.log', 4096, state, threading.Lock(), 'stdout', True, None, cap)
            self.assertIn('fixture read failure', state['stdout_reader_error'])
            self.assertFalse(cap.document()['complete'])
            self.assertIn('received', cap.document()['blocks'][0]['text'])
            with mock.patch.object(pack_evidence, 'UNCOMPRESSED_CAP', 100):
                with self.assertRaises(ValueError): pack_evidence.pack(root)


class ReviewRepairTests(unittest.TestCase):
    """Localized regressions for review5db34a9 B-01/P1 and B-02/P2."""
    GROUP = 's2-batch3probes-u34'

    def complete_streams(self, root):
        for stream in ('stdout', 'stderr'):
            capture = diagnostics.Capture(stream, 8192, root/('rustc-'+stream+'-receipt.json'))
            capture.finish()

    def test_b01_exact_group_fallback_cannot_inherit_complete_setup(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self.complete_streams(root/'setup')
            check_package.fallback(root, [self.GROUP])
            path = root/'groups'/self.GROUP/'receipt.json'
            before = path.read_bytes()
            artifact = unpack(root)
            self.assertTrue(artifact['rustc_diagnostics']['setup']['complete'])
            self.assertIn('groups/'+self.GROUP, artifact['rustc_diagnostics'])
            group = artifact['rustc_diagnostics']['groups/'+self.GROUP]
            self.assertFalse(group['complete'])
            self.assertEqual(group['execution_state'], 'NOT_RUN_OR_INTERRUPTED')
            self.assertIn('stdout:DIAGNOSTIC_RECEIPT_UNAVAILABLE', group['incomplete_reasons'])
            self.assertIn('stderr:DIAGNOSTIC_RECEIPT_UNAVAILABLE', group['incomplete_reasons'])
            self.assertFalse(artifact['diagnostic_retention']['complete'])
            self.assertIn('EXECUTION_STATE:NOT_RUN_OR_INTERRUPTED', artifact['diagnostic_retention']['incomplete_reasons'])
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(json.loads(before)['outcome'], 'UNKNOWN')

    def test_b01_both_main_streams_removed_at_pack_boundary(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            group = root/'groups'/self.GROUP
            self.complete_streams(root/'setup')
            self.complete_streams(group)
            summary = diagnostics.summary(group)
            value = {'state': 'FAILED', 'execution': {'original_exit_code': 42},
                     'rustc_diagnostics': summary, 'outcome': 'UNKNOWN', 'proof_credit': 'NONE'}
            (group/'receipt.json').write_text(json.dumps(value))
            (root/'receipt.json').write_text(json.dumps({'selected_groups': [self.GROUP], 'rows': []}))
            self.assertTrue(unpack(root)['diagnostic_retention']['complete'])
            for stream in ('stdout', 'stderr'):
                (group/('rustc-'+stream+'-receipt.json')).unlink()
            before = (group/'receipt.json').read_bytes()
            artifact = unpack(root)
            self.assertFalse(artifact['diagnostic_retention']['complete'])
            self.assertIn('groups/'+self.GROUP, artifact['diagnostic_retention']['expected_directories'])
            self.assertFalse(artifact['rustc_diagnostics']['groups/'+self.GROUP]['complete'])
            packed = json.loads(artifact['files']['groups/'+self.GROUP+'/receipt.json']['text'])
            self.assertEqual(packed, value)
            self.assertEqual((group/'receipt.json').read_bytes(), before)

    def test_b01_terminal_inventory_missing_group_and_execution_states(self):
        for state in ('NOT_RUN', 'INTERRUPTED', 'IN_PROGRESS', None):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as d:
                root = Path(d)
                self.complete_streams(root/'setup')
                (root/'receipt.json').write_text(json.dumps({'selected_groups': [self.GROUP], 'rows': []}))
                group = root/'groups'/self.GROUP
                if state:
                    self.complete_streams(group)
                    (group/'receipt.json').write_text(json.dumps({'state': state, 'original_exit_code': None}))
                artifact = unpack(root)
                self.assertFalse(artifact['diagnostic_retention']['complete'])
                summary = artifact['rustc_diagnostics']['groups/'+self.GROUP]
                self.assertFalse(summary['complete'])
                self.assertEqual(summary['execution_state'], state or 'RECEIPT_UNAVAILABLE')

    def test_b02_exact_review_suggestion_and_ansi_split_both_streams(self):
        fixture = (b'error[E0308]: mismatched types\n --> src/a.rs:1:1\n  |\n'
                   b'1 | let n = 42;\n  |         ^^ expected &str\nhelp: replace the value\n  |\n'
                   b'1 - let n = 42;\n1 + let n = "42";\n  |\n\n')
        self.assertEqual(len(fixture), 165)
        for stream in ('stdout', 'stderr'):
            for ansi in (False, True):
                with self.subTest(stream=stream, ansi=ansi), tempfile.TemporaryDirectory() as d:
                    root = Path(d)
                    prefix = b'noise before block\n'
                    tail = '  = note: café after suggestion\nhelp: retained after diff\n'.encode() if ansi else b''
                    block = fixture+tail
                    wire = block.replace(b'error[E0308]', b'\x1b[31merror[E0308]\x1b[0m').replace(b'1 - ', b'\x1b[31m1 - \x1b[0m').replace(b'1 + ', b'\x1b[32m1 + \x1b[0m') if ansi else block
                    for name in ('stdout', 'stderr'):
                        cap = diagnostics.Capture(name, 8192, root/('rustc-'+name+'-receipt.json'))
                        if name == stream:
                            for byte in prefix+wire:
                                cap.feed(bytes([byte]))
                        cap.finish()
                    value = json.loads((root/('rustc-'+stream+'-receipt.json')).read_text())
                    self.assertTrue(value['complete'])
                    self.assertEqual(value['dropped_bytes'], 0)
                    self.assertEqual(value['retained_input_bytes'], len(wire))
                    self.assertEqual(len(value['blocks']), 1)
                    captured = value['blocks'][0]
                    self.assertTrue(captured['complete'])
                    self.assertEqual(captured['text'], block.decode())
                    self.assertEqual(captured['start_byte'], len(prefix))
                    self.assertEqual(captured['end_byte'], len(prefix)+len(wire))
                    artifact = unpack(root)
                    packed = json.loads(artifact['files']['rustc-'+stream+'-receipt.json']['text'])
                    self.assertEqual(packed, value)
                    self.assertTrue(artifact['diagnostic_retention']['complete'])


if __name__ == '__main__':
    unittest.main()
