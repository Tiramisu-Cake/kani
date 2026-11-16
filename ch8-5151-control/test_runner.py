# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest

import runner


class ExportOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / 'source.rs'
        self.source.write_text('source')
        self.export = self.root / 'export.json'
        self.row = {'harness': 'read_in_drop_of_uninit_slot'}
        self.run = {'timed_out': False, 'exit_code': 0, 'stdout_truncated': False,
                    'stderr_truncated': False, 'stdout_excerpt': '', 'stderr_excerpt': '',
                    'cwd': str(self.root)}
        self.value = {'schema_version': '0.1.0', 'run_state': 'COMPLETE',
            'kani_commit': runner.PINS['prototype']['sha'], 'kani_commit_dirty': False,
            'harness_selection': {'requested_filters': ['read_in_drop_of_uninit_slot'], 'exact': True,
                                  'unmatched_filters': [], 'matched_count': 1},
            'harnesses': [{'name': 'read_in_drop_of_uninit_slot', 'file': str(self.source),
                'outcome': {'kind': 'COMPLETED', 'verdict': 'SUCCESS'},
                'checks': {'total': 1, 'success': 1, 'failure': [], 'unreachable': [], 'undetermined': [],
                           'error': [], 'unknown': [], 'other': []},
                'covers': {'total': 0, 'satisfied': []}, 'n_failed': 0, 'n_properties': 1,
                'failure_kind': 'NONE', 'failed_properties': [], 'unsupported_constructs': []}],
            'summary': {'total': 1, 'successful': 1, 'failed': 0, 'checks_total': 1,
                        'checks_success': 1, 'covers_total': 0, 'covers_satisfied': 0}}

    def tearDown(self): self.temp.cleanup()

    def parse(self):
        return runner.status_from_export(self.export, self.row, self.source, self.run, 'prototype')

    def test_success(self):
        self.export.write_text(json.dumps(self.value))
        self.assertEqual(self.parse()['outcome'], 'SUCCESS')

    def test_structural_uninit_failure(self):
        self._make_failure_export()
        self.run['exit_code'] = 1
        self.export.write_text(json.dumps(self.value))
        self.assertEqual(self.parse()['outcome'], 'UNINIT_FAILURE')

    def _make_failure_export(self):
        prop = {'id': 'read_in_drop_of_uninit_slot::read_volatile.safety_check', 'status': 'FAILURE', 'class': 'safety_check',
                'description': 'Undefined Behavior: Reading from an uninitialized pointer of type `u8`'}
        self.value['harnesses'][0]['outcome']['verdict'] = 'FAILURE'
        self.value['harnesses'][0]['checks'] = {'total': 1, 'success': 0, 'failure': [prop['id']],
            'unreachable': [], 'undetermined': [], 'error': [], 'unknown': [], 'other': []}
        self.value['harnesses'][0]['failed_properties'] = [prop]
        self.value['harnesses'][0]['n_failed'] = 1
        self.value['harnesses'][0]['failure_kind'] = 'SAFETY_CHECK'
        self.value['summary'].update(successful=0, failed=1, checks_success=0)
        self.value['harnesses'][0]['covers'] = {'total': 0, 'satisfied': []}

    def test_negative_exit_with_complete_failure_export_is_unknown(self):
        self._make_failure_export()
        self.run['exit_code'] = -signal.SIGTERM
        self.export.write_text(json.dumps(self.value))
        self.assertEqual(self.parse()['outcome'], 'UNKNOWN')

    def test_timeout_is_unknown(self):
        self.run['timed_out'] = True
        self.assertEqual(self.parse()['state'], 'EXECUTION_INCOMPLETE')

    def test_exact_stock_unsupported_diagnostic(self):
        self.run['exit_code'] = 1
        self.run['stderr_excerpt'] = runner.STOCK_UNSUPPORTED_DIAGNOSTIC
        observed = runner.status_from_export(self.export, self.row, self.source, self.run, 'stock')
        self.assertEqual(observed['outcome'], 'UNSUPPORTED_UNION')

    def test_arbitrary_stock_error_is_unknown(self):
        self.run['exit_code'] = 1
        self.run['stderr_excerpt'] = 'compiler failed for another reason'
        observed = runner.status_from_export(self.export, self.row, self.source, self.run, 'stock')
        self.assertEqual(observed['outcome'], 'UNKNOWN')

    def test_mixed_stock_diagnostic_and_fatal_error_is_unknown(self):
        self.run['exit_code'] = 1
        self.run['stderr_excerpt'] = runner.STOCK_UNSUPPORTED_DIAGNOSTIC + '\nerror: unrelated compiler error'
        observed = runner.status_from_export(self.export, self.row, self.source, self.run, 'stock')
        self.assertEqual(observed['outcome'], 'UNKNOWN')

    def test_partial_export_is_unknown(self):
        self.export.write_text('{"schema_version":')
        self.assertEqual(self.parse()['state'], 'EXPORT_INVALID_OR_PARTIAL')

    def test_missing_export_is_unknown(self):
        self.assertEqual(self.parse()['state'], 'EXPORT_MISSING')

    def test_null_export_is_unknown(self):
        self.export.write_text('null')
        self.assertEqual(self.parse()['state'], 'EXPORT_WRONG_TYPE')

    def test_wrong_top_level_type_is_unknown(self):
        self.export.write_text('[]')
        self.assertEqual(self.parse()['state'], 'EXPORT_WRONG_TYPE')

    def test_never_started_row_is_not_run(self):
        report = self.root / 'fallback'
        import subprocess
        result = subprocess.run([__import__('sys').executable, str(runner.CONTROL / 'runner.py'), 'fallback', '--out', str(report)])
        self.assertEqual(result.returncode, 0)
        rows = json.loads((report / 'fallback.json').read_text())['rows']
        self.assertTrue(all(x['status'] == 'NOT_RUN' and x['outcome'] == 'UNKNOWN' for x in rows))

    def test_source_target_mismatch_is_unknown(self):
        self.value['harnesses'][0]['file'] = str(self.root / 'elsewhere.rs')
        self.export.write_text(json.dumps(self.value))
        self.assertEqual(self.parse()['state'], 'SOURCE_STAGE_TARGET_MISMATCH')


class BoundedRunTests(unittest.TestCase):
    def setUp(self): self.temp = tempfile.TemporaryDirectory()
    def tearDown(self): self.temp.cleanup()

    def test_spawn_error_is_receipted(self):
        out = Path(self.temp.name) / 'missing-command'
        record = runner.bounded_run([str(Path(self.temp.name) / 'does-not-exist')], Path(self.temp.name), out, 1)
        self.assertIsNone(record['original_exit_code'])
        self.assertIn('FileNotFoundError', record['runner_error'])

    @unittest.skipUnless(Path('/proc').is_dir(), 'process-group check requires Linux /proc')
    def test_timeout_kills_descendant_that_ignores_sigterm(self):
        root = Path(self.temp.name)
        pid_file = root / 'child.pid'
        child = "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
        parent = ("import subprocess,sys,time; "
                  f"p=subprocess.Popen([sys.executable,'-c',{child!r}]); "
                  f"open({str(pid_file)!r},'w').write(str(p.pid)); time.sleep(60)")
        record = runner.bounded_run([sys.executable, '-c', parent], root, root / 'timeout', .5)
        self.assertTrue(record['timed_out'])
        child_pid = int(pid_file.read_text())
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            stat = Path(f'/proc/{child_pid}/stat')
            if not stat.exists(): break
            try: state = stat.read_text().split(')')[-1].split()[0]
            except OSError: break
            if state == 'Z': break
            time.sleep(.05)
        else: self.fail('SIGTERM-ignoring descendant remained alive after bounded timeout')


if __name__ == '__main__': unittest.main()
