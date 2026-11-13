"""Isolated Python service checks. No Rust/Kani/CBMC is executed."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('replay', Path(__file__).with_name('replay.py'))
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def finished(exit=0):
    return dict(status='FINISHED', exit=exit, complete=True, timeout=False,
                overflow=False, exception=None)


def backend(exit=0, output=''):
    return dict(finished(exit), argv=['/binary', 'input.goto', '--json-ui'],
                binary_sha256='expected', output=output)


class ReplayTests(unittest.TestCase):
    def test_inputs_and_verbatim_issue(self):
        r.check_inputs()

    def test_success(self):
        self.assertEqual(r.classify(finished(), 'VERIFICATION:- SUCCESSFUL\n',
                                    [backend()], 'expected'), 'VERIFIED')

    def test_failures_are_distinct(self):
        invariant = ('--- begin invariant violation report ---\nInvariant check failed\n'
                     'File: simplify_utils.cpp function: bits2expr\n'
                     'Condition: el_size_opt.has_value() && *el_size_opt > 0\nReason: Check return value\n')
        self.assertEqual(r.classify(finished(1), invariant, [backend(-6, invariant)], 'expected'),
                         'BITS2EXPR_ARRAY_INVARIANT')
        self.assertEqual(r.invariant_blocks(invariant), [invariant])
        self.assertEqual(r.classify(finished(1), 'failed', [backend(10)], 'expected'), 'OTHER_FAILURE')
        self.assertEqual(r.classify(finished(1), 'compiler panic', [], 'expected'),
                         'NO_CBMC_MODEL_INVOCATION')
        self.assertEqual(r.classify(finished(), 'VERIFICATION:- SUCCESSFUL',
                                    [dict(backend(), argv=['/binary', '--version'])], 'expected'),
                         'NO_CBMC_MODEL_INVOCATION')

    def test_missing_null_wrong_type_partial_and_not_run(self):
        for bad in [None, {}, {'status': 'NOT_RUN'}, dict(finished(), exit=None),
                    dict(finished(), exit='0'), dict(finished(), exit=False),
                    dict(finished(), complete=False), dict(finished(), timeout=True),
                    dict(finished(), overflow=True), dict(finished(), exception={'type': 'OSError'})]:
            self.assertEqual(r.classify(bad, 'VERIFICATION:- SUCCESSFUL', [backend()], 'expected'),
                             'INCOMPLETE_OR_SETUP_ERROR')
        for bad in [dict(backend(), binary_sha256='other'), dict(backend(), complete=False),
                    dict(backend(), exit=None)]:
            self.assertEqual(r.classify(finished(), 'VERIFICATION:- SUCCESSFUL', [bad], 'expected'),
                             'CBMC_IDENTITY_OR_CAPTURE_ERROR')
        self.assertEqual(r.classify(finished(), 'VERIFICATION:- SUCCESSFUL',
                                    [dict(backend(), argv=None)], 'expected'), 'NO_CBMC_MODEL_INVOCATION')

    def test_capture_original_exit_signal_and_missing_executable(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp) / 'result'
            out = r.capture([sys.executable, '-c', 'print("ok")'], temp, prefix, 5)
            self.assertTrue(r.sound_capture(out))
            self.assertEqual(out['exit'], 0)
            self.assertIn('ok', r.text_logs(prefix))
            out = r.capture([sys.executable, '-c', 'raise SystemExit(7)'], temp, prefix, 5)
            self.assertEqual(out['exit'], 7)
            out = r.capture([sys.executable, '-c', 'import os,signal; os.kill(os.getpid(),signal.SIGTERM)'],
                            temp, prefix, 5)
            self.assertEqual((out['exit'], out['signal']), (-15, 15))
            out = r.capture(['/missing/kani5085-tool'], temp, prefix, 5)
            self.assertEqual(out['exception']['type'], 'FileNotFoundError')
            self.assertIsNone(out['exit'])

    def test_timeout_and_bounded_drain(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp) / 'result'
            out = r.capture([sys.executable, '-c', 'import time; time.sleep(10)'], temp, prefix, .1)
            self.assertTrue(out['timeout'])
            self.assertFalse(r.sound_capture(out))
            cap = r.CAP
            try:
                r.CAP = 1024
                out = r.capture([sys.executable, '-c', 'import sys; sys.stdout.write("x"*200000)'],
                                temp, prefix, 5)
            finally:
                r.CAP = cap
            self.assertTrue(out['overflow'])
            self.assertEqual(out['exit'], 0)
            self.assertEqual(out['raw_bytes'], 200000)
            self.assertEqual(out['retained_bytes'], 1024)

    def test_not_run_snapshot(self):
        with tempfile.TemporaryDirectory() as temp:
            r.init(temp)
            result = json.loads((Path(temp) / 'RESULT.json').read_text())
            self.assertEqual(len(result['cases']), 10)
            self.assertTrue(all(row['verdict'] == 'NOT_RUN' for row in result['cases']))

    def test_proxy_preserves_bytes_and_underlying_exit(self):
        # An executable Python fixture stands in for a backend; never a verifier.
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            fake = temp / 'fake'
            fake.write_text('#!' + sys.executable + '\nimport sys\n'
                            'sys.stdout.write("[1,2,3]\\n")\n'
                            'sys.stderr.write("stderr-marker\\n")\nraise SystemExit(7)\n')
            fake.chmod(0o755)
            env = dict(os.environ, K5085_BINARY=str(fake), K5085_CASE=str(temp))
            proc = subprocess.run([sys.executable, str(r.HERE / 'replay.py'), 'proxy', '--json-ui'],
                                  env=env, capture_output=True, timeout=10)
            self.assertEqual(proc.returncode, 7)
            self.assertEqual(proc.stdout, b'[1,2,3]\n')
            self.assertEqual(proc.stderr, b'stderr-marker\n')
            rows = list(temp.glob('cbmc-*.json'))
            self.assertEqual(len(rows), 1)
            row = json.loads(rows[0].read_text())
            self.assertEqual(row['exit'], 7)
            self.assertEqual(row['binary_sha256'], r.sha(fake))
            self.assertEqual(row['argv'], [str(fake), '--json-ui'])


if __name__ == '__main__':
    unittest.main()
