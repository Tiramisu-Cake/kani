#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Isolated receipt/error-path tests using Python children only."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

from bounded_step import run_gate, TAIL_BYTES
from finalize_arm_a import finalize


class ReceiptTests(unittest.TestCase):
    def test_success_failure_exception_timeout_and_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            for gate, command, expected, status in (
                ('success', 'print("success")', 0, 'COMPLETED'),
                ('failure', 'raise SystemExit(37)', 37, 'COMPLETED'),
                ('timeout', 'import time; time.sleep(10)', 124, 'TIMEOUT'),
                ('bounded', f'import os; os.write(1, b"x" * {TAIL_BYTES + 100})', 0, 'COMPLETED'),
            ):
                self.assertEqual(run_gate([sys.executable, '-c', command], out, out, gate,
                                          timeout=0.1 if gate == 'timeout' else 10), expected)
                receipt = json.loads((out / f'{gate}.json').read_text())
                self.assertEqual(receipt['status'], status)
                self.assertLessEqual((out / f'{gate}.tail.txt').stat().st_size, TAIL_BYTES)
                if gate == 'timeout':
                    self.assertEqual(receipt['exit_code'], -9)
                else:
                    self.assertEqual(receipt['exit_code'], expected)
            self.assertEqual(run_gate(['/no/such/receipt-test-command'], out, out, 'missing'), 1)
            self.assertEqual(json.loads((out / 'missing.json').read_text())['status'], 'ERROR')

    def test_setup_failure_missing_partial_and_no_false_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            (out / 'old-build.json').write_text(json.dumps({'gate': 'old-build',
                'status': 'IN_PROGRESS', 'exit_code': None}))
            req = {'pins': {'pr02': {'sha': 'src', 'patched_tree': 'tree'}},
                   'patch': {'sha256': 'patch'}, 'expected_target': 'target'}
            finalize(out, req, {'setup': {'outcome': 'failure'}}, 'failure', {'GITHUB_SHA': 'trigger'})
            result = json.loads((out / 'result.json').read_text())
            self.assertEqual(result['gates'][0]['status'], 'IN_PROGRESS')
            self.assertTrue(all(g['status'] == 'NOT_RUN' for g in result['gates'][1:]))
            self.assertEqual(result['steps']['setup']['outcome'], 'failure')
            self.assertEqual(result['proof_credit'], 'NONE')
            self.assertEqual(result['source_pin']['sha'], 'src')
            # Malformed/null/wrong-type receipts remain errors, never successes.
            for raw in ('{', 'null', '"wrong"',
                        '{"gate":"other","status":"COMPLETED","exit_code":0}',
                        '{"gate":"old-build","status":"COMPLETED","exit_code":true}'):
                (out / 'old-build.json').write_text(raw)
                finalize(out, req, {}, 'failure', {})
                self.assertEqual(json.loads((out / 'result.json').read_text())['gates'][0]['status'],
                                 'MALFORMED')


if __name__ == '__main__':
    unittest.main(verbosity=2)
