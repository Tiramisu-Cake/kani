#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Exercise the actual A shell runner with isolated Python command substitutes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from finalize_arm_a import GATES, finalize

HERE = Path(__file__).resolve().parent
STUB = '''#!{python}
import json, os, sys
name = os.path.basename(sys.argv[0])
if name == 'cargo':
    gate = {{'build-dev': 'build', 'clippy': 'clippy', 'test': 'compiler-units',
             'build': 'compiletest-build'}}[sys.argv[1]]
elif name == 'compiletest':
    suite = sys.argv[sys.argv.index('--suite') + 1]
    gate = suite + '-' + sys.argv[-1].replace('/', '_')
elif name == 'run_old_control.py':
    gate = 'old-controls'
else:
    gate = 'fmt'
print(gate)
sys.exit(json.loads(os.environ['FAKE_FAILURES']).get(gate, 0))
'''


class GateTests(unittest.TestCase):
    def run_scenario(self, failures, missing_compiletest=False):
        with tempfile.TemporaryDirectory(prefix='ch8-a-gates-') as tmp:
            root = Path(tmp)
            repo, control = root / 'source', root / 'control'
            scripts = control / 'scripts/ch8-pr02-reset'
            scripts.mkdir(parents=True)
            shutil.copy2(HERE / 'bounded_step.py', scripts / 'bounded_step.py')
            for path in (repo / 'scripts/kani-fmt.sh', root / 'bin/cargo',
                         scripts / 'run_old_control.py', repo / 'target/debug/compiletest'):
                path.parent.mkdir(parents=True, exist_ok=True)
                if missing_compiletest and path.name == 'compiletest':
                    continue
                path.write_text(STUB.format(python=sys.executable))
                path.chmod(0o755)
            env = {**os.environ, 'CONTROL_DIR': str(control), 'OLD_DIR': str(root / 'old'),
                   'RUNNER_TEMP': str(root), 'FAKE_FAILURES': json.dumps(failures),
                   'PATH': str(root / 'bin') + os.pathsep + os.environ['PATH']}
            result = subprocess.run(['bash', str(HERE / 'run_arm_a.sh'), str(repo)],
                                    env=env, text=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=30)
            out = root / 'ch8-pr02-reset-a'
            receipts = {p.stem: json.loads(p.read_text()) for p in out.glob('*.json')}
            expected = set(GATES[1:]) if not failures.get('build') else {'fmt', 'build'}
            self.assertEqual(set(receipts), expected, result.stdout)
            for gate, receipt in receipts.items():
                if missing_compiletest and gate.startswith(('expected-', 'script-based-')):
                    self.assertEqual(receipt['status'], 'ERROR')
                    self.assertIsNone(receipt['exit_code'])
                else:
                    self.assertEqual(receipt['status'], 'COMPLETED')
                    self.assertEqual(receipt['exit_code'], failures.get(gate, 0))
            self.assertEqual(result.returncode, int(bool(failures) or missing_compiletest), result.stdout)
            request = {'pins': {'pr02': {}}, 'patch': {}, 'expected_target': 'synthetic'}
            finalize(out, request, {}, 'failure' if result.returncode else 'success', {})
            final = json.loads((out / 'result.json').read_text())
            self.assertEqual(final['gates'][0]['status'], 'NOT_RUN')
            if failures.get('build'):
                self.assertTrue(all(g['status'] == 'NOT_RUN' for g in final['gates'][3:]))

    def test_success_and_each_failed_gate(self):
        self.run_scenario({})
        for gate in GATES[1:]:
            with self.subTest(gate=gate):
                self.run_scenario({gate: 37})

    def test_multiple_failures_and_missing_executable(self):
        self.run_scenario({'fmt': 2, 'script-based-pre-autoharness_entry_reset_': 101,
                           'old-controls': 41})
        self.run_scenario({}, missing_compiletest=True)


if __name__ == '__main__':
    unittest.main(verbosity=2)
