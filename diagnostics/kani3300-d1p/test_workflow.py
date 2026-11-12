#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""YAML fixture tests and shell syntax only; never execute workflow commands."""
from pathlib import Path
import subprocess
import unittest
import yaml

WORKFLOW=Path(__file__).resolve().parents[2]/'.github/workflows/kani3300-d1p.yml'


def validate(wf):
    if set(wf.get('on',{}))!={'workflow_dispatch'}:
        raise ValueError('manual trigger only')
    if wf['concurrency']['cancel-in-progress'] is not False:
        raise ValueError('no cancellation/retry')
    jobs=wf['jobs']
    if set(jobs)!={'r1-skip','r6b'} or jobs['r6b'].get('needs')!='r1-skip':
        raise ValueError('sequential pins')
    for name,job in jobs.items():
        if 'strategy' in job or job['permissions']!={'contents':'read'}:
            raise ValueError('no matrix/write permission')
        steps=job['steps']
        ids={s.get('id'):s for s in steps if s.get('id')}
        if ids['upload']['if']!='${{ always() }}' or ids['manifest']['if']!='${{ always() }}':
            raise ValueError('always upload')
        if any(s.get('continue-on-error') for s in steps):
            raise ValueError('visible failures required')
        if ids['upload']['with']['if-no-files-found']!='error':
            raise ValueError('missing artifact must fail')
        for step in steps:
            if 'run' in step:
                checked=subprocess.run(['bash','-n'],input=step['run'],text=True,capture_output=True)
                if checked.returncode:
                    raise ValueError('shell syntax: '+checked.stderr)


class WorkflowTests(unittest.TestCase):
    def fixture(self):
        return yaml.safe_load(WORKFLOW.read_text())
    def test_current_and_shell_syntax(self):
        validate(self.fixture())
    def test_push_rejected(self):
        value=self.fixture();value['on']['push']={}
        with self.assertRaisesRegex(ValueError,'manual'): validate(value)
    def test_parallel_rejected(self):
        value=self.fixture();value['jobs']['r6b'].pop('needs')
        with self.assertRaisesRegex(ValueError,'sequential'): validate(value)
    def test_hidden_failure_rejected(self):
        value=self.fixture();value['jobs']['r1-skip']['steps'][4]['continue-on-error']=True
        with self.assertRaisesRegex(ValueError,'visible'): validate(value)
    def test_upload_condition_rejected(self):
        value=self.fixture();value['jobs']['r1-skip']['steps'][6]['if']='${{ success() }}'
        with self.assertRaisesRegex(ValueError,'always'): validate(value)


if __name__=='__main__': unittest.main()
