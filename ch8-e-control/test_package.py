"""Synthetic package guards; never launches Rust or a verifier."""
import copy
import os
from unittest.mock import patch
from pathlib import Path
import tempfile
import unittest
import yaml
import check_package as c


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.doc = yaml.load((c.ROOT/'.github/workflows/ch8-e.yml').read_text(), Loader=yaml.BaseLoader)

    def check(self, doc):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'workflow.yml'
            p.write_text(yaml.dump(doc, sort_keys=False))
            return c.yaml_check(p)

    def test_good(self):
        self.assertEqual(self.check(self.doc)['yaml'], 'PASS')

    def test_bad_variants(self):
        for kind in ('runner_job', 'runner_non_env_step', 'depth', 'pin', 'attempt_host', 'trigger', 'target', 'parallel', 'missing_companion'):
            d = copy.deepcopy(self.doc)
            job = d['jobs']['controls']
            if kind == 'runner_job': job['env'] = {'BAD': '${{ runner.temp }}'}
            elif kind == 'runner_non_env_step': job['steps'][0]['working-directory'] = '${{ runner.temp }}'
            elif kind == 'depth': job['steps'][0]['with']['fetch-depth'] = '1'
            elif kind == 'pin': job['strategy']['matrix']['include'][1]['sha'] = 'HEAD'
            elif kind == 'attempt_host': job['if'] = 'true'
            elif kind == 'trigger': d['on']['workflow_dispatch'] = {}
            elif kind == 'target': job['steps'][-1]['with']['path'] = '${{ env.RECEIPT_ROOT }}/'
            elif kind == 'parallel': job['strategy']['max-parallel'] = '2'
            elif kind == 'missing_companion': job['strategy']['matrix']['include'].pop()
            with self.subTest(kind=kind), self.assertRaises(AssertionError): self.check(d)

    def test_runtime_control_identity_guards(self):
        sha = '1'*40
        env = {'GITHUB_REPOSITORY': 'Tiramisu-Cake/kani', 'GITHUB_EVENT_NAME': 'push',
               'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_REF': 'refs/heads/uninit-ci/ch8-e-ctl-test',
               'GITHUB_SHA': sha}
        parent = c.PINS['upstream']['sha']
        good = {('rev-parse', 'HEAD'): sha,
                ('rev-list', '--parents', '-n', '1', 'HEAD'): sha+' '+parent,
                ('status', '--porcelain=v1', '--untracked-files=no'): '',
                ('diff', '--name-only', 'HEAD^', 'HEAD'): 'ch8-e-control/runner.py',
                ('ls-tree', '-r', '--name-only', 'HEAD', '.github/workflows'): '.github/workflows/ch8-e.yml'}
        cases = ['good', 'attempt', 'repository', 'event', 'branch', 'sha', 'parent', 'merge', 'dirty', 'scope', 'stock']
        with tempfile.TemporaryDirectory() as td:
            for kind in cases:
                e, g = env.copy(), good.copy()
                if kind == 'attempt': e['GITHUB_RUN_ATTEMPT'] = '2'
                elif kind == 'repository': e['GITHUB_REPOSITORY'] = 'model-checking/kani'
                elif kind == 'event': e['GITHUB_EVENT_NAME'] = 'workflow_dispatch'
                elif kind == 'branch': e['GITHUB_REF'] = 'refs/heads/main'
                elif kind == 'sha': g[('rev-parse', 'HEAD')] = '2'*40
                elif kind == 'parent': g[('rev-list', '--parents', '-n', '1', 'HEAD')] = sha+' '+'2'*40
                elif kind == 'merge': g[('rev-list', '--parents', '-n', '1', 'HEAD')] += ' '+'3'*40
                elif kind == 'dirty': g[('status', '--porcelain=v1', '--untracked-files=no')] = ' M runner.py'
                elif kind == 'scope': g[('diff', '--name-only', 'HEAD^', 'HEAD')] = 'library/kani/src/arbitrary.rs'
                elif kind == 'stock': g[('ls-tree', '-r', '--name-only', 'HEAD', '.github/workflows')] += '\n.github/workflows/kani.yml'
                with self.subTest(kind=kind), patch.dict(os.environ, e, clear=True), patch.object(c, 'ROOT', Path(td)/'control'), patch.object(c, 'static_check', return_value={}), patch.object(c, 'git', side_effect=lambda *args: g[args]):
                    if kind == 'good': self.assertEqual(c.control_check()['control_sha'], sha)
                    else:
                        with self.assertRaises(AssertionError): c.control_check()


if __name__ == '__main__': unittest.main()
