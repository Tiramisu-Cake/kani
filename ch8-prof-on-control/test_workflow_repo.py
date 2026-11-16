# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Offline checkout-path regressions; never execute workflow commands."""
import copy
from pathlib import Path
import tempfile
import unittest

import yaml

import check_package
from workflow_repo import check_control_repo_paths


class WorkflowRepoTests(unittest.TestCase):
    def setUp(self):
        self.path = Path(__file__).resolve().parent.parent/'.github/workflows/ch8-prof-on.yml'
        self.doc = yaml.load(self.path.read_text(), Loader=yaml.BaseLoader)
        self.steps = self.doc['jobs']['profiles']['steps']
        self.step = next(s for s in self.steps if s.get('name') == 'Validate control and synthetic wrapper')

    def test_actual_workflow_and_old_failure(self):
        self.assertEqual(check_package.check_yaml(self.path)['control_repo_paths'][0]['repo'], '..')
        self.step['run'] = self.step['run'].replace('--repo ..', '--repo ../..')
        with self.assertRaisesRegex(AssertionError, '--repo resolves'):
            check_control_repo_paths(self.doc)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'old.yml'
            path.write_text(yaml.dump(self.doc))
            with self.assertRaisesRegex(AssertionError, '--repo resolves'):
                check_package.check_yaml(path)

    def test_different_control_names_and_depths(self):
        for directory in ('ch8-s1-control', 'scripts/ch8-b-control', 'ch8-c-control', 'ch8-e-control'):
            with self.subTest(directory=directory):
                self.step['working-directory'] = 'control/'+directory
                self.step['run'] = 'python3 check_package.py control --repo '+('/'.join(['..']*(directory.count('/')+1)))
                self.assertEqual(check_control_repo_paths(self.doc)[0]['resolved_checkout'], 'control')

    def test_workflow_job_and_step_working_directory_precedence(self):
        cwd = self.step.pop('working-directory')
        self.doc['defaults'] = {'run': {'working-directory': cwd}}
        self.assertEqual(check_control_repo_paths(self.doc)[0]['working_directory'], cwd)
        self.doc['jobs']['profiles']['defaults'] = {'run': {'working-directory': 'wrong'}}
        with self.assertRaises(AssertionError):
            check_control_repo_paths(self.doc)
        self.step['working-directory'] = cwd
        check_control_repo_paths(self.doc)

    def test_repo_equals_and_line_continuation(self):
        self.step['run'] = 'python3 check_package.py control ' + '\\' + '\n --repo=..'
        self.assertEqual(check_control_repo_paths(self.doc)[0]['repo'], '..')

    def test_wrong_or_unresolved_paths_rejected(self):
        for repo in ('.', '../..', '../../tool', '/control', '$ROOT', '${{ github.workspace }}', 'null'):
            with self.subTest(repo=repo):
                self.step['run'] = 'python3 check_package.py control --repo '+repo
                with self.assertRaises((AssertionError, SystemExit)):
                    check_control_repo_paths(self.doc)

    def test_missing_null_wrong_type_and_not_run_command(self):
        for command in ('', 'python3 check_package.py control', 'python3 check_package.py control --repo',
                        'python3 check_package.py control --repo .. --repo ../..', None, [],
                        'echo NOT_RUN # check_package.py control --repo ..'):
            with self.subTest(command=command):
                self.step['run'] = command
                with self.assertRaises((AssertionError, SystemExit)):
                    check_control_repo_paths(self.doc)

    def test_missing_wrong_late_or_duplicate_checkout(self):
        for mutation in ('missing', 'wrong', 'late', 'duplicate'):
            self.setUp()
            checkout = next(s for s in self.steps if s.get('uses', '').startswith('actions/checkout@'))
            if mutation == 'missing': self.steps.remove(checkout)
            if mutation == 'wrong': checkout['with']['path'] = 'tool'
            if mutation == 'late': self.steps.remove(checkout); self.steps.append(checkout)
            if mutation == 'duplicate': self.steps.insert(1, copy.deepcopy(checkout))
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                check_control_repo_paths(self.doc)

    def test_every_explicit_control_step_is_checked(self):
        extra = copy.deepcopy(self.step)
        extra['run'] = extra['run'].replace('--repo ..', '--repo ../..')
        self.steps.append(extra)
        with self.assertRaises(AssertionError):
            check_control_repo_paths(self.doc)


if __name__ == '__main__':
    unittest.main()
