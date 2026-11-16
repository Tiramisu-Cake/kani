# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Offline dual-lane checkout-path regressions; never execute workflow commands."""
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
        self.on_steps = self.doc['jobs']['profiles-on']['steps']
        self.off_steps = self.doc['jobs']['profiles-off']['steps']
        self.step = next(s for s in self.on_steps if s.get('name') == 'Validate control and synthetic wrappers')

    def test_actual_workflow_and_bad_control_root(self):
        checked = check_package.check_yaml(self.path)['control_repo_paths']
        self.assertEqual(len(checked), 2)
        self.assertEqual([entry['repo'] for entry in checked], ['control', 'control'])
        self.step['run'] = self.step['run'].replace('--repo control', '--repo wrong', 1)
        with self.assertRaisesRegex(AssertionError, '--repo resolves'):
            check_control_repo_paths(self.doc)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'bad.yml'
            path.write_text(yaml.dump(self.doc))
            with self.assertRaisesRegex(AssertionError, '--repo resolves'):
                check_package.check_yaml(path)

    def test_different_control_names_and_depths(self):
        for directory in ('ch8-s1-control', 'scripts/ch8-b-control', 'ch8-c-control', 'ch8-e-control'):
            with self.subTest(directory=directory):
                self.setUp()
                self.step['working-directory'] = 'control/'+directory
                repo = '/'.join(['..']*(directory.count('/')+1))
                self.step['run'] = 'python3 check_package.py control --repo '+repo
                result = check_control_repo_paths(self.doc)
                self.assertEqual(result[0]['resolved_checkout'], 'control')

    def test_job_and_step_working_directory_precedence(self):
        cwd = self.step.pop('working-directory', '.')
        self.doc['defaults'] = {'run': {'working-directory': cwd}}
        self.assertEqual(len(check_control_repo_paths(self.doc)), 2)
        self.doc['jobs']['profiles-on']['defaults'] = {'run': {'working-directory': 'wrong'}}
        with self.assertRaises(AssertionError):
            check_control_repo_paths(self.doc)
        self.step['working-directory'] = cwd
        self.assertEqual(len(check_control_repo_paths(self.doc)), 2)

    def test_repo_equals_and_line_continuation(self):
        self.step['run'] = 'python3 check_package.py control \\\n --repo=control'
        self.assertEqual(check_control_repo_paths(self.doc)[0]['repo'], 'control')

    def test_wrong_or_unresolved_paths_rejected(self):
        for repo in ('.', '../..', '../../tool', '/control', '$ROOT', '${{ github.workspace }}', 'null'):
            with self.subTest(repo=repo):
                self.setUp()
                self.step['run'] = 'python3 check_package.py control --repo '+repo
                with self.assertRaises((AssertionError, SystemExit)):
                    check_control_repo_paths(self.doc)

    def test_no_implicit_root_claim(self):
        for job_id in ('profiles-on', 'profiles-off'):
            step = next(s for s in self.doc['jobs'][job_id]['steps'] if s.get('name') == 'Validate control and synthetic wrappers')
            step['run'] = 'python3 check_package.py control'
        with self.assertRaisesRegex(AssertionError, 'no explicit control --repo'):
            check_control_repo_paths(self.doc)

    def test_missing_null_wrong_type_and_not_run_command(self):
        for command in ('', 'python3 check_package.py control', 'python3 check_package.py control --repo',
                        'python3 check_package.py control --repo control --repo wrong', None, [],
                        'echo NOT_RUN # check_package.py control --repo control'):
            with self.subTest(command=command):
                self.setUp()
                off_step = next(s for s in self.off_steps if s.get('name') == 'Validate control and synthetic wrappers')
                self.step['run'] = command
                off_step['run'] = command
                with self.assertRaises((AssertionError, SystemExit)):
                    check_control_repo_paths(self.doc)

    def test_missing_wrong_late_or_duplicate_checkout(self):
        for mutation in ('missing', 'wrong', 'late', 'duplicate'):
            self.setUp()
            checkout = next(s for s in self.on_steps if s.get('uses', '').startswith('actions/checkout@'))
            if mutation == 'missing': self.on_steps.remove(checkout)
            if mutation == 'wrong': checkout['with']['path'] = 'tool'
            if mutation == 'late': self.on_steps.remove(checkout); self.on_steps.append(checkout)
            if mutation == 'duplicate': self.on_steps.insert(1, copy.deepcopy(checkout))
            with self.subTest(mutation=mutation), self.assertRaises(AssertionError):
                check_control_repo_paths(self.doc)

    def test_every_explicit_control_step_is_checked(self):
        extra = copy.deepcopy(self.step)
        extra['run'] = extra['run'].replace('--repo control', '--repo wrong')
        self.on_steps.append(extra)
        with self.assertRaises(AssertionError):
            check_control_repo_paths(self.doc)


if __name__ == '__main__':
    unittest.main()
