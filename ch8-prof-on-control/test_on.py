# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""ON guards with synthetic data only; never executes a compiler/verifier."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

import runner
import check_package
from test_runner import export, row


class OnTests(unittest.TestCase):
    def test_all_rows_receive_on_without_changing_cfg_or_bounds(self):
        request = runner.load_request()
        for group in runner.batch_groups(request['rows']):
            argv = runner.build_argv(Path('/std'), Path('/tool'),
                                     [r['selector'] for r in group], None, Path('/out/export.json'))
            features = [argv[i+1] for i, a in enumerate(argv[:-1]) if a == '-Z']
            self.assertEqual(features.count('uninit-checks'), 1)
            self.assertNotIn('valid-value-checks', features)
            self.assertNotIn('--default-unwind', argv)
            self.assertIn('--output-format=regular', argv)
            self.assertEqual(argv[-3:], ['--cbmc-args', '--object-bits', '12'])
            self.assertEqual(argv.count('--harness'), len(group))

    def test_export_requires_on_and_refuses_validity_and_stock(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'export.json'
            good = export()
            p.write_text(json.dumps(good))
            self.assertEqual(runner.parse_export(p, row())['outcome'], 'EXPECTED')
            for features in (None, {}, [], [None],
                             [f for f in good['enabled_unstable_features'] if f != 'uninit-checks'],
                             good['enabled_unstable_features'] + ['valid-value-checks'],
                             good['enabled_unstable_features'] + ['unexpected-feature'],
                             good['enabled_unstable_features'] + ['ghost-state'],
                             good['enabled_unstable_features'] + ['uninit-checks'],
                             [f for f in good['enabled_unstable_features'] if f != 'unstable-options']):
                bad = copy.deepcopy(good); bad['enabled_unstable_features'] = features
                p.write_text(json.dumps(bad))
                self.assertEqual(runner.parse_export(p, row())['state'], 'WRONG_UNSTABLE_FEATURE_SET')
            good['kani_commit'] = '0aac16ef62da9e9d5645782d458593e5d78143ba'
            p.write_text(json.dumps(good))
            self.assertEqual(runner.parse_export(p, row())['state'], 'WRONG_TOOL_BINDING')

    def test_request_profile_drift_stops_whole_manifest(self):
        original = json.loads(runner.REQUEST_PATH.read_bytes())
        for key, value in (('on_flags', None), ('on_flags', {}),
                           ('tool_repository', 'model-checking/kani'), ('toolchain', 'other')):
            bad = copy.deepcopy(original); bad[key] = value
            with tempfile.TemporaryDirectory() as d:
                p = Path(d)/'CI-REQUEST.json'; p.write_text(json.dumps(bad))
                with self.assertRaisesRegex(runner.RunnerError, 'ON profile'):
                    runner.load_request(p)
        for key, value in (('uninit', False), ('valid_value', True)):
            bad = copy.deepcopy(original); bad['on_flags'][key] = value
            with tempfile.TemporaryDirectory() as d:
                p = Path(d)/'CI-REQUEST.json'; p.write_text(json.dumps(bad))
                with self.assertRaisesRegex(runner.RunnerError, 'ON profile'):
                    runner.load_request(p)

    def test_yaml_old_repo_and_old_checkout_rejected(self):
        path = runner.HERE.parent/'.github/workflows/ch8-prof-on.yml'
        good = path.read_text()
        self.assertEqual(check_package.check_yaml(path)['yaml'], 'PASS')
        for bad in (good.replace('--repo control', '--repo wrong'),
                    good.replace('uninit-ci/ch8-prof02-*', 'uninit-ci/wrong-*'),
                    good.replace('repository: Tiramisu-Cake/kani', 'repository: model-checking/kani'),
                    good.replace('ref: ${{ steps.pins.outputs.tool }}', 'ref: main')):
            with tempfile.TemporaryDirectory() as d:
                p = Path(d)/'workflow.yml'; p.write_text(bad)
                with self.assertRaises(AssertionError):
                    check_package.check_yaml(p)


if __name__ == '__main__':
    unittest.main()
