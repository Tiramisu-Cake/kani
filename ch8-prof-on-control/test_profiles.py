# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Profiles ON synthetic preflight; never starts a compiler or verifier."""
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

import check_package
import runner
from test_runner import export, row


class ProfilesTests(unittest.TestCase):
    def test_frozen_manifest_and_order(self):
        request = runner.load_request()
        self.assertEqual(len(request['rows']), 62)
        self.assertEqual(sum(r['profile_mode'].startswith('Replace:') for r in request['rows']), 5)
        self.assertEqual(sum(r['mode'] == 'PFC' for r in request['rows']), 38)
        seen = set()
        for r in request['rows']:
            if r['profile_mode'].startswith('Replace:'):
                self.assertIn(r['leaf_companion'], seen)
            self.assertEqual(runner.ci_env(r)['RUSTFLAGS'], '--cfg kani_smallsort_controls' if r['cfg'] else '')
            seen.add(r['id'])
        self.assertEqual(request['budgets']['phase_seconds'], 8400)
        self.assertEqual(request['caps']['workflow_minutes'], 180)

    def test_manifest_cfg_and_budget_drift(self):
        original = json.loads(runner.REQUEST_PATH.read_text())
        for field in ('cfg', 'unwind', 'selector', 'source_file', 'leaf_companion'):
            changed = copy.deepcopy(original)
            changed['rows'][0][field] = ['bad'] if field == 'cfg' else 'wrong'
            with tempfile.TemporaryDirectory() as d:
                p = Path(d) / 'CI-REQUEST.json'
                p.write_text(json.dumps(changed))
                (Path(d) / 'manifest.json').write_bytes((runner.HERE / 'manifest.json').read_bytes())
                with self.assertRaises(runner.RunnerError):
                    runner.load_request(p)
        changed = copy.deepcopy(original)
        changed['budgets']['phase_seconds'] += 1
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'CI-REQUEST.json'; p.write_text(json.dumps(changed))
            (Path(d) / 'manifest.json').write_bytes((runner.HERE / 'manifest.json').read_bytes())
            with self.assertRaisesRegex(runner.RunnerError, 'budget'):
                runner.load_request(p)

    def test_multiple_negative_oracles_no_unrelated_failures(self):
        selected = row(expected='DETECTED', allowed_failure_descriptions=['branch-A', 'branch-B', 'branch-C'])
        payload = export(verdict='FAILURE', failures=['p1', 'p2', 'p3'], named=[
            {'id': f'p{i+1}', 'description': f'branch-{name}'} for i, name in enumerate('ABC')])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'e.json'; p.write_text(json.dumps(payload))
            self.assertEqual(runner.parse_export(p, selected, contract_binding={selected['selector']: 'slice::sort::body'})['outcome'], 'EXPECTED')
            payload['harnesses'][0]['failed_properties'][2]['description'] = 'unrelated'
            p.write_text(json.dumps(payload))
            self.assertEqual(runner.parse_export(p, selected, contract_binding={selected['selector']: 'slice::sort::body'})['outcome'], 'UNEXPECTED')

    def test_frame_id_is_never_guessed(self):
        r = row(expected='DETECTED', allowed_failure_descriptions=['<generated modifies property; bind first>'])
        payload = export(verdict='FAILURE', failures=['p1'], named=[{'id': 'p1', 'description': 'arbitrary assertion'}])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'e.json'; p.write_text(json.dumps(payload))
            result = runner.parse_export(p, r, contract_binding={r['selector']: 'slice::sort::body'})
            self.assertEqual(result['outcome'], 'UNKNOWN')
            self.assertEqual(result['state'], 'FRAME_BINDING_REVIEW_REQUIRED')
            self.assertEqual(result['failed_properties'][0]['id'], 'p1')

    def test_source_stage_target_not_run_and_nested_wrong_types(self):
        r = row(source_file='library/core/src/pinned.rs')
        payload = export(); payload['harnesses'][0]['file'] = '/export/library/core/src/other.rs'
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'e.json'
            def parse(value):
                p.write_text(json.dumps(value))
                return runner.parse_export(p, r, contract_binding={r['selector']: 'slice::sort::body'})
            self.assertEqual(parse(payload)['state'], 'WRONG_SOURCE_FILE')
            payload['harnesses'][0]['file'] = '/export/library/core/src/pinned.rs'
            for location, value in [('outcome', {'kind': 'NOT_RUN'}), ('checks', None), ('covers', []),
                                    ('attributes', None), ('failed_properties', [None])]:
                broken = copy.deepcopy(payload); broken['harnesses'][0][location] = value
                self.assertNotEqual(parse(broken)['outcome'], 'EXPECTED')
            broken = copy.deepcopy(payload); broken['harnesses'][0]['covers']['satisfied'] = ['only-one']
            self.assertEqual(parse(broken)['state'], 'COVERAGE_INCOMPLETE')
            broken = copy.deepcopy(payload); broken['harnesses'][0]['checks']['failure'] = [{}]
            self.assertNotEqual(parse(broken)['outcome'], 'EXPECTED')

    def test_export_source_stage_target_mismatch(self):
        r = row(profile_mode='PFC:swap_profile')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'export.json'; p.write_text(json.dumps(export()))
            self.assertEqual(runner.parse_export(p, r)['state'], 'SOURCE_STAGE_TARGET_MISMATCH')

    def test_macro_spaced_and_local_profile_targets(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'export.json'
            for rid, profile, targets in [
                ('swap_contract_u8_n2', 'swap_profile',
                 ['super::merge::profiles::swap_profile', 'super :: merge :: profiles :: swap_profile']),
                ('stable_cell_n2', 'concrete_forwarder', ['stable_cell', 'module :: stable_cell']),
                ('unstable_byte_n2', 'concrete_forwarder', ['unstable_byte']),
                ('freeze_noncopy_n2', 'concrete_forwarder', ['freeze_noncopy']),
            ]:
                r = row(id=rid, profile_mode='PFC:' + profile,
                        source_file='library/core/src/pinned.rs')
                def parse(target):
                    payload = export()
                    payload['harnesses'][0]['file'] = r['source_file']
                    payload['harnesses'][0]['attributes']['kind']['ProofForContract']['target_fn'] = target
                    p.write_text(json.dumps(payload))
                    return runner.parse_export(p, r)
                for target in targets:
                    self.assertEqual(parse(target)['outcome'], 'EXPECTED', target)
                for target in [None, {}, '', 'other_profile', 'x::wrong_' + targets[0].split('::')[-1],
                               targets[0] + '_wrong', targets[0] + '()', 'swap_ profile',
                               'stable_ cell', 'x : : ' + targets[0].split('::')[-1]]:
                    self.assertEqual(parse(target)['state'], 'SOURCE_STAGE_TARGET_MISMATCH', target)

    def test_binding_fix_preserves_inventory_and_target_guards(self):
        r = row(profile_mode='PFC:swap_profile', source_file='library/core/src/pinned.rs')
        good = export()
        h = good['harnesses'][0]
        h['file'] = r['source_file']
        h['attributes']['kind']['ProofForContract']['target_fn'] = 'super :: profiles :: swap_profile'
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'export.json'
            for field, value, state in [
                ('file', 'library/core/src/other.rs', 'WRONG_SOURCE_FILE'),
                ('resolved_unwind', 5, 'WRONG_UNWIND'),
                ('attributes', {'kind': 'Proof'}, 'WRONG_MODE'),
                ('unsupported_constructs', [{'status': 'SUCCESS'}], 'INCOMPLETE_CHECK_INVENTORY'),
                ('checks', {**h['checks'], 'unreachable': ['p']}, 'INCOMPLETE_CHECK_INVENTORY'),
            ]:
                payload = copy.deepcopy(good); payload['harnesses'][0][field] = value
                p.write_text(json.dumps(payload))
                self.assertEqual(runner.parse_export(p, r)['state'], state)
            good['target'] = 'wrong-target'; p.write_text(json.dumps(good))
            self.assertEqual(runner.parse_export(p, r)['state'], 'WRONG_TARGET')

    def test_per_cfg_groups_and_leaf_postcheck(self):
        request = runner.load_request()
        groups = runner.batch_groups(request['rows'])
        self.assertEqual([len(g) for g in groups], [53, 9])
        self.assertEqual([g[0]['cfg'] for g in groups], [[], ['kani_smallsort_controls']])
        self.assertEqual({r['id'] for g in groups for r in g}, {r['id'] for r in request['rows']})
        self.assertFalse(hasattr(runner, 'list_inventory'))
        leaf = row(id='leaf')
        consumer = row(id='consumer', mode='Original', profile_mode='Replace:profile_wrapper', leaf_companion='leaf')
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            results = {r['id']: {**runner._row_base(r), 'outcome': 'EXPECTED'} for r in [leaf, consumer]}
            runner._consumer_gates([leaf, consumer], results, out)
            self.assertEqual(results['consumer']['outcome'], 'EXPECTED')
            self.assertEqual(results['consumer']['consumer_gate']['leaf_receipt_sha256'], runner.sha256(out/'leaf/receipt.json'))
            results['leaf']['outcome'] = 'UNKNOWN'
            runner._consumer_gates([leaf, consumer], results, out)
            self.assertEqual(results['consumer']['outcome'], 'UNKNOWN')
            self.assertEqual(results['consumer']['reason'], 'matching_leaf_not_accepted')
            real = runner.load_request()['rows'][0]['id']
            (out / real).mkdir(); saved = out / real / 'receipt.json'
            saved.write_text('{"status":"OBSERVED","original_exit":17}')
            before = saved.read_bytes()
            target = out / 'groups/group-00/target'; target.mkdir(parents=True)
            (target/'build-output').write_text('disposable')
            check_package.fallback(out)
            self.assertFalse(target.exists())
            self.assertEqual(saved.read_bytes(), before)

    def test_host_guard_attempt_and_parent(self):
        request = json.loads(runner.REQUEST_PATH.read_text())
        payload = {'GITHUB_REPOSITORY': 'Tiramisu-Cake/kani', 'GITHUB_EVENT_NAME': 'push',
                   'GITHUB_REF': 'refs/heads/uninit-ci/ch8-prof-on-a', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'candidate'}
        def git(repo, *args):
            return {('rev-parse', 'HEAD'): 'candidate', ('rev-parse', 'HEAD^'): runner.TOOL_SHA,
                    ('rev-list', '--parents', '-n', '1', 'HEAD'): 'candidate '+runner.TOOL_SHA,
                    ('status', '--porcelain', '--untracked-files=no'): '',
                    ('diff', '--name-only', 'HEAD^', 'HEAD'): '\n'.join(request['ci_changed_paths']),
                    ('ls-tree', '-r', '--name-only', 'HEAD', '.github/workflows'): '.github/workflows/ch8-prof-on.yml'}[args]
        with mock.patch.dict(os.environ, payload), mock.patch.object(check_package, 'git', side_effect=git):
            self.assertEqual(check_package.control(runner.HERE.parent)['status'], 'PASS')
            for key, value in [('GITHUB_REPOSITORY', 'other/repo'), ('GITHUB_RUN_ATTEMPT', '2'),
                               ('GITHUB_EVENT_NAME', 'workflow_dispatch'), ('GITHUB_REF', 'refs/heads/other')]:
                with mock.patch.dict(os.environ, {key: value}), self.assertRaises(AssertionError):
                    check_package.control(runner.HERE.parent)
        with mock.patch.dict(os.environ, payload), mock.patch.object(check_package, 'git', return_value='wrong-parent'):
            with self.assertRaises(AssertionError):
                check_package.control(runner.HERE.parent)

    def test_yaml_contract(self):
        self.assertEqual(check_package.check_yaml(runner.HERE.parent / '.github/workflows/ch8-prof-on.yml')['yaml'], 'PASS')

    def test_provenance_resolves_rustc_without_running_compiler(self):
        import subprocess
        with tempfile.TemporaryDirectory() as d:
            tool = Path(d); (tool / 'target/kani/bin').mkdir(parents=True)
            (tool / 'rust-toolchain.toml').write_text('[toolchain]\nchannel="pinned-nightly"\n')
            for rel in ('target/kani/bin/kani-driver', 'target/kani/bin/kani-compiler', 'actual-rustc', 'cbmc'):
                (tool / rel).write_bytes(rel.encode())
            completed = subprocess.CompletedProcess([], 0, str(tool / 'actual-rustc')+'\n', '')
            with mock.patch.object(runner.subprocess, 'run', return_value=completed) as run, mock.patch.object(runner.shutil, 'which', return_value=str(tool / 'cbmc')):
                result = runner.binary_fingerprints(tool, {'target': runner.TARGET})
                self.assertTrue(result['required_hashes_present'])
                self.assertEqual(result['binaries']['rustc']['sha256'], runner.sha256(tool / 'actual-rustc'))
                self.assertEqual(run.call_args.args[0], ['rustup', 'which', '--toolchain', 'pinned-nightly', 'rustc'])
            with mock.patch.object(runner.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['rustup'], 10)):
                result = runner.binary_fingerprints(tool, {})
                self.assertFalse(result['required_hashes_present'])
                self.assertIn('TimeoutExpired', result['rustc_resolution']['original_exception'])

    def test_target_and_harness_timeout_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'e.json'
            for key, value, expected in [('run_state', 'NOT_RUN', 'NOT_RUN'),
                                          ('target', 'wrong-target', 'WRONG_TARGET'),
                                          ('harness_timeout_s', None, 'WRONG_HARNESS_TIMEOUT')]:
                payload = export(); payload[key] = value; p.write_text(json.dumps(payload))
                self.assertEqual(runner.parse_export(p, row())['state'], expected)

    def test_default_checks_cannot_be_weakened(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'e.json'
            for key in ('assertion_reach_checks', 'prove_safety_only', 'ignore_global_asm', 'extra_pointer_checks'):
                payload = export(); checks = payload['configuration']['checks']; checks[key] = not checks[key]
                p.write_text(json.dumps(payload))
                self.assertEqual(runner.parse_export(p, row(), contract_binding={row()['selector']: 'slice::sort::body'})['state'], 'WRONG_CONFIGURATION')

    def test_exec_missing_and_error_preserve_original_exit(self):
        with tempfile.TemporaryDirectory() as d:
            result = runner.execute(['/nonexistent/synthetic'], Path(d), Path(d) / 'missing', 1)
            self.assertIsNone(result['original_exit_code'])
            self.assertIn('exec failed', result['runner_error'])
            import sys
            result = runner.execute([sys.executable, '-c', 'raise SystemExit(17)'], Path(d), Path(d) / 'error', 1)
            self.assertEqual(result['original_exit_code'], 17)
            self.assertFalse(result['timed_out'])


if __name__ == '__main__':
    unittest.main()
