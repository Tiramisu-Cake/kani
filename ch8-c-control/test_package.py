"""Synthetic package checks; never invokes Kani or a verifier build."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import yaml
import check_package as c


class PackageTests(unittest.TestCase):
    def test_yaml_valid_and_sensitivity(self):
        source = Path(__file__).resolve().parents[1] / '.github/workflows/ch8-c.yml'
        self.assertEqual(c.check_yaml(source)['yaml'], 'PASS')
        doc = yaml.load(source.read_text(), Loader=yaml.BaseLoader)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'workflow.yml'
            mutators = [
                lambda x: x['on'].update({'workflow_dispatch': {}}),
                lambda x: x['jobs']['c-controls'].update({'env': {'TEMP': '${{ runner.temp }}'}}),
                lambda x: x['jobs']['c-controls']['steps'][1]['with'].update({'fetch-depth': '1'}),
                lambda x: x['jobs']['c-controls'].update({'runs-on': 'self-hosted'}),
                lambda x: x['on']['push'].update({'branches': ['uninit-ci/ch8-s1-*']}),
                lambda x: x['jobs']['c-controls'].update({'timeout-minutes': '61'}),
                lambda x: next(s for s in x['jobs']['c-controls']['steps']
                               if s.get('name') == 'Seed frozen inventory and run fixed C batches').update({'timeout-minutes': '111'}),
                lambda x: next(s for s in x['jobs']['c-controls']['steps']
                               if s.get('name') == 'Seed frozen inventory and run fixed C batches').update(
                                   {'run': next(s for s in x['jobs']['c-controls']['steps']
                                                if s.get('name') == 'Seed frozen inventory and run fixed C batches')['run'].replace('runner.py inventory', 'runner.py list')}),
                lambda x: x['jobs']['c-controls']['steps'][-1]['with'].update({'path': '${{ env.RECEIPT_ROOT }}/'}),
                lambda x: x['jobs']['c-controls']['steps'][1]['with'].update({'ref': 'main'}),
                lambda x: next(s for s in x['jobs']['c-controls']['steps']
                               if s.get('with', {}).get('path') == 'export')['with'].update({'repository': 'Tiramisu-Cake/kani'}),
                lambda x: next(s for s in x['jobs']['c-controls']['steps']
                               if s.get('with', {}).get('path') == 'export')['with'].update({'submodules': 'false'}),
                lambda x: next(s for s in x['jobs']['c-controls']['steps']
                               if s.get('with', {}).get('path') == 'tool')['with'].update({'ref': 'main'}),
            ]
            for mutate in mutators:
                bad = copy.deepcopy(doc); mutate(bad); p.write_text(yaml.safe_dump(bad))
                with self.assertRaises(AssertionError): c.check_yaml(p)

    def test_control_guards_and_payload_drift(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); repo = root / 'control'; here = repo / 'ch8-c-control'; here.mkdir(parents=True)
            payload = here / 'payload.py'; payload.write_text('synthetic')
            rel = 'ch8-c-control/payload.py'
            payload_digest = hashlib.sha256(payload.read_bytes()).hexdigest()
            manifest = here / 'MANIFEST.sha256'
            manifest.write_text(f'{payload_digest}  {rel}\n')
            req = {'status': 'READY', 'tool_sha': 'a'*40, 'payload_manifest': 'MANIFEST.sha256',
                   'payload_manifest_sha256': hashlib.sha256(manifest.read_bytes()).hexdigest(),
                   'flags': {'attempt': 1, 'max_root_seconds': 600, 'uninit_checks': False,
                             'valid_value_checks': False, 'assert_contracts': False, 'sorting_cfg': False},
                   'budgets': {'setup_seconds': 1800, 'phase_seconds': 6720, 'reserve_seconds': 300,
                     'job_seconds': 9000, 'run_step_seconds': 6720, 'group_seconds': 2100},
                   'rows': [{'id': x, 'timeout_seconds': 600, 'unwind': unwind} for x, unwind in [
                     ('c_merge_source_write_restore', 17), ('c_merge_source_read_only', 17)]],
                   'ci_payload_sha256': {rel: payload_digest}, 'ci_changed_paths': [rel]}
            (here / 'CI-REQUEST.json').write_text(json.dumps(req))
            responses = {('rev-parse', 'HEAD'): 'b'*40, ('rev-parse', 'HEAD^'): 'a'*40,
                ('rev-list', '--parents', '-n', '1', 'HEAD'): 'b'*40+' '+'a'*40,
                ('status', '--porcelain=v1'): '', ('diff', '--name-only', 'HEAD^', 'HEAD'): rel,
                ('ls-tree', '-r', '--name-only', 'HEAD', '.github/workflows'): '.github/workflows/ch8-c.yml'}
            env = {'GITHUB_REPOSITORY': 'Tiramisu-Cake/kani', 'GITHUB_EVENT_NAME': 'push',
                   'GITHUB_REF': 'refs/heads/uninit-ci/ch8-c-ctl-synthetic',
                   'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_SHA': 'b'*40}
            with patch.object(c, 'HERE', here), patch.object(c, 'git', side_effect=lambda repo, *args: responses[args]), patch.dict(os.environ, env, clear=True):
                self.assertEqual(c.control(repo)['status'], 'PASS')
                for key, value in [('GITHUB_REPOSITORY', 'other/repo'), ('GITHUB_EVENT_NAME', 'workflow_dispatch'),
                                   ('GITHUB_REF', 'refs/heads/main'), ('GITHUB_REF', 'refs/heads/uninit-ci/ch8-s1-old'),
                                   ('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_SHA', 'c'*40)]:
                    with patch.dict(os.environ, {key: value}):
                        with self.assertRaises(AssertionError): c.control(repo)
                for args, bad in [
                    (('rev-parse', 'HEAD^'), 'c'*40),
                    (('status', '--porcelain=v1'), ' M ch8-c-control/payload.py'),
                    (('diff', '--name-only', 'HEAD^', 'HEAD'), 'kani-driver/src/main.rs'),
                    (('diff', '--name-only', 'HEAD^', 'HEAD'), rel+'\nch8-c-control/unlisted.py'),
                    (('ls-tree', '-r', '--name-only', 'HEAD', '.github/workflows'), '.github/workflows/ch8-c.yml\n.github/workflows/extra.yml')]:
                    original = responses[args]; responses[args] = bad
                    with self.subTest(args=args, bad=bad):
                        with self.assertRaises(AssertionError): c.control(repo)
                    responses[args] = original
                responses[('rev-list', '--parents', '-n', '1', 'HEAD')] += ' ' + 'c'*40
                with self.assertRaises(AssertionError): c.control(repo)
                responses[('rev-list', '--parents', '-n', '1', 'HEAD')] = 'b'*40+' '+'a'*40
                payload.write_text('drift')
                with self.assertRaises(AssertionError): c.control(repo)
                payload.write_text('synthetic'); (root / 'Cargo.toml').write_text('[workspace]')
                with self.assertRaises(AssertionError): c.control(repo)

    def test_build_wrapper_receipts_and_errors_without_build(self):
        import runner
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); epoch = root / 'epoch'; epoch.write_text('1000')
            result = {'original_exit_code': 0, 'timed_out': False, 'termination_reason': None,
                      'stdout_truncated': False, 'stderr_truncated': False}
            with patch.object(c.time, 'time', return_value=1010), patch.object(runner, 'execute', return_value=result.copy()) as execute:
                self.assertEqual(c.build(root, epoch, root/'ok')['setup'], 'COMPLETE')
                self.assertEqual(execute.call_args.args[0], ['cargo', 'build-dev', '--', '--release'])
                for key, value in [('original_exit_code', 42), ('timed_out', True),
                                   ('termination_reason', 'signal'), ('stdout_truncated', True), ('stderr_truncated', True)]:
                    execute.return_value = {**result, key: value}; out = root / key
                    with self.assertRaises(AssertionError): c.build(root, epoch, out)
                    self.assertEqual(json.loads((out/'receipt.json').read_text())[key], value)
                execute.side_effect = OSError('synthetic launch error')
                with self.assertRaises(OSError): c.build(root, epoch, root/'exception')
            with patch.object(c.time, 'time', return_value=2801), patch.object(runner, 'execute') as execute:
                with self.assertRaises(AssertionError): c.build(root, epoch, root/'expired')
                execute.assert_not_called()

    def test_fallback_preserves_receipt_materializes_tail_and_bounds(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); here = root/'control'; here.mkdir(); out = root/'receipts'; out.mkdir()
            request = {'rows': [{'id': s, 'selector': 'x::'+s, 'mode': 'Original', 'variant': 'production'} for s in ['done', 'tail']],
                       'budgets': {'artifact_bytes': 10000}}
            (here/'CI-REQUEST.json').write_text(json.dumps(request))
            done = out/'done'; done.mkdir(); (done/'receipt.json').write_text('{"original_exit_code":42}')
            with patch.object(c, 'HERE', here):
                c.fallback(out)
                self.assertEqual(json.loads((done/'receipt.json').read_text())['original_exit_code'], 42)
                self.assertEqual(json.loads((out/'tail/receipt.json').read_text())['status'], 'NOT_RUN')
                (out/'oversize.log').write_bytes(b'x'*20000)
                c.fallback(out)
                self.assertTrue((out/'TRUNCATED.json').is_file())
                self.assertFalse((out/'oversize.log').exists())

    def test_fallback_excludes_build_targets_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); here = root/'control'; here.mkdir(); out = root/'receipts'; out.mkdir()
            (here/'CI-REQUEST.json').write_text(json.dumps({'rows': [], 'budgets': {'artifact_bytes': 10000}}))
            listed = out/'list'; listed.mkdir()
            evidence = listed/'kani-list.json'; evidence.write_text('{"original":42}')
            target = listed/'target'/'debug'; target.mkdir(parents=True)
            (target/'build.bin').write_bytes(b'x'*20000)
            with patch.object(c, 'HERE', here):
                c.fallback(out)
                self.assertFalse((listed/'target').exists())
                self.assertEqual(evidence.read_text(), '{"original":42}')
                self.assertEqual(json.loads((out/'job-status.json').read_text())['excluded_build_directories'], ['list/target'])
                self.assertFalse((out/'TRUNCATED.json').exists())
                (listed/'target').mkdir()
                with patch.object(c.shutil, 'rmtree', side_effect=OSError('synthetic cleanup failure')):
                    with self.assertRaisesRegex(OSError, 'synthetic cleanup failure'): c.fallback(out)
                self.assertEqual(evidence.read_text(), '{"original":42}')


if __name__ == '__main__':
    unittest.main()
