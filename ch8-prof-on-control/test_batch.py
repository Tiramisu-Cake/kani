# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Only isolated Python children; no toolchain invocation."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

import runner
from test_runner import row, export


def payload_for(rows):
    payload = export()
    payload['harness_selection']['requested_filters'] = [r['selector'] for r in rows]
    payload['harness_selection']['matched_count'] = len(rows)
    base = payload['harnesses'][0]
    payload['harnesses'] = []
    for r in rows:
        h = copy.deepcopy(base)
        h['name'] = r['selector']
        h['file'] = '/std/' + r.get('source_file', 'library/core/src/f.rs')
        if r['mode'] != 'PFC':
            h['attributes']['kind'] = 'Proof'
            h['contract'] = None
        if r.get('profile_mode', '').startswith('PFC:'):
            target = r['profile_mode'].split(':', 1)[1]
            target = {'stable_cell_n2': 'stable_cell', 'unstable_byte_n2': 'unstable_byte',
                      'freeze_noncopy_n2': 'freeze_noncopy'}.get(r['id'], target)
            # Match the export's TokenStream formatting and local forwarders.
            h['attributes']['kind']['ProofForContract']['target_fn'] = (
                target if r['profile_mode'] == 'PFC:concrete_forwarder' else 'slice :: ' + target)
        h['resolved_unwind'] = r['unwind']
        if r['expected'] == 'DETECTED':
            descriptions = r.get('allowed_failure_descriptions', [r.get('failure_description', '')])
            h['checks']['failure'] = [f'property-{n}' for n in range(len(descriptions))]
            h['checks']['total'] = 4 + len(descriptions)
            h['n_properties'] = 6 + len(descriptions)
            h['n_failed'] = len(descriptions)
            h['failed_properties'] = [{'id': f'property-{n}', 'description': text} for n, text in enumerate(descriptions)]
            h['outcome']['verdict'] = 'FAILURE'
        payload['harnesses'].append(h)
    return payload


class BatchTests(unittest.TestCase):
    def run_batch(self, rows, payload=None, code=0, fail=None, budget=None):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); std = root/'std'; tool = root/'tool'; out = root/'out'
            std.mkdir(); tool.mkdir()
            fp = {'required_hashes_present': True, 'binaries': {'a': {'sha256': 'pinned'}}}
            calls = []
            real_execute = runner.execute
            def execute(argv, cwd, group_out, timeout, **kwargs):
                calls.append((argv, timeout, kwargs))
                if fail:
                    return fail
                selected = kwargs['batch_rows']
                value = payload if payload is not None else payload_for(selected)
                path = kwargs['export_path']
                markers = ''.join('Checking harness '+r['selector']+'...\n' for r in reversed(selected))
                # Keep fixtures off argv (real62 metadata exceeds a single-arg OS limit).
                fixture = group_out/'fixture.json'; fixture.write_text(json.dumps(value))
                script = ('import sys,shutil; '
                          f'print({markers!r}, end="", flush=True); '
                          f'shutil.copyfile({str(fixture)!r}, {str(path)!r}); '
                          f'sys.exit({(int(any(h.get("outcome", {}).get("verdict") == "FAILURE" for h in value["harnesses"])) if code == "auto" else code)})')
                result = real_execute([sys.executable, '-c', script], cwd, group_out, timeout, **kwargs)
                fixture.unlink()
                return result
            request = {'rows': rows, 'changed_file_sha256': {}, 'variants': {}}
            with mock.patch.object(runner, 'verify_source', return_value={'source': 'pinned'}), \
                 mock.patch.object(runner, 'binary_fingerprints', return_value=fp), \
                 mock.patch.object(runner, 'group_rss_cap', return_value=runner.GROUP_RSS_MAX_KIB), \
                 mock.patch.object(runner, 'execute', side_effect=execute), \
                 mock.patch.object(runner, 'PHASE_SECONDS', budget or runner.PHASE_SECONDS):
                exit_code = runner.run_rows(std, tool, out, request)
            receipts = {r['id']: json.loads((out/r['id']/'receipt.json').read_text()) for r in rows}
            final = json.loads((out/'receipt.json').read_text())
            compiles = [json.loads(p.read_text()) for p in out.glob('groups/*/compile-receipt.json')]
            return exit_code, receipts, final, calls, compiles

    def test_mixed_verdicts_one_invocation_and_exit_preserved(self):
        rows = [row(id='positive', timeout_seconds=600),
                row(id='negative', selector='slice::sort::negative', expected='DETECTED', timeout_seconds=600)]
        code, receipts, final, calls, compiles = self.run_batch(rows, code=1)
        self.assertEqual(code, 0, receipts)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0].count('--harness'), 2)
        self.assertEqual(calls[0][0].count('--exact'), 1)
        self.assertEqual(calls[0][1], runner.COMPILE_SECONDS + 1200)
        for receipt in receipts.values():
            self.assertEqual(receipt['outcome'], 'EXPECTED')
            self.assertEqual(receipt['original_exit'], 1)
            self.assertEqual(receipt['exit_scope'], 'GROUP_NOT_ROW')
            self.assertEqual(receipt['per_row_rss'], 'UNKNOWN')
        self.assertEqual(compiles[0]['state'], 'PRE_HARNESS_COMPLETE')
        self.assertEqual(compiles[0]['harness_marker_order'], ['negative', 'positive'])

    def test_two_cfg_groups_and_real62_oracles(self):
        rows = runner.load_request()['rows']
        code, receipts, final, calls, compiles = self.run_batch(rows, code='auto')
        self.assertEqual([len(c[2]['batch_rows']) for c in calls], [53, 9])
        self.assertEqual(len(compiles), 2)
        self.assertEqual(len(receipts), 62)
        for r in rows:
            observation = receipts[r['id']]
            if any(x.startswith('<generated modifies') for x in r['allowed_failure_descriptions']):
                self.assertEqual(observation['export']['state'], 'FRAME_BINDING_REVIEW_REQUIRED')
            else:
                self.assertEqual(observation['outcome'], 'EXPECTED', observation)
        self.assertEqual(code, 1)
        self.assertFalse(final['stop_reason'])
        self.assertEqual(final['proof_credit'], 'NONE')

    def test_selection_is_group_exact_and_each_row_binds_own_entry(self):
        rows = [row(id='a'), row(id='b', selector='slice::sort::b')]
        good = payload_for(rows)
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'e.json'
            for change in ('missing', 'duplicate', 'extra', 'filters', 'unmatched', 'generated', 'target'):
                value = copy.deepcopy(good)
                if change == 'missing': value['harnesses'].pop()
                if change == 'duplicate': value['harnesses'][1] = value['harnesses'][0]
                if change == 'extra': value['harnesses'].append(value['harnesses'][0])
                if change == 'filters': value['harness_selection']['requested_filters'].reverse()
                if change == 'unmatched': value['harness_selection']['unmatched_filters'] = ['bad']
                if change == 'generated': value['harnesses'][0]['is_automatically_generated'] = True
                if change == 'target': value['target'] = 'wrong'
                path.write_text(json.dumps(value))
                self.assertEqual(runner.parse_export(path, rows[0], group_rows=rows)['outcome'], 'UNKNOWN', change)
            value = copy.deepcopy(good)
            value['harnesses'][1]['outcome'] = {'kind': 'TIMEOUT'}
            path.write_text(json.dumps(value))
            self.assertEqual(runner.parse_export(path, rows[0], group_rows=rows)['outcome'], 'EXPECTED')
            self.assertEqual(runner.parse_export(path, rows[1], group_rows=rows)['outcome'], 'UNKNOWN')

    def test_error_timeout_partial_and_wrong_shapes(self):
        rows = [row(id='a'), row(id='b', selector='slice::sort::b')]
        for fixture in ([], {'harnesses': None}, {'run_state': 'NOT_RUN'}, {'schema_version': '0.1.0', 'run_state': 'PARTIAL'}):
            code, receipts, _, _, _ = self.run_batch(rows, fixture)
            self.assertEqual(code, 1)
            self.assertTrue(all(r['outcome'] == 'UNKNOWN' for r in receipts.values()))
        for execution in ({'original_exit_code': 17, 'signal': None},
                          {'original_exit_code': -15, 'signal': 15, 'termination_reason': 'timeout', 'timed_out': True},
                          {'original_exit_code': None, 'runner_error': 'exec failed'}):
            code, receipts, final, _, _ = self.run_batch(rows, fail=execution)
            self.assertEqual(code, 1)
            self.assertTrue(final['stop_reason'])
            self.assertTrue(all(r['original_exit'] == execution['original_exit_code'] for r in receipts.values()))
            self.assertTrue(all(r['outcome'] == 'UNKNOWN' for r in receipts.values()))

    def test_failed_leaf_blocks_consumer_after_batch(self):
        rows = [row(id='leaf'), row(id='consumer', selector='slice::sort::consumer', mode='Original',
                 profile_mode='Replace:profile_wrapper', leaf_companion='leaf')]
        value = payload_for(rows)
        value['harnesses'][0]['outcome'] = {'kind': 'NOT_RUN'}
        code, receipts, _, _, _ = self.run_batch(rows, value, code=1)
        self.assertEqual(code, 1)
        self.assertEqual(receipts['consumer']['outcome'], 'UNKNOWN')
        self.assertEqual(receipts['consumer']['reason'], 'matching_leaf_not_accepted')

    def test_phase_cap_not_run(self):
        code, receipts, _, calls, _ = self.run_batch([row(id='a')], budget=runner.COMPILE_SECONDS)
        self.assertEqual(code, 1)
        self.assertFalse(calls)
        self.assertEqual(receipts['a']['status'], 'NOT_RUN')

    def test_compile_timeout_cbmc_and_group_rss_caps(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with mock.patch.object(runner, 'COMPILE_SECONDS', 0.05):
                result = runner.execute([sys.executable, '-c', 'import time; time.sleep(2)'], root, root/'compile', 5,
                                        batch_rows=[row()], receipt_root=root)
            self.assertEqual(result['termination_reason'], 'compile_timeout')
            self.assertEqual(result['compilation']['state'], 'UNKNOWN')
            with mock.patch.object(runner, '_cbmc_rss_kib', return_value=runner.RSS_CAP_KIB+1):
                result = runner.execute([sys.executable, '-c', 'import time; time.sleep(2)'], root, root/'cbmc', 5,
                                        batch_rows=[row()], receipt_root=root)
            self.assertEqual(result['termination_reason'], 'cbmc_rss_cap')
            with mock.patch.object(runner, '_group_rss_kib', return_value=100):
                result = runner.execute([sys.executable, '-c', 'import time; time.sleep(2)'], root, root/'rss', 5,
                                        rss_cap_kib=10, batch_rows=[row()], receipt_root=root)
            self.assertEqual(result['termination_reason'], 'rss_cap')

    def test_batch_execution_reports_output_bytes_and_truncation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            script = ("import sys; print('Checking harness slice::sort::root...', flush=True); "
                      "sys.stdout.write('x' * 1200000); sys.stdout.flush()")
            result = runner.execute([sys.executable, '-c', script], root, root/'group', 5,
                                    batch_rows=[row()], receipt_root=root)
            self.assertEqual(result['termination_reason'], 'row_stdout_cap')
            self.assertGreater(result['output_bytes'], runner.STDOUT_CAP_BYTES)
            self.assertTrue(result['stdout_truncated'])
            self.assertTrue(result['output_truncated'])
            self.assertFalse(result['stderr_truncated'])

    def test_output_row_caps_and_compile_head_tail(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); group = root/'group'; group.mkdir()
            capture = runner.BatchCapture(group, root, [row()])
            capture.feed('stdout', b'x' * 200000 + b'\n')
            capture.feed('stderr', b'y' * 200000)
            capture.feed('stdout', b'Checking harness slice::sort::root...\n')
            capture.feed('stdout', b'x' * (runner.STDOUT_CAP_BYTES + 8192))
            capture.feed('stderr', b'y' * (runner.STDERR_CAP_BYTES + 1))
            receipt = capture.finish()
            self.assertLessEqual((root/'synthetic/stdout.log').stat().st_size, runner.STDOUT_CAP_BYTES)
            self.assertLessEqual((root/'synthetic/stderr.log').stat().st_size, runner.STDERR_CAP_BYTES)
            self.assertTrue(capture.reason)
            for key in ('stdout', 'stderr'):
                self.assertLessEqual((group/('compile-'+key+'.log')).stat().st_size, runner.COMPILE_LOG_BYTES + 64)
                self.assertGreater(receipt['logs'][key]['bytes'], runner.COMPILE_LOG_BYTES)


if __name__ == '__main__':
    unittest.main()
