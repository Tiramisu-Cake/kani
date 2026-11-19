# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""R14-01/02: real static gate and authentic writer/public-reader regressions.

Native execution and Git identities are synthetic in the existing writer fixture.
No compiler, verifier, or proof credit. This module is selected by CI Validate.
"""
import itertools
import json
import tempfile
import unittest
from collections import defaultdict
from pathlib import Path
from unittest import mock

import collect as public
import pack_evidence
import runner
import s4p_campaign as campaign
import s4p_contract_stacks as stacks
import test_s4p_paths as fixtures


class ProjectionTests(unittest.TestCase):
    def test_real_gate_complete_power_set_and_active_normalization(self):
        request = runner.load_request()
        sources = json.loads((runner.HERE / 'S4P-SOURCE.json').read_text())
        baseline = stacks.frozen()
        normalized = stacks.normalize(baseline)
        comparisons = defaultdict(dict)
        original = stacks.declarations

        def observe(text, active, parent=()):
            records = list(original(text, active, parent))
            if not parent and text in (baseline, normalized):
                comparisons[frozenset(active)]['old' if text == baseline else 'new'] = records
            return iter(records)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, text in sources.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
            with mock.patch.object(stacks, 'declarations', side_effect=observe):
                report = stacks.check(root, request)

        keys = {'kani', 'kani_smallsort_sorting', 'kani_smallsort_s2_assumed',
                'kani_smallsort_s3_leaf', 'kani_smallsort_s4_partition'}
        expected = {frozenset(part) for size in range(len(keys) + 1)
                    for part in itertools.combinations(keys, size)}
        rows = report['cfg_projection_invariance']
        actual = [frozenset(row['effective_cfg']) for row in rows]
        self.assertEqual(report['status'], 'STATIC_PASS')
        self.assertEqual(len(rows), 32)
        self.assertEqual(len(set(actual)), 32)
        self.assertEqual(set(actual), expected)
        self.assertEqual(sum('kani_smallsort_sorting' in row for row in actual), 16)
        self.assertEqual(set(comparisons), expected)
        active = {row for row in expected if stacks.ACTIVE <= row}
        self.assertEqual(len(active), 4)
        for row in rows:
            self.assertGreater(row['functions'], 0)
            self.assertEqual(row['semantics'], 'EXACT_TOKEN_MATCH')
            self.assertEqual(row['outside_s2_attrs'],
                             'NORMALIZED' if stacks.ACTIVE <= set(row['effective_cfg']) else 'EXACT_TOKEN_MATCH')
        for context in active:
            pair = comparisons[context]
            self.assertEqual(set(pair), {'old', 'new'})
            changed = 0
            for (old_name, _, old_attrs), (new_name, _, new_attrs) in zip(pair['old'], pair['new']):
                self.assertEqual(old_name, new_name)
                old, new = stacks.contracts(old_attrs), stacks.contracts(new_attrs)
                self.assertEqual([(x['op'], x['predicate_tokens']) for x in old],
                                 [(x['op'], x['predicate_tokens']) for x in new])
                if any(x['family'] == 'safety_wrapper' for x in old):
                    self.assertTrue(new)
                    self.assertTrue(all(x['family'] == 'direct_kani' for x in new))
                    changed += 1
            self.assertGreater(changed, 0, 'ACTIVE comparisons must exercise wrapper normalization')
        self.assertEqual(report['source_files_sha256'], request['contract_stack_source_sha256'])


class TerminalSchemaTests(unittest.TestCase):
    def schema_routes(self, fix, terminal):
        out, request = fix[3], fix[4]
        path = out / 'receipt.json'
        authentic = path.read_bytes()
        self.assertIs(type(terminal['schema']), str)
        self.assertEqual(terminal['schema'], 'ch8-s4p-1-campaign-v1')
        self.assertIs(type(terminal['s3_campaign']['selected_roots']), int)
        self.assertEqual(terminal['s3_campaign']['selected_roots'], 8)
        frozen = {str(p.relative_to(out)): p.read_bytes() for p in out.rglob('*.json') if p != path}
        upload = fix[0] / 'schema-upload'
        upload.mkdir(exist_ok=True)
        # First four malformed cases are the sealed review's original 24 cases.
        variants = (('genuine', 'ch8-s4p-1-campaign-v1'), ('missing', None),
                    ('null', None), ('old-schema', 'ch8-s3s4-bridge1-campaign-v1'),
                    ('wrong-type', 123), ('bool', True), ('false', False),
                    ('float', 1.0), ('list', []), ('object', {}), ('empty', ''),
                    ('unknown', 'ch8-s4p-unknown-campaign-v1'),
                    ('old-s3', 'ch8-s3-1-campaign-v1'), ('old-s32', 'ch8-s3-2-campaign-v1'))
        try:
            for name, value in variants:
                doc = json.loads(authentic)
                if name == 'missing':
                    del doc['schema']
                else:
                    doc['schema'] = value
                campaign.atomic(path, doc)
                pack_evidence.pack(out)
                (upload / pack_evidence.NAME).write_bytes((out / pack_evidence.NAME).read_bytes())
                self.assertEqual([p.name for p in upload.iterdir()], [pack_evidence.NAME])
                accepted = []
                for route in (out, upload):
                    with self.subTest(state=terminal['state'], variant=name, route=route.name):
                        with mock.patch.object(public, 'legacy_collect', wraps=public.legacy_collect) as collector:
                            if name == 'genuine':
                                result = public.collect([route], request)
                                collector.assert_called_once()
                                self.assertEqual(len(result['rows']), 8)
                                self.assertEqual(sum(row['outcome'] == 'RECORDED' for row in result['rows']),
                                                 len(terminal['s3_campaign']['completed']))
                                accepted.append(result)
                            else:
                                with self.assertRaisesRegex(campaign.GlobalFailure, 'terminal campaign schema'):
                                    public.collect([route], request)
                                collector.assert_not_called()
                if accepted:
                    self.assertEqual(accepted[0], accepted[1])
        finally:
            path.write_bytes(authentic)
        self.assertEqual(frozen, {str(p.relative_to(out)): p.read_bytes() for p in out.rglob('*.json') if p != path})

    def test_authentic_full_eight_schema_before_local_and_upload_collection(self):
        case = fixtures.RealPathWriterTests()
        with case.fixture() as fix:
            code, terminal = case.run_fixture(fix)
            self.assertEqual(code, 0)
            self.assertEqual(terminal['s3_campaign']['completed'], list(campaign.p.ORDER))
            self.schema_routes(fix, terminal)

    def test_authentic_stopped0_and_partial0_schema_before_both_routes(self):
        case = fixtures.RealPathWriterTests()
        with case.fixture() as fix:
            with mock.patch.object(campaign, 'check_usage', side_effect=campaign.GlobalFailure('schema prelaunch stop')):
                code, terminal = case.run_fixture(fix)
            self.assertEqual(code, 1)
            self.assertEqual(terminal['state'], 'STOPPED')
            self.assertEqual(terminal['s3_campaign']['completed'], [])
            self.schema_routes(fix, terminal)
            terminal = campaign.finalize(fix[3], fix[4])
            self.assertEqual(terminal['state'], 'SELECTED_PARTIAL')
            self.assertEqual(terminal['s3_campaign']['completed'], [])
            self.schema_routes(fix, terminal)


if __name__ == '__main__':
    unittest.main()
