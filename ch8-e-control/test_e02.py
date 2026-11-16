"""E-02 diagnostic/selection regressions using synthetic RFC0015 exports only."""
import copy
import json
from pathlib import Path
import re
import unittest

import test_runner as base

valid_export = base.valid_export
runner = base.runner


class E02Tests(unittest.TestCase):
    tearDown = base.RunnerTests.tearDown
    _write = base.RunnerTests._write
    def setUp(self):
        base.RunnerTests.setUp(self)
        self.rows = json.loads((Path(__file__).parent/'rows.json').read_text())
        self.mre = next(r for r in self.rows if r['id'] == 'e_h_issue_mre')

    def failure(self):
        value = valid_export('sel1', self.source, harness=self.mre['harness'])
        h = value['harnesses'][0]
        h.update(outcome={'kind':'COMPLETED', 'verdict':'FAILURE'}, failure_kind='OTHER',
                 n_properties=4, n_failed=2)
        h['checks'].update(total=3, success=0, failure=['p1','p2'], unreachable=['later'])
        h['covers'].update(total=1, satisfied=['body'])
        h['failed_properties'] = [dict(id=p, status='FAILURE', trace_available=False,
            **{'class':'assigns'}, description='Check that self->value is assignable',
            file='library/kani_core/src/mem_init.rs', line='120') for p in ('p1','p2')]
        value['summary'].update(successful=0, failed=1, checks_total=3, checks_success=0,
                                covers_total=1, covers_satisfied=1)
        return value

    def classify(self, value, row=None, run=None):
        return runner.parse_export(self._write(value), row or self.mre, 'ON', 'sel1',
            self.source, run or {'cwd':str(self.root), 'original_exit_code':1})

    def test_exact_assigns_reproduction_is_diagnostic_only(self):
        got = self.classify(self.failure())
        self.assertEqual(got['outcome'], 'ASSIGNS_FAILURE')
        self.assertEqual(got['proof_credit'], 'NONE')

    def test_unrelated_or_mixed_failures_never_match(self):
        for key, replacement in [('class','safety_check'), ('description','other assigns'),
                                 ('file','library/kani_core/src/else.rs'), ('line','121')]:
            v = self.failure()
            v['harnesses'][0]['failed_properties'][1][key] = replacement
            with self.subTest(key=key):
                self.assertEqual(self.classify(v)['outcome'], 'UNKNOWN')

    def test_wrong_absolute_tool_root_and_missing_cover_never_match(self):
        v = self.failure()
        v['harnesses'][0]['failed_properties'][0]['file'] = '/wrong/tool/library/kani_core/src/mem_init.rs'
        self.assertEqual(self.classify(v)['outcome'], 'UNKNOWN')
        v = self.failure()
        v['harnesses'][0]['covers']['satisfied'] = []
        self.assertEqual(self.classify(v)['outcome'], 'UNKNOWN')

    def test_absolute_exact_tool_location(self):
        v = self.failure()
        for p in v['harnesses'][0]['failed_properties']:
            p['file'] = str(runner.REPO.parent/'tool'/p['file'])
        self.assertEqual(self.classify(v)['outcome'], 'ASSIGNS_FAILURE')

    def test_incomplete_or_unsupported_diagnostic_never_matches(self):
        for kind in ('unknown', 'unreachable_count', 'unsupported', 'timeout', 'exit'):
            v = self.failure()
            run = {'cwd':str(self.root),'original_exit_code':1}
            if kind == 'unknown': v['harnesses'][0]['checks']['unknown'] = ['x']
            if kind == 'unreachable_count': v['harnesses'][0]['checks']['unreachable'] = []
            if kind == 'unsupported': v['harnesses'][0]['unsupported_constructs'] = [copy.deepcopy(v['harnesses'][0]['failed_properties'][0])]
            if kind == 'timeout': run['timed_out'] = True
            if kind == 'exit': run['original_exit_code'] = 0
            with self.subTest(kind=kind):
                self.assertEqual(self.classify(v, run=run)['outcome'], 'UNKNOWN')

    def test_pin_specific_expectations_and_validation(self):
        self.assertEqual(runner.row_for_pin(self.mre,'upstream')['expected_by_check']['ON'],'SUCCESS')
        self.assertEqual(runner.row_for_pin(self.mre,'sel1')['expected_by_check']['ON'],'ASSIGNS_FAILURE')
        row = copy.deepcopy(self.mre)
        del row['expected_by_pin']['upstream']
        with self.assertRaises(runner.RunnerError): runner.row_for_pin(row,'sel1')
        row = copy.deepcopy(self.mre)
        row['expected_by_pin']['sel1']['ON'] = None
        with self.assertRaises(runner.RunnerError): runner.row_for_pin(row,'sel1')

    def test_original_source_failure_gate_still_rejects_unreachable(self):
        row = copy.deepcopy(self.mre)
        del row['expected_by_pin']
        row['expected_by_check']['ON'] = 'ASSERTION_FAILURE'
        self.assertEqual(self.classify(self.failure(),row=row)['outcome'],'UNKNOWN')

    def test_false_control_exact_assertion_and_line(self):
        row = next(r for r in self.rows if r['id'] == 'e_s_false_value')
        text = (Path(__file__).parent/row['file']).read_text().splitlines()
        self.assertIn('assert!(value == value.wrapping_add(1))',text[row['failure_match']['line']-1])
        self.assertTrue(re.fullmatch(row['failure_match']['description_regex'],
                                   'assertion failed: value == value.wrapping_add(1)'))
        self.assertEqual([i for i,l in enumerate(text) if 'kani::cover' in l],
                         [i for i,l in enumerate(text) if 'kani::cover' in l and i < row['failure_match']['line']-1])

    def test_false_control_accepts_only_named_source_assertion(self):
        row = next(r for r in self.rows if r['id'] == 'e_s_false_value')
        source = Path(__file__).parent/row['file']
        v = valid_export('upstream', source, harness=row['harness'])
        h = v['harnesses'][0]
        h.update(outcome={'kind':'COMPLETED','verdict':'FAILURE'}, failure_kind='OTHER',
                 n_properties=4, n_failed=1)
        h['checks'].update(total=1, success=0, failure=['false'])
        h['covers'].update(total=3, satisfied=['a','b','c'])
        h['failed_properties'] = [dict(id='false', status='FAILURE', trace_available=False,
            **{'class':'assertion'}, description='assertion failed: value == value.wrapping_add(1)',
            file=str(source.resolve()), line=str(row['failure_match']['line']))]
        v['summary'].update(successful=0, failed=1, checks_total=1, checks_success=0,
                            covers_total=3, covers_satisfied=3)
        def parse(value):
            return runner.parse_export(self._write(value),row,'ON','upstream',source,
                {'cwd':str(self.root),'original_exit_code':1})['outcome']
        self.assertEqual(parse(v),'ASSERTION_FAILURE')
        h['failed_properties'][0]['line'] = '1'
        self.assertEqual(parse(v),'UNKNOWN')


if __name__ == '__main__': unittest.main()
