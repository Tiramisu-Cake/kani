# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
import copy
import json
import unittest

from evidence import regular, stock_export


SELECTOR = 'slice::sort::shared::smallsort::verify::trait_contracts::sample'


def regular_output(ending=''):
    # Renderer shape from cbmc_property_renderer.rs: blank line before SUMMARY,
    # summary counts, and a terminal VERIFICATION line.
    return (f'Checking harness {SELECTOR}...\n'
            'RESULTS:\n'
            'Check 1: repeated.assertion.1\n'
            '\t - Status: SUCCESS\n'
            '\t - Description: "first line\nand second line"\n'
            '\t - Location: src/lib.rs:20:4 in function sample\ncontinued\n\n'
            'Check 2: repeated.assertion.1\n'
            '\t - Status: FAILURE\n'
            '\t - Description: "same ID, another observation"\n'
            '\t - Location: src/lib.rs:24 in function sample\n\n'
            '\nSUMMARY:\n ** 1 of 2 failed\n'
            'VERIFICATION:- FAILED\n' + ending).encode()


def harness(name=SELECTOR):
    return {
        'name': name, 'crate_name': 'core', 'file': 'src/lib.rs', 'line': 10,
        'contract': {'contracted_function_name': 'sort_impl', 'recursion_tracker': None},
        'is_automatically_generated': False, 'has_loop_contracts': False, 'is_bounded': False,
        'has_refcount_caveat': False,
        'attributes': {'kind': 'Proof', 'should_panic': False, 'solver': None,
                       'unwind_value': 32, 'stubs': [], 'verified_stubs': []},
        'outcome': {'kind': 'COMPLETED', 'verdict': 'FAILURE'},
        'resolved_solver': 'cadical', 'resolved_unwind': 32,
        'generated_concrete_test': False, 'resources': {'verification_time_s': 1.25},
        'n_properties': 3, 'n_failed': 1, 'failure_kind': 'OTHER',
        'failed_properties': [{'id': 'p2', 'description': 'failed check', 'class': 'assertion',
                              'file': 'src/lib.rs', 'line': '25', 'trace_available': False,
                              'status': 'FAILURE'}],
        'unsupported_constructs': [], 'warnings': [],
        'warnings_truncated': 0,
        'checks': {'total': 2, 'success': 1, 'failure': ['p2'],
                   'unreachable': [], 'undetermined': [], 'error': [], 'unknown': [], 'other': []},
        'covers': {'total': 1, 'satisfied': ['c1'], 'unsatisfiable': [],
                   'unreachable': [], 'undetermined': [], 'error': [], 'unknown': [], 'other': []},
    }


def export_document():
    return {
        'schema_version': '0.1.0', 'kani_commit': 'abc123', 'kani_commit_dirty': False,
        'tools': {'kani': '0.60.0', 'rustc': '1.91.0', 'cbmc': '6.11.0'},
        'enabled_unstable_features': ['function-contracts'],
        'harness_selection': {'requested_filters': [SELECTOR], 'exact': True,
                             'unmatched_filters': [], 'matched_count': 1},
        'harness_timeout_s': 240.0,
        'configuration': {
            'checks': {'memory_safety': True, 'overflow': True, 'unwinding': True,
                       'undefined_function': True, 'assertion_reach_checks': True,
                       'ignore_global_asm': False, 'extra_pointer_checks': False,
                       'assert_contracts': False, 'prove_safety_only': False},
            'cbmc_args': ['--object-bits', '12'], 'coverage_enabled': False,
        },
        'outcome': {'kind': 'COMPLETED'}, 'run_state': 'COMPLETE', 'target': 'x86_64-unknown-linux-gnu',
        'started_at': '2026-11-22T10:00:00Z', 'wall_time_s': 5.5,
        'harnesses': [harness()],
        'summary': {'total': 1, 'successful': 0, 'failed': 1, 'checks_total': 2,
                    'checks_success': 1, 'covers_total': 1, 'covers_satisfied': 1},
    }


class EvidenceTests(unittest.TestCase):
    def test_regular_renderer_shape_native_coordinates_terminal_and_repeats(self):
        result = regular(regular_output(), SELECTOR)
        self.assertEqual(result['state'], 'COMPLETE', result.get('reason'))
        self.assertEqual([p['ordinal'] for p in result['observations']], [1, 2])
        self.assertEqual(result['observations'][0]['description'], 'first line\nand second line')
        self.assertEqual(result['observations'][0]['location'],
                         'src/lib.rs:20:4 in function sample\ncontinued')
        self.assertLess(result['observations'][0]['source_coordinate']['byte_start'],
                        result['observations'][0]['source_coordinate']['byte_end'])
        self.assertEqual(result['observations'][0]['id'], result['observations'][1]['id'])
        self.assertEqual(result['terminal']['verification'], 'VERIFICATION:- FAILED')

    def test_regular_requires_terminal_verification_after_summary(self):
        data = regular_output().replace(b'VERIFICATION:- FAILED\n', b'')
        result = regular(data, SELECTOR)
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertIn('terminal VERIFICATION', result['reason'])

    def test_regular_malformed_record_is_incomplete(self):
        data = regular_output().replace(b'Check 1: repeated.assertion.1', b'Check 1: malformed')
        result = regular(data, SELECTOR)
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertIn('property class/ID suffix', result['reason'])

    def test_stock_export_scoped_effective_fields_and_pointers(self):
        result = stock_export(json.dumps(export_document()).encode(), SELECTOR)
        self.assertEqual(result['state'], 'COMPLETE', result['reason'])
        fields = result['observations'][0]['fields']
        self.assertEqual(fields['contract.contracted_function_name'], 'sort_impl')
        self.assertEqual(fields['resolved_solver'], 'cadical')
        self.assertEqual(fields['resolved_unwind'], 32)
        self.assertEqual(result['metadata']['configuration_checks']['assert_contracts'], False)
        self.assertEqual(result['metadata']['tools']['cbmc'], '6.11.0')
        self.assertIn('/harnesses/0/checks/failure/0', result['json_pointers'])

    def test_stock_export_accepts_timeout_null_totals_and_partial_state(self):
        document = export_document()
        document['run_state'] = 'PARTIAL'
        root = document['harnesses'][0]
        root['outcome'] = {'kind': 'TIMEOUT'}
        root['n_properties'] = root['n_failed'] = None
        root['checks']['total'] = root['checks']['success'] = None
        root['covers']['total'] = None
        root['checks']['failure'] = []
        root['checks']['success'] = None
        root['checks']['total'] = None
        root['covers']['satisfied'] = []
        root['covers']['total'] = None
        root['failed_properties'] = []
        root.pop('failure_kind')
        document['summary'].update(failed=0, checks_total=0, checks_success=0,
                                   covers_total=0, covers_satisfied=0)
        result = stock_export(json.dumps(document).encode(), SELECTOR)
        self.assertEqual(result['state'], 'COMPLETE', result['reason'])
        self.assertEqual(result['observations'][0]['fields']['outcome.kind'], 'TIMEOUT')
        self.assertIsNone(result['observations'][0]['totals']['checks.total'])

    def test_stock_export_rejects_wrong_exact_selector_and_totals(self):
        document = export_document()
        document['harness_selection']['requested_filters'] = ['not-the-selector']
        document['harnesses'][0]['checks']['total'] = 8
        result = stock_export(json.dumps(document).encode(), SELECTOR)
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertIn('exact requested selector', result['reason'])
        self.assertIn('partition total mismatch', result['reason'])

    def test_stock_export_requires_exactly_one_matching_harness(self):
        document = export_document()
        document['harnesses'].append(copy.deepcopy(document['harnesses'][0]))
        document['summary']['total'] = 3
        result = stock_export(json.dumps(document).encode(), SELECTOR)
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertIn('exactly one exact selector match', result['reason'])
        document['harnesses'][1]['name'] = 'different::selector'
        self.assertIn('singleton export', stock_export(json.dumps(document).encode(), SELECTOR)['reason'])

    def test_stock_export_malformed_partial_json(self):
        result = stock_export(b'{"harnesses": [', SELECTOR)
        self.assertEqual(result['state'], 'INCOMPLETE')
        self.assertIn('malformed or partial JSON', result['reason'])


if __name__ == '__main__':
    unittest.main()
