# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Targeted source controls; no native compiler or macro executable."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import cfg_pfc as c
import contract_stacks as s
import runner

HERE = Path(__file__).resolve().parent


class ContractStackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sources = json.loads((HERE / 'S2-SOURCE.json').read_text())
        for rel, text in self.sources.items():
            p = self.root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        self.request = copy.deepcopy(runner.load_request())

    def check(self):
        return s.check(self.root, self.request)

    def replace(self, rel, old, new):
        path = self.root / rel
        self.assertIn(old, path.read_text())
        path.write_text(path.read_text().replace(old, new, 1))
        # Deliberately reseal to test semantic checks independently of byte pins.
        self.request['contract_stack_source_sha256'][rel] = hashlib.sha256(path.read_bytes()).hexdigest()

    def test_all_contexts_unselected_and_full_stacks(self):
        doc = self.check()
        self.assertEqual(len(doc['contexts']), 11)
        self.assertEqual(len(doc['modules']), 23)
        self.assertEqual(len(doc['functions']), 326)
        self.assertEqual(len(doc['contract_stacks']), 19)
        self.assertEqual(len(doc['cfg_projection_invariance']), 8)
        swap = next(x for x in doc['contract_stacks'] if x['function'].endswith('::swap_if_less'))
        self.assertEqual([x['op'] for x in swap['contracts_expansion_order']], ['requires'] * 5 + ['modifies', 'ensures'])
        self.assertTrue(any('old(' in x['predicate_tokens'] for x in swap['contracts_expansion_order']))
        self.assertEqual(swap['expected_single_marker_group']['recursion_check'], '__kani_recursion_check_swap_if_less')
        self.assertTrue(any('::merge::profiles::' in x['function'] for x in doc['contract_stacks']))
        self.assertEqual(doc['compilation'], 'NOT_RUN')

    def test_known_r2_mixed_stack_rejected(self):
        (self.root / s.SMALLSORT).write_text(s.frozen())
        with self.assertRaisesRegex(c.GateError, 'exact r2-preserving normalization'):
            self.check()

    def test_missing_fifth_clause_wrong_cfg_order_and_changed_post_rejected(self):
        original = self.sources[s.SMALLSORT]
        changes = [
            ('crate::kani::requires(\n    b_pos.checked_mul', 'crate::kani::requires(\n    a_pos.checked_mul'),
            ('cfg_attr(' + s.GUARD + ', crate::kani::requires(', 'cfg_attr(kani, crate::kani::requires('),
            ('cfg_attr(not(' + s.GUARD + '), safety::requires(', 'cfg_attr(not(kani), safety::requires('),
            ('crate::kani::ensures(|_| !verify::sorting_s2_swap', 'crate::kani::requires(|_| !verify::sorting_s2_swap'),
            ('crate::kani::modifies(v_base.wrapping_add(a_pos), v_base.wrapping_add(b_pos))', 'crate::kani::modifies(v_base.wrapping_add(a_pos))'),
            ('let should_swap = is_less(&*v_b, &*v_a);', 'let should_swap = false;'),
        ]
        for old, new in changes:
            (self.root / s.SMALLSORT).write_text(original)
            self.replace(s.SMALLSORT, old, new)
            with self.subTest(change=old), self.assertRaises(c.GateError):
                self.check()

    def test_unselected_provider_wrapper_rejected_after_resealing(self):
        rel = c.BASE + 'slice/sort/shared/smallsort/verify/forwarding_contracts.rs'
        self.replace(rel, 'kani::requires(', 'safety::requires(')
        with self.assertRaisesRegex(c.GateError, 'mixed/wrapper'):
            self.check()

    def test_missing_model_module_rejected(self):
        rel = c.BASE + 'slice/sort/shared/smallsort/verify/sorting_s2_span.rs'
        (self.root / rel).unlink()
        with self.assertRaisesRegex(c.GateError, 'missing/ambiguous'):
            self.check()

    def test_gate_is_called_by_existing_source_preflight(self):
        import s2_policy
        with mock.patch.object(s, 'check', side_effect=c.GateError('stack sentinel')):
            with self.assertRaisesRegex(c.GateError, 'stack sentinel'):
                s2_policy.validate_source(self.root, self.request)

    def test_comments_strings_do_not_form_contracts(self):
        text = '// #[safety::requires(false)]\nfn fixture(){let s="#[kani::ensures(false)]";}'
        records = list(s.declarations(text, s.ACTIVE))
        self.assertEqual(len(records), 1)
        self.assertEqual(s.contracts(records[0][2]), [])


if __name__ == '__main__':
    unittest.main()
