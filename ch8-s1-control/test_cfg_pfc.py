# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Static Rust fixtures only: no compiler, Kani or full runner."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import cfg_pfc as c
import check_package as cp
import runner

HERE = Path(__file__).resolve().parent
BATCH = c.BASE + 'slice/sort/shared/smallsort/verify/sorting_s2_batch.rs'
HELPER = c.BASE + 'slice/sort/shared/smallsort/verify/helper_contracts.rs'
VERIFY = c.BASE + c.VERIFY
PFC = '#[kani::proof_for_contract(sort8_stable)]'


class LegacyCfgPfcTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sources = json.loads((HERE/'S2-SOURCE.json').read_text())
        self.sources[BATCH] = (HERE/'fixtures/s2-r1-batch.rs.txt').read_text()
        for rel, text in self.sources.items():
            path = self.root/rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.request = copy.deepcopy(runner.load_request())
        # Semantic mutations reseal hashes explicitly: must fail for cfg/target
        # matching itself, not just frozen byte identity. Production retains map.
        self.request.pop('cfg_pfc_source_sha256')

    def replace(self, rel, old, new):
        path = self.root/rel
        self.assertIn(old, path.read_text())
        path.write_text(path.read_text().replace(old, new))

    def check(self):
        return c.check(self.root, self.request)

    def test_all_eleven_rows_and_full_targets(self):
        doc = self.check()
        self.assertEqual(len(doc['rows']), 11)
        self.assertEqual(sum(len(r['stub_verified']) for r in doc['rows']), 6)
        self.assertEqual(len(doc['source_files_sha256']), 8)
        self.assertEqual(doc['source_files_sha256'], {rel:hashlib.sha256(self.sources[rel].encode()).hexdigest() for rel in doc['source_files_sha256']})
        for row in doc['rows']:
            self.assertEqual(row['effective_cfg'], sorted({'kani'} | {
                x[len('--cfg='):] for x in self.request['flags']['RUSTFLAGS'].split()}))
            for ref in row['stub_verified']:
                self.assertTrue(ref['target'].startswith('core::slice::sort::shared::smallsort::'))
                self.assertTrue(ref['matching_pfc'])
        self.assertFalse(doc['qualification_from_registration'])

    def test_old_97ac_rejected_for_observed_sort8_class(self):
        old = (HERE/'fixtures/s2-old97ac-batch.rs.txt').read_bytes()
        self.assertEqual(hashlib.sha256(old).hexdigest(),
                         '37125e0d65bbce0b70fc6626960cbf0c17dab3d2d07675c183cf15407a37c850')
        (self.root/BATCH).write_bytes(old)
        with self.assertRaisesRegex(c.GateError, 'sort8_stable.*no active matching proof_for_contract'):
            self.check()

    def test_missing_registration(self):
        self.replace(BATCH, PFC, '#[kani::proof]')
        with self.assertRaisesRegex(c.GateError, 'sort8_stable.*no active matching'):
            self.check()

    def test_wrong_cfg_registration(self):
        self.replace(BATCH, PFC, '#[cfg(not(kani_smallsort_s2_assumed))]\n'+PFC)
        with self.assertRaisesRegex(c.GateError, 'sort8_stable.*no active matching'):
            self.check()

    def test_cfg_attr_guard_is_evaluated(self):
        self.replace(BATCH, PFC,
                     '#[cfg_attr(not(kani_smallsort_s2_assumed),kani::proof_for_contract(sort8_stable))]')
        with self.assertRaisesRegex(c.GateError, 'sort8_stable.*no active matching'):
            self.check()
        self.replace(BATCH, 'cfg_attr(not(kani_smallsort_s2_assumed)',
                     'cfg_attr(all(kani,any(kani_smallsort_s2_assumed,not(kani_smallsort_sorting)))')
        self.assertEqual(self.check()['status'], 'STATIC_PASS')

    def test_cfg_attr_can_disable_function(self):
        self.replace(BATCH, PFC, '#[cfg_attr(kani_smallsort_sorting,cfg(not(kani_smallsort_s2_assumed)))]\n'+PFC)
        with self.assertRaisesRegex(c.GateError, 'sort8_stable.*no active matching'):
            self.check()

    def test_foreign_same_basename_and_alias_do_not_match(self):
        # A real, visible function in another compiled module, not an unresolved
        # path. Matching only the basename would incorrectly accept this fixture.
        path = self.root/HELPER
        path.write_text(path.read_text() + '\n#[kani::ensures(|_| true)]\n'
                        'pub(super) fn sort8_stable() {}\n')
        self.replace(BATCH, PFC,
                     'use super::helper_contracts::sort8_stable as foreign_sort8;\n#[kani::proof_for_contract(foreign_sort8)]')
        with self.assertRaisesRegex(c.GateError, 'sort8_stable.*no active matching'):
            self.check()

    def test_matching_full_path_and_aliases(self):
        self.replace(BATCH, PFC,
                     'use super::super::sort8_stable as leaf8;\n#[kani::proof_for_contract(leaf8)]')
        self.replace(BATCH, '#[kani::stub_verified(sort8_stable)]',
                     '#[crate::kani::stub_verified(crate::slice::sort::shared::smallsort::sort8_stable)]')
        self.assertEqual(self.check()['status'], 'STATIC_PASS')

    def test_attribute_alias(self):
        self.replace(BATCH, 'use crate::{kani, mem::MaybeUninit, ptr};',
                     'use crate::{kani, mem::MaybeUninit, ptr};\nuse crate::kani as k;')
        self.replace(BATCH, PFC, '#[k::proof_for_contract(sort8_stable)]')
        self.assertEqual(self.check()['status'], 'STATIC_PASS')

    def test_other_required_targets_cannot_lose_registration(self):
        for target in ('insert_tail', 'bidirectional_merge', 'swap_if_less'):
            with self.subTest(target=target):
                (self.root/HELPER).write_text(self.sources[HELPER])
                (self.root/BATCH).write_text(self.sources[BATCH])
                for rel in (HELPER, BATCH):
                    path = self.root/rel
                    path.write_text(path.read_text().replace(
                        '#[kani::proof_for_contract('+target+')]', '#[kani::proof]'))
                with self.assertRaisesRegex(c.GateError, target+'.*no active matching'):
                    self.check()

    def test_ordinary_stub_does_not_require_pfc(self):
        doc = self.check()
        for rid in ('sort13_weak', 'general32_weak'):
            row = next(r for r in doc['rows'] if r['id'] == rid)
            self.assertEqual(len(row['ordinary_stubs_no_pfc_required']), 1)
            self.assertTrue(row['ordinary_stubs_no_pfc_required'][0]['replacement'].endswith(
                '::weak_swap' if rid == 'sort13_weak' else '::weak_merge'))

    def test_inactive_root_and_module_fail_closed(self):
        self.replace(BATCH, 'fn general32_weak()',
                     '#[cfg(not(kani_smallsort_s2_assumed))]\nfn general32_weak()')
        with self.assertRaisesRegex(c.GateError, 'manifest root inactive/missing'):
            self.check()
        (self.root/BATCH).write_text(self.sources[BATCH])
        self.request['flags']['RUSTFLAGS'] = '--cfg=kani_smallsort_sorting --cfg=kani_smallsort_controls'
        with self.assertRaisesRegex(c.GateError, 'inactive module'):
            self.check()

    def test_unsupported_glob_unknown_cfg_and_ambiguous_alias_fail_closed(self):
        cases = [('use super::super::*;', 'glob import'),
                 ('use super::super::sort8_stable;', 'ambiguous use alias'),
                 ('fn sort8_stable() {}', 'ambiguous imported/local function'),
                 ('#[cfg(unknown_target_cfg)]\n'+PFC, 'unknown cfg')]
        for replacement, message in cases:
            with self.subTest(message=message):
                (self.root/BATCH).write_text(self.sources[BATCH])
                self.replace(BATCH, PFC, replacement if replacement.startswith('#') else replacement+'\n'+PFC)
                with self.assertRaisesRegex(c.GateError, message):
                    self.check()

    def test_literal_and_comment_decoys_do_not_register(self):
        self.replace(BATCH, PFC, '// '+PFC+'\n#[doc = "#[kani::proof_for_contract(sort8_stable)]"]')
        with self.assertRaisesRegex(c.GateError, 'sort8_stable.*no active matching'):
            self.check()

    def test_frozen_hashes_and_workflow_order(self):
        self.replace(BATCH, 'let mut src: [u8;8]', 'let mut src: [u8; 8]')
        with self.assertRaisesRegex(c.GateError, 'source-hash binding drift'):
            c.check(self.root, runner.load_request())
        text = (HERE.parent/'.github/workflows/ch8-s2.yml').read_text()
        doc = cp.load_yaml(text)
        steps = doc['jobs']['s2_batch']['steps']
        a = next(i for i,s in enumerate(steps) if s['name'] == 'Check all source identities')
        b = next(i for i,s in enumerate(steps) if s['name'] == 'Build exact stock tool once')
        steps[a], steps[b] = steps[b], steps[a]
        import yaml
        path = self.root/'wrong-order.yml'
        path.write_text(yaml.safe_dump(doc))
        with self.assertRaises(AssertionError):
            cp.check_yaml(path)


class R2CfgPfcTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.sources = json.loads((HERE/'S2-SOURCE.json').read_text())
        for rel, text in self.sources.items():
            path = self.root/rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.request = copy.deepcopy(runner.load_request())
        self.request.pop('cfg_pfc_source_sha256')

    def test_both_general_roots_exact_ordinary_and_remaining_pfcs(self):
        doc = c.check(self.root, self.request)
        expected = {'sort13_assumed': ['swap_if_less'],
                    'general32_assumed': ['insert_tail','bidirectional_merge'],
                    'general32_weak': ['insert_tail']}
        for row in doc['rows']:
            self.assertEqual([x['target'].split('::')[-1] for x in row['stub_verified']], expected.get(row['id'], []))
            if row['id'] in ('general32_assumed','general32_weak'):
                models = [x for x in row['ordinary_stubs_no_pfc_required'] if x['target'].endswith('::sort8_stable')]
                self.assertEqual(len(models), 1)
                self.assertTrue(models[0]['replacement'].endswith('::sorting_s2_batch::diagnostic_sort8'))
                self.assertEqual(models[0]['replacement_location']['file'], BATCH)
        self.assertFalse(any(x['target'].endswith('::sort8_stable') for x in doc['checked_active_slice_uses']))

    def test_either_reintroduced_verified_sort8_fails_including_unselected(self):
        baseline=self.sources[BATCH]
        for index in (0,1):
            parts=baseline.split('#[kani::stub(sort8_stable,diagnostic_sort8)]')
            parts[index]+='#[kani::stub_verified(sort8_stable)]'
            text=parts[0]+parts[1]+'#[kani::stub(sort8_stable,diagnostic_sort8)]'+parts[2] if index==0 else parts[0]+'#[kani::stub(sort8_stable,diagnostic_sort8)]'+parts[1]+parts[2]
            (self.root/BATCH).write_text(text)
            with self.assertRaisesRegex(c.GateError, 'sort8_stable.*no active matching'):
                c.check(self.root,self.request)
        (self.root/BATCH).write_text(baseline+'\n#[kani::proof]\n#[kani::stub_verified(sort8_stable)]\nfn unselected() {}\n')
        with self.assertRaisesRegex(c.GateError,'sort8_stable.*no active matching'):
            c.check(self.root,self.request)

    def test_ordinary_replacement_missing_wrong_cfg_foreign_rejected(self):
        baseline=self.sources[BATCH]
        changes=[('unsafe fn diagnostic_sort8','unsafe fn absent_sort8'),
                 ('unsafe fn diagnostic_sort8','#[cfg(not(kani_smallsort_s2_assumed))]\nunsafe fn diagnostic_sort8'),
                 ('stub(sort8_stable,diagnostic_sort8)','stub(sort8_stable,super::helper_contracts::diagnostic_sort8)'),
                 ('stub(sort8_stable,diagnostic_sort8)','stub(super::helper_contracts::sort8_stable,diagnostic_sort8)')]
        for old,new in changes:
            with self.subTest(new=new):
                (self.root/BATCH).write_text(baseline.replace(old,new))
                with self.assertRaisesRegex(c.GateError, 'ordinary (replacement|stub target)'):
                    c.check(self.root,self.request)

    def test_exact_model_delta_preserves_domain_post_frame_and_original_roots(self):
        import s2_policy
        baseline=self.sources[BATCH]
        self.assertTrue(s2_policy.validate_sort8_model(baseline))
        changes=[('assert!(span::active::<T,F>());',''),
                 ('kani::assume(span::post::<T,F>(before,dst,8));','kani::assume(true);'),
                 ('for i in 0..8 {','for i in 0..7 {'),
                 ('merge_contract_regions_disjoint(dst,scratch_base,8)','merge_contract_regions_disjoint(dst,dst,8)'),
                 ('scratch_base.cast::<u8>().add(i).write','v_base.cast::<u8>().add(i).write'),
                 ('S2_NEG_GENERAL32_WEAK','REMOVED_NEGATIVE')]
        for old,new in changes:
            self.assertIn(old,baseline)
            with self.subTest(old=old), self.assertRaises(AssertionError):
                s2_policy.validate_sort8_model(baseline.replace(old,new))


if __name__ == '__main__':
    unittest.main()
