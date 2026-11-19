# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
import copy,json,unittest
from collections import Counter
from pathlib import Path
import runner
import s4p3_domain as domain
import s4p3_profile as profile
import s4p3_policy as policy
import test_s4p3 as fixtures
HERE=Path(__file__).resolve().parent

class DomainTests(unittest.TestCase):
    def setUp(self):
        self.source=json.loads((HERE/'S4P3-SOURCE.json').read_text())
        self.old=self.source[domain.OLD];self.new=self.source[domain.NEW]
    def test_exact_correspondence_lengths_and_all_canary_indices(self):
        self.assertEqual(domain.check_text(self.old,self.new)['singleton_lengths'],[8,9,13,17])
        for n in domain.LENGTHS:
            self.assertEqual({x for x in range(35) if n<=x<=n},{n})
            active=set(range(1,1+n));outside=set(range(34))-active
            self.assertEqual(len(active),n)
            self.assertEqual(outside,{i for i in range(34) if i<1 or i>=1+n})
            self.assertIn(0,outside);self.assertIn(33,outside)
    def test_adverse_call_snapshot_post_domain_frame_and_role_changes_reject(self):
        for n in domain.LENGTHS:
            changes=[(f'let n: usize = {n};',f'let n: usize = {n-1};'),
                (f'snapshot::<u8, KeyLess<u8>>(&v[1..{n+1}])',f'snapshot::<u8, KeyLess<u8>>(&v[1..{n}])'),
                (f'small_sort_network(&mut v[1..{n+1}]',f'small_sort_network(&mut v[1..{n}]'),
                (f'post::<u8, KeyLess<u8>>(before, &v[1..{n+1}])',f'post::<u8, KeyLess<u8>>(before, &v[1..{n}])')]
            for before,after in changes:
                self.assertIn(before,self.new)
                with self.subTest(n=n,change=before),self.assertRaises(AssertionError):domain.check_text(self.old,self.new.replace(before,after,1))
        changes=[('let bytes = v;','kani::assume(v[1] < 2);\n    let bytes = v;'),
            ('for i in 0..34','for i in 0..33'),('canary < 34','canary < 33'),
            ('#[kani::unwind(36)]','#[kani::unwind(18)]'),
            ('small_sort_network(&mut','insertion_sort_shift_left(&mut'),
            ('let mut v: [u8; 34] = kani::any();','let mut v: [u8; 34] = [0; 34];'),
            ('    let canary: usize = kani::any();','    kani::assert(active_u8(), "EXTRA_ROLE");\n    let canary: usize = kani::any();'),
            ('&& pair::enabled::<u8, KeyLess<u8>>()',''),
            ('kani::cover(n == 17 && descending(&bytes[1..18]), "S4P3_N_17_MAX_DESCENDING");','')]
        for before,after in changes:
            self.assertIn(before,self.new)
            with self.subTest(change=before),self.assertRaises(AssertionError):domain.check_text(self.old,self.new.replace(before,after,1))
    def test_four_negatives_and_resources_equal_network_r2_fixture(self):
        req=runner.load_request();old=json.loads((HERE/'fixtures/s4p2r2-request.json').read_text())
        self.assertEqual(req['rows'][:4],old['rows'][:4])
        self.assertEqual(req['flags'],old['flags']);self.assertEqual(req['budgets'],old['budgets'])
        for row in req['rows'][:4]:
            rid=row['id'];self.assertEqual(req['source_bindings'][rid],old['source_bindings'][rid])
            rel=req['source_bindings'][rid]['file']
            self.assertEqual(self.source[rel],json.loads((HERE/'S4P2R2-SOURCE.json').read_text())[rel])
    def test_request_and_role_mutations_reject(self):
        req=runner.load_request()
        changes=[lambda q:q['rows'].reverse(),lambda q:q['enabled_summary_edges'].append('summary'),
                 lambda q:q['unreachable_admission'].update(enabled=True),lambda q:q['flags'].update(cbmc_args=['--unwind','5']),
                 lambda q:q['budgets'].update(projected_group_count=True),lambda q:q.update(std_sha='0'*40)]
        for i in range(4,8):
            changes += [lambda q,i=i:q['rows'][i]['roles'].pop(),lambda q,i=i:q['rows'][i].update(target='callee'),
                        lambda q,i=i:q['rows'][i].update(mode='PFC'),lambda q,i=i:q['rows'][i]['roles'][0].update(line=True),
                        lambda q,i=i:q['domains'][q['rows'][i]['id']].update(logical_values='BINARY')]
        for change in changes:
            bad=copy.deepcopy(req);change(bad)
            with self.assertRaises((AssertionError,KeyError,TypeError)):profile.validate(bad)
    def test_each_native_cover_required_sat_and_each_assertion_success(self):
        for row in runner.load_request()['rows'][4:]:
            self.assertEqual(row['required_cover_count'],6)
            for role in row['roles']:
                for status in ('UNSATISFIABLE','UNREACHABLE','UNKNOWN',None,'FAILURE'):
                    parsed,props=fixtures.inventory(row)
                    next(p for p in props['properties'] if p['description']==role['description'])['status']=status
                    with self.subTest(root=row['id'],role=role['description'],status=status):self.assertFalse(policy.expected_observation(row,parsed,props))
    def test_fullbyte_cover_witnesses_are_independent_and_oracle_consistent(self):
        contract=json.loads((HERE/'S4P3-ROLE-CONTRACT.json').read_text())
        for row in contract['rows']:
            n,=row['lengths']
            self.assertEqual(len(row['static_assignments']),6)
            for witness in row['static_assignments']:
                v,out=witness['active_input'],witness['candidate_output'];role=witness['role']
                self.assertEqual(len(v),n);self.assertTrue(all(0<=x<=255 for x in v))
                self.assertEqual(Counter(v),Counter(out));self.assertEqual(out,sorted(out))
                if role=='UNSORTED':self.assertGreater(v[0],v[-1])
                if role=='DUPLICATE':self.assertEqual(v[0],v[-1])
                if role=='NONCONSTANT':self.assertLess(out[0],out[-1])
                if role=='MAX_DESCENDING':self.assertTrue(all(a>b for a,b in zip(v,v[1:])))
