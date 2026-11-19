# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
import copy,json,unittest
from pathlib import Path
import runner
import s4p2r2_domain as domain
import s4p2r2_profile as profile
import s4p2r2_policy as policy
import test_s4p2r2 as fixtures
HERE=Path(__file__).resolve().parent

class DomainTests(unittest.TestCase):
    def setUp(self):
        self.source=json.loads((HERE/'S4P2R2-SOURCE.json').read_text())
        self.old=self.source[domain.OLD];self.new=self.source[domain.NEW]
    def test_exact_transformation_and_exhaustive_length_relation(self):
        self.assertEqual(domain.check_text(self.old,self.new)['N01_bool_union'],[0,1])
        for n in (2,3,4):self.assertEqual({x for x in range(35) if n<=x<=n},{n})
        self.assertEqual({x for x in range(35) if 0<=x<=1},{int(b) for b in (False,True)})
        # Canary membership is unchanged for every backing-cell index/length.
        for n in (0,1,2,3,4):
            active=set(range(1,1+n));outside=set(range(34))-active
            self.assertEqual(outside,{i for i in range(34) if i<1 or i>=1+n})
            self.assertEqual(len(active),n)
    def test_adverse_source_changes_reject(self):
        changes=[('let n: usize = 2;','let n: usize = 3;'),
            ('snapshot::<u8, KeyLess<u8>>(&v[1..3])','snapshot::<u8, KeyLess<u8>>(&v[1..4])'),
            ('small_sort_network(&mut v[1..3]','small_sort_network(&mut v[1..4]'),
            ('post::<u8, KeyLess<u8>>(before, &v[1..3])','post::<u8, KeyLess<u8>>(before, &v[1..4])'),
            ('small_sort_network(&mut v[1..1], &mut KeyLess::<u8>::new());','/* no-op */'),
            ('small_sort_network(&mut v[1..2], &mut KeyLess::<u8>::new());','/* no-op */'),
            ('let one: bool = kani::any();','let one: bool = bytes[0] == 0;'),
            ('if one { 1 } else { 0 }','if one { 1 } else { 1 }'),
            ('let bytes = v;','kani::assume(v[1] < 2);\n    let bytes = v;'),
            ('for i in 0..34','for i in 0..33'),('canary < 34','canary < 33'),
            ('#[kani::unwind(36)]','#[kani::unwind(5)]'),
            ('small_sort_network(&mut','insertion_sort_shift_left(&mut'),
            ('let mut v: [u8; 34] = kani::any();','let mut v: [u8; 34] = [0; 34];'),
            ('    let canary: usize = kani::any();','    kani::assert(active_u8(), "EXTRA_ROLE");\n    let canary: usize = kani::any();')]
        for before,after in changes:
            self.assertIn(before,self.new)
            with self.subTest(change=before),self.assertRaises(AssertionError):domain.check_text(self.old,self.new.replace(before,after,1))
    def test_four_negatives_and_expectations_byte_equal_old_fixture(self):
        req=runner.load_request();old=json.loads((HERE/'fixtures/s4p2-request.json').read_text())
        self.assertEqual(req['rows'][:4],old['rows'][:4])
        self.assertEqual(req['flags'],old['flags']);self.assertEqual(req['budgets'],old['budgets'])
        for row in req['rows'][:4]:
            rid=row['id'];self.assertEqual(req['source_bindings'][rid],old['source_bindings'][rid])
            rel=req['source_bindings'][rid]['file']
            self.assertEqual(self.source[rel],json.loads((HERE/'S4P2-SOURCE.json').read_text())[rel])
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
    def test_both_N01_native_length_covers_required_sat(self):
        row=runner.load_request()['rows'][-1]
        self.assertEqual(row['required_cover_count'],3)
        for label in ('S4P2R2_N_00_01_N00','S4P2R2_N_00_01_N01'):
            parsed,props=fixtures.inventory(row)
            for status in ('UNSATISFIABLE','UNREACHABLE','UNKNOWN',None):
                bad=copy.deepcopy(props)
                next(p for p in bad['properties'] if p['description']==label)['status']=status
                self.assertFalse(policy.expected_observation(row,parsed,bad))
