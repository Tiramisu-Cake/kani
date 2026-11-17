# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Small static/synthetic S1-08 checks; no verifier or admission invocation."""
import copy
import json
from pathlib import Path
import unittest

import s108_package as s

HERE = Path(__file__).resolve().parent


class S108Tests(unittest.TestCase):
    def setUp(self):
        self.request_bytes = (HERE/'CI-REQUEST.json').read_bytes()
        self.request = json.loads(self.request_bytes)
        self.manifest = json.loads((HERE/'ROLE-MAP.json').read_bytes())
        self.digest = s.sha(self.request_bytes)

    def test_manifest_coverage_pins_and_legacy_sets(self):
        self.assertEqual(s.validate_map(self.manifest,self.request)['required'],127)
        self.assertEqual(s.sha((HERE/'ROLE-MAP.json').read_bytes()), self.request['role_map']['sha256'])
        for rel,digest in self.request['ci_payload_sha256'].items():
            self.assertEqual(s.sha((HERE.parent/rel).read_bytes()),digest,rel)
        sets=[e for e in self.manifest['required_success_bindings'] if e['binding_kind']=='EXACT_SUCCESS_SEMANTIC_SET']
        self.assertEqual(len(sets),3)
        for e in sets:
            self.assertEqual(len(e['legacy_s107']['candidate_property_ids']),3)
            self.assertEqual(len(e['source']['helper_callsites']),3)
            self.assertEqual(e['cardinality'],'COMPLETE_SOURCE_INSTANCE_SET')
        for union in self.request['replacement_unions']:
            expected=[m for rid in union['member_row_ids'] for row in self.request['rows']
                      if row['id']==rid for m in row['required_success_messages']]
            self.assertEqual(union['required_success_messages'],expected)
            self.assertEqual(len(expected),20)
            self.assertEqual(len(set(expected)),20)
        self.assertEqual(sum(len(row['required_cover_messages']) for row in self.request['rows']),113)
        self.assertEqual(sum(row['expected']=='DETECTED' for row in self.request['rows']),8)

    def test_manifest_drift_rejected(self):
        for mutate in [lambda m:m['required_success_bindings'].pop(),
                       lambda m:m['required_success_bindings'].append(m['required_success_bindings'][0]),
                       lambda m:m['required_success_bindings'][0].update(role='wrong_role'),
                       lambda m:m['required_success_bindings'][0].update(selector='wrong_harness'),
                       lambda m:m['required_success_bindings'][0]['source'].update(sha256='0'*64),
                       lambda m:m['required_success_bindings'][0].update(expected_description='wrong'),
                       lambda m:m['required_success_bindings'][0].update(observed_s108_property_ids=['guessed.assertion.1']),
                       lambda m:m['supplemental_label_sites'][1].update(applies=False)]:
            m=copy.deepcopy(self.manifest);mutate(m)
            with self.assertRaises(AssertionError):s.validate_map(m,self.request)

    def fixture(self,e):
        # Deliberately opaque ID, not a guessed future property ordinal.
        return {'std_sha':self.manifest['std_sha'],'std_tree':self.manifest['std_tree'],
                'tool_sha':self.manifest['tool_sha'],'row_id':e['row_id'],'request_sha256':self.digest,
                'source_sha256':e['source']['sha256'],'selector':e['selector'],'state':'COMPLETE',
                'properties':[{'id':e['selector']+'.opaque-fixture-id','class':'assertion','status':'SUCCESS',
                    'description':e['expected_description'],'file':e['source']['file'],
                    'line':e['source']['allowed_property_lines'][0]}]}

    def test_every_new_label_interface_and_missing_duplicate_role_status_harness_source(self):
        entries=[e for e in self.manifest['required_success_bindings'] if e['binding_kind']=='EXACT_ROLE_LABEL']
        for e in entries:
            envelope=self.fixture(e)
            self.assertEqual(s.label_fixture(e,envelope,self.manifest,self.digest)['binding'],'EXACT_LABEL_INTERFACE_MATCH')
            for mutation in [None, [], {}, {**envelope,'properties':None}, {**envelope,'state':'NOT_RUN'},
                    {**envelope,'state':'PARTIAL'}, {**envelope,'state':'TIMEOUT'},
                    {**envelope,'std_sha':'0'*40}, {**envelope,'std_tree':'0'*40},
                    {**envelope,'tool_sha':'0'*40}, {**envelope,'row_id':'other-root'},
                    {**envelope,'request_sha256':'0'*64},
                    {**envelope,'source_sha256':'0'*64}, {**envelope,'selector':'wrong'},
                    {**envelope,'properties':[]},
                    {**envelope,'properties':envelope['properties']*2},
                    {**envelope,'properties':[None]}]:
                self.assertEqual(s.label_fixture(e,mutation,self.manifest,self.digest)['binding'],'UNKNOWN')
            for key,values in {'id':[None,'other::root.opaque-id'], 'class':['cover','unreachable',None],
                    'description':['wrong::role',s.PLACEHOLDER,None],
                    'status':['FAILURE','UNREACHABLE','UNDETERMINED','UNKNOWN','NOT_RUN',None],
                    'file':['wrong.rs',None], 'line':[0,True,None,'1']}.items():
                for value in values:
                    bad=copy.deepcopy(envelope);bad['properties'][0][key]=value
                    self.assertEqual(s.label_fixture(e,bad,self.manifest,self.digest)['binding'],'UNKNOWN',(e['row_id'],key,value))
            bad=copy.deepcopy(envelope)
            bad['properties'].append({**bad['properties'][0],'description':'other::role'})
            self.assertEqual(s.label_fixture(e,bad,self.manifest,self.digest)['binding'],'UNKNOWN')
        legacy=next(e for e in self.manifest['required_success_bindings'] if e['binding_kind'].startswith('EXACT_SUCCESS_SEMANTIC'))
        self.assertEqual(s.label_fixture(legacy,self.fixture(legacy),self.manifest,self.digest)['binding'],'UNKNOWN')

    def test_equivalence_check_detects_operand_branch_cover_order_domain_and_negative_drift(self):
        base='''macro_rules! smoke {
fn $name() {
 kani::assume(n <= 3);
 assert!(enabled::<T, F>(), "S1_ENTRY_MODEL_ENABLED");
 if n == 1 { assert!(post(before, &v), "S1_N1_VALUE_UNCHANGED"); }
 kani::cover(n == 0, "return");
}
}
fn negative() { assert!(false, "negative oracle"); }
'''
        candidate=base.replace('assert!(enabled::<T, F>(), "S1_ENTRY_MODEL_ENABLED")',
            'kani::assert(enabled::<T, F>(), concat!(stringify!($name), "::model_enabled"))').replace(
            'assert!(post(before, &v), "S1_N1_VALUE_UNCHANGED")',
            'kani::assert(post(before, &v), concat!(stringify!($name), "::n1_value_unchanged"))')
        self.assertEqual(s.equivalent(base,candidate,{'smoke':2}),{'smoke':2})
        for bad in [candidate.replace('n <= 3','n <= 2'), candidate.replace('n == 1','n == 0'),
                    candidate.replace('post(before, &v)','true'), candidate.replace('cover(n == 0','cover(false'),
                    candidate.replace('assert!(false','assert!(true'),
                    candidate.replace('kani::assume(n <= 3);',''),
                    candidate.replace('kani::assume(n <= 3);','kani::cover(n == 0, "return");').replace(
                        'kani::cover(n == 0, "return");\n}', 'kani::assume(n <= 3);\n}'),
                    candidate.replace('::model_enabled','::wrong_role'),
                    candidate.replace('kani::cover(n == 0, "return");','kani::cover(n == 0, "return"); kani::assume(false);')]:
            with self.assertRaises(AssertionError):s.equivalent(base,bad,{'smoke':2})


if __name__=='__main__':unittest.main()
