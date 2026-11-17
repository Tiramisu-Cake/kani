# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Pinned source extraction and exact negative-ID regression; no real verifier."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import negative_oracle
import oracle_source as s

HERE=Path(__file__).resolve().parent
MODEL='library/core/src/slice/sort/shared/smallsort/verify/sorting_model_controls.rs'
SMALLSORT='library/core/src/slice/sort/shared/smallsort.rs'


def fixture_sources():
    sources={('production',rel):(HERE/'fixtures'/('s108r1-'+Path(rel).name+'.txt')).read_bytes()
             for rel in (MODEL,SMALLSORT)}
    with tempfile.TemporaryDirectory() as tmp:
        repo=Path(tmp);subprocess.run(['git','init','-q',str(repo)],check=True)
        path=repo/SMALLSORT;path.parent.mkdir(parents=True);path.write_bytes(sources['production',SMALLSORT])
        def git(*args):return subprocess.check_output(['git','-C',str(repo),*args])
        for variant in ('activation-default','activation-override'):
            git('read-tree','--empty');git('add','--',SMALLSORT)
            git('apply','--cached','--check',str(HERE/(variant+'.patch')))
            git('apply','--cached',str(HERE/(variant+'.patch')))
            sources[variant,SMALLSORT]=git('show',':'+SMALLSORT)
    return sources


def harness(oracle):
    pid=oracle['property_id']
    return {'name':oracle['selector'],'outcome':{'kind':'COMPLETED','verdict':'FAILURE'},
        'n_failed':1,'n_properties':1,'checks':{'total':1,'success':0,'failure':[pid],
            'unreachable':[],'undetermined':[],'error':[],'unknown':[],'other':[]},
        'covers':{'total':0,'satisfied':[],'unsatisfiable':[],'unreachable':[],
            'undetermined':[],'error':[],'unknown':[],'other':[]},'unsupported_constructs':[],
        'failed_properties':[{'id':pid,'file':oracle['export_file'],'line':str(oracle['line']),
                              'class':'assertion','status':'FAILURE'}]}


class OracleSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.request=json.loads((HERE/'CI-REQUEST.json').read_bytes())
        cls.baselines=json.loads((HERE/'ORACLE-SOURCES.json').read_bytes())
        cls.sources=fixture_sources()

    def test_all_eight_declared_oracles_from_source(self):
        checked=s.validate(self.request,self.sources,self.baselines)
        self.assertEqual(len(checked),8)
        self.assertEqual(sum(x['closure_span'] is not None for x in checked),2)
        for row in self.request['rows']:
            if row.get('oracle'):
                self.assertTrue(negative_oracle.matches(harness(row['oracle']),row['oracle']))
        source=self.sources['production',MODEL].decode()
        for root in ('activation_descending_rejected','activation_effectful_rejected'):
            span=s.closure_span(source,root)
            line=source.splitlines()[span['start_line']-1]
            self.assertEqual(line[span['start_column']-1:span['end_column']-1],span['text'])
            self.assertEqual(span['text'],'|a: &u8, b: &u8|')

    def test_original_stale_lines_columns_and_id_tail_rejected(self):
        for rid,stale_line in [('activation_descending_rejected',100),('activation_effectful_rejected',106)]:
            for change in ('old-lines','start-column','end-column','wrong-source-path','wrong-ordinal'):
                bad=copy.deepcopy(self.request)
                o=next(r['oracle'] for r in bad['rows'] if r['id']==rid)
                m=s.CLOSURE_COORD.search(o['property_id'])
                if change=='old-lines':
                    coords=f"{stale_line}:{m['sc']}: {stale_line}:{m['ec']}"
                    o['property_id']=o['property_id'][:m.start('sl')]+coords+o['property_id'][m.end('ec'):]
                elif change=='wrong-source-path':o['property_id']=o['property_id'].replace('export/library/','wrong/library/')
                elif change=='wrong-ordinal':o['property_id']=o['property_id'].removesuffix('.assertion.1')+'.assertion.2'
                else:
                    group='sc' if change=='start-column' else 'ec'
                    o['property_id']=o['property_id'][:m.start(group)]+str(int(m[group])+1)+o['property_id'][m.end(group):]
                # Coherent observed/declared wrong IDs still fail source preflight.
                self.assertTrue(negative_oracle.matches(harness(o),o))
                with self.subTest(row=rid,mutation=change),self.assertRaises(AssertionError):
                    s.validate(bad,self.sources,self.baselines)
                actual=next(r['oracle'] for r in self.request['rows'] if r['id']==rid)
                self.assertFalse(negative_oracle.matches(harness(o),actual))

    def test_coherent_shifted_source_hash_context_and_id_rejected(self):
        bad=copy.deepcopy(self.request);sources=self.sources.copy();baseline=copy.deepcopy(self.baselines)
        source=sources['production',MODEL].decode()
        shifted=source.replace('#[kani::proof]\nfn activation_descending_rejected()',
            '\n'*5+'#[kani::proof]\nfn activation_descending_rejected()',1)
        self.assertNotEqual(source,shifted)
        sources['production',MODEL]=shifted.encode();digest=s.sha(shifted.encode())
        bad['changed_file_sha256'][MODEL]=digest
        for row in bad['rows']:
            o=row.get('oracle')
            if not o or o['file']!=MODEL:continue
            if o['line']>93:o['line']+=5
            o['source_sha256']=digest
            o['property_id']=s.repair_id(o['property_id'],shifted,row['selector'].rsplit('::',1)[-1])
            # Update redundant metadata too; independent canonical source pins stay.
            baseline['oracles'][row['id']]['oracle_without_id']={k:v for k,v in o.items() if k!='property_id'}
        for binding in bad['source_bindings'].values():
            if binding['file']==MODEL:binding['sha256']=digest
        with self.assertRaisesRegex(AssertionError,'canonical source hash mismatch'):
            s.validate(bad,sources,baseline)
        shifted=source.replace('    require_active(&[0u8, 1], &|','       require_active(&[0u8, 1], &|',1)
        original=s.closure_span(source,'activation_descending_rejected')
        moved=s.closure_span(shifted,'activation_descending_rejected')
        self.assertEqual(moved['start_column'],original['start_column']+3)
        self.assertEqual(moved['end_column'],original['end_column']+3)

    def test_all_oracle_context_identity_class_status_and_sole_failure_fail_closed(self):
        for row in self.request['rows']:
            if not row.get('oracle'):continue
            for field,value in [('property_id',row['oracle']['property_id']+'.wrong'),
                    ('source_line','assert!(true);'),('source_sha256','0'*64),('line',1),
                    ('class','cover'),('selector','wrong-root')]:
                bad=copy.deepcopy(self.request);o=next(x['oracle'] for x in bad['rows'] if x['id']==row['id']);o[field]=value
                with self.subTest(row=row['id'],field=field),self.assertRaises(AssertionError):
                    s.validate(bad,self.sources,self.baselines)
            o=row['oracle'];h=harness(o)
            for mutate in [lambda x:x['failed_properties'][0].update(status='SUCCESS'),
                    lambda x:x['failed_properties'][0].update(line='1'),
                    lambda x:x['checks'].update(failure=[o['property_id'],'second.assertion.1']),
                    lambda x:x.update(n_failed=2),lambda x:x.update(name='wrong-root'),
                    lambda x:x.update(outcome={'kind':'COMPLETED','verdict':'SUCCESS'})]:
                wrong=copy.deepcopy(h);mutate(wrong)
                self.assertFalse(negative_oracle.matches(wrong,o))
        for missing in (None,{},[]):
            bad=copy.deepcopy(self.request);next(r for r in bad['rows'] if r.get('oracle'))['oracle']=missing
            with self.assertRaises((AssertionError,TypeError,KeyError)):s.validate(bad,self.sources,self.baselines)


if __name__=='__main__':unittest.main()
