# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Isolated synthetic service tests. Never invokes a compiler or verifier."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import census as c


class CensusTests(unittest.TestCase):
    def setUp(self):
        self.req, roots = c.load()
        self.row = roots[0]
        self.execution = {'exit':0, 'stop':None}
        self.data = dict(schema_version='0.1.0', kani_commit=c.KANI, kani_commit_dirty=False,
            target=self.req['target'], run_state='COMPLETE', outcome={'kind':'COMPLETED'},
            enabled_unstable_features=sorted(self.req['organizer_features']+['unstable-options','valid-value-checks','export-json']),
            configuration={'checks':dict(memory_safety=True,overflow=True,unwinding=True,undefined_function=True,
                assertion_reach_checks=True,ignore_global_asm=False,extra_pointer_checks=False,assert_contracts=False,prove_safety_only=False),
                'cbmc_args':['--object-bits','12'],'coverage_enabled':False},
            harness_selection=dict(requested_filters=[self.row['selector']],exact=True,unmatched_filters=[],matched_count=1),
            harnesses=[dict(name=self.row['selector'],crate_name='core',is_automatically_generated=False,
                outcome={'kind':'COMPLETED','verdict':'SUCCESS'},n_properties=2,n_failed=0,failed_properties=[],unsupported_constructs=[],
                checks=dict(total=1,success=1,failure=[],unreachable=[],undetermined=[],error=[],unknown=[],other=[]),
                covers=dict(total=1,satisfied=['read-cover'],unsatisfiable=[],unreachable=[],undetermined=[],error=[],unknown=[],other=[]))])

    def classify(self):
        return c.classify(self.data,self.row,self.execution,self.req)

    def fail(self,desc,cls='unsupported_construct'):
        h=self.data['harnesses'][0]
        p=dict(id='p.1',description=desc,**{'class':cls},status='FAILURE')
        h.update(outcome={'kind':'COMPLETED','verdict':'FAILURE'},n_failed=1,failed_properties=[p],unsupported_constructs=[p] if cls=='unsupported_construct' else [])
        h['checks'].update(success=0,failure=['p.1'])
        self.execution['exit']=1

    def test_pass_preserves_checks_and_reads(self):
        out=self.classify()
        self.assertEqual(out['classification'],'PASS')
        self.assertEqual(out['harness']['covers']['satisfied'],['read-cover'])

    def test_unsupported_families(self):
        for text,expected in [('copy_nonoverlapping','copy Unsupported'),('mutable cast','casts'),('transmute','other Unsupported')]:
            self.fail("Kani currently doesn't support checking validity of `"+text+"` for `u8`")
            self.assertEqual(self.classify()['classification'],expected)

    def test_intent_is_explicit_not_inferred(self):
        self.fail('Undefined Behavior: Invalid value of type `bool`','assertion')
        self.assertEqual(self.classify()['classification'],c.CATCHALL)
        self.assertFalse(self.classify()['complete'])
        self.row=dict(self.row,intended_invalid_value=True)
        self.assertEqual(self.classify()['classification'],'intended invalid-value failure')

    def test_partial_timeout_crash_null_wrong_type_not_run(self):
        original=copy.deepcopy(self.data)
        for value in [None,[],{},'SUCCESS',False]:
            self.assertFalse(c.classify(value,self.row,self.execution,self.req)['complete'])
        mutations=[('run_state','PARTIAL'),('run_state','INCOMPLETE'),('run_state','NOT_RUN'),('harnesses',None),('harnesses',[])]
        for k,v in mutations:
            self.data=copy.deepcopy(original); self.data[k]=v
            self.assertFalse(self.classify()['complete'])
        self.data=copy.deepcopy(original)
        self.data['harnesses'][0]['outcome']={'kind':'TIMEOUT'}
        self.assertFalse(self.classify()['complete'])
        self.data['harnesses'][0]['outcome']={'kind':'CRASHED','code':-9}
        self.assertFalse(self.classify()['complete'])

    def test_source_stage_target_selection_flags_mismatch(self):
        original=copy.deepcopy(self.data)
        for k,v in [('kani_commit','0'*40),('kani_commit_dirty',True),('target','other'),('schema_version','future')]:
            self.data=copy.deepcopy(original); self.data[k]=v
            self.assertFalse(self.classify()['complete'])
        for path,value in [('matched_count',0),('exact',False),('requested_filters',['wrong']),('unmatched_filters',['wrong'])]:
            self.data=copy.deepcopy(original); self.data['harness_selection'][path]=value
            self.assertFalse(self.classify()['complete'])
        self.data=copy.deepcopy(original); self.data['enabled_unstable_features'].append('uninit-checks')
        self.assertFalse(self.classify()['complete'])
        self.data=copy.deepcopy(original); self.data['configuration']['checks']['unwinding']=False
        self.assertFalse(self.classify()['complete'])
        self.data=copy.deepcopy(original); self.data['harnesses'][0]['is_automatically_generated']=True
        self.assertFalse(self.classify()['complete'])

    def test_checks_and_exit_disagreement(self):
        self.execution['exit']=1
        self.assertFalse(self.classify()['complete'])
        self.execution['exit']=0; self.execution['stop']='OUTPUT_LIMIT'
        self.assertFalse(self.classify()['complete'])
        self.execution['stop']=None; self.data['harnesses'][0]['checks']['total']=20
        self.assertFalse(self.classify()['complete'])

    def test_malformed_buckets_and_boolean_numbers_cannot_pass(self):
        original=copy.deepcopy(self.data)
        for group,fields in [('checks',['failure','unreachable','undetermined','error','unknown','other']),('covers',['satisfied','unsatisfiable','unreachable','undetermined','error','unknown','other'])]:
            for key in fields:
                for value in ['',None,{},0,False]:
                    self.data=copy.deepcopy(original)
                    h=self.data['harnesses'][0]
                    h[group][key]=value
                    if group=='covers':
                        h['covers']['total']=0; h['n_properties']=1
                    result=self.classify()
                    self.assertFalse(result['complete'],(group,key,value))
        for key in original['configuration']['checks']:
            self.data=copy.deepcopy(original)
            self.data['configuration']['checks'][key]=int(self.data['configuration']['checks'][key])
            self.assertFalse(self.classify()['complete'],key)
        self.data=copy.deepcopy(original); self.data['harness_selection']['matched_count']=True
        self.assertFalse(self.classify()['complete'])
        self.data=copy.deepcopy(original); self.data['harnesses'][0]['n_properties']=True
        self.assertFalse(self.classify()['complete'])

    def test_observed_unsupported_survives_unknown_checks(self):
        self.fail("Kani currently doesn't support checking validity of `copy_nonoverlapping` for `u8`")
        h=self.data['harnesses'][0]
        h['checks']['unknown']=['p.2']; h['checks']['total']+=1; h['n_properties']+=1
        result=self.classify()
        self.assertEqual(result['classification'],'copy Unsupported')
        self.assertFalse(result['complete'])
        self.assertEqual(result['harness']['checks']['unknown'],['p.2'])
        self.assertEqual(len(result['harness']['failed_properties']),1)

    def test_binary_hash_snapshot_detects_changes_and_missing(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); folder=root/'target/kani/bin'; folder.mkdir(parents=True)
            with self.assertRaises(AssertionError): c.binary_hashes(root)
            exe=folder/'kani-driver'; exe.write_bytes(b'fixture-v1')
            first=c.binary_hashes(root)
            self.assertEqual(first,c.binary_hashes(root))
            exe.write_bytes(b'fixture-v2')
            self.assertNotEqual(first,c.binary_hashes(root))

    def test_missing_receipt_fallback_and_partial(self):
        with tempfile.TemporaryDirectory() as td:
            out=Path(td)
            result=c.finalize(out,[self.row],'success')
            self.assertEqual(result['status'],'PARTIAL')
            self.assertEqual(result['counts'],{c.CATCHALL:1})
            self.assertEqual(json.loads(next(out.glob('root-*.json')).read_text())['runtime_proof_status'],'NOT_RUN')

    def test_guard_original_exits_exception_timeout_output_rss(self):
        req=dict(self.req,stdout_cap_bytes=1024)
        with tempfile.TemporaryDirectory() as td:
            run=lambda code, seconds=2: c.guarded([sys.executable,'-c',code],Path(td),seconds,req)
            self.assertEqual(run('raise SystemExit(7)')['exit'],7)
            self.assertEqual(run('print("success")')['exit'],0)
            timed=run('import time; time.sleep(3)',.05)
            self.assertEqual(timed['stop'],'TIMEOUT'); self.assertEqual(timed['signal'],9)
            self.assertEqual(run('print("x"*2048)')['stop'],'OUTPUT_LIMIT')
            with patch.object(c,'rss_groups',side_effect=lambda groups:{p:7*1024**3 for p in groups}):
                self.assertEqual(run('import time; time.sleep(3)')['stop'],'RSS_LIMIT')
            failed=c.guarded(['/does-not-exist'],Path(td),1,req)
            self.assertEqual(failed['stop'],'SPAWN_ERROR'); self.assertIsNone(failed['exit'])
            self.assertIsNotNone(failed['exception'])

    def test_pprime_and_no_inventory_phase(self):
        import ast
        self.assertEqual(c.STD, 'c5ff36ff433692140605891f646043f991db05de')
        self.assertEqual(self.req['std']['tree'], '1302063846873aa300f8bac64fe09e8a3ed1280f')
        self.assertEqual(self.req['kani']['repository'], 'model-checking/kani')
        tree = ast.parse(Path(c.__file__).read_text())
        literals = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertFalse(set(literals) & {'list', 'metrics', 'run-kani.sh'})
        argv = c.argv_for(self.req, self.row, Path('/tool/scripts/kani'), Path('/target'), Path('/out'))
        self.assertEqual(argv[1], 'verify-std')
        self.assertEqual(argv[argv.index('--harness') + 1], self.row['selector'])
        self.assertIn('--exact', argv)

    def test_argv_has_only_frozen_semantics_and_no_cfg(self):
        argv=c.argv_for(self.req,self.row,Path('/export/scripts/kani'),Path('/target'),Path('/out.json'))
        self.assertEqual(argv[-3:],['--cbmc-args','--object-bits','12'])
        self.assertNotIn('--default-unwind',argv)
        self.assertNotIn('autoharness',argv)
        with patch.dict(os.environ,{'RUSTFLAGS':'--cfg kani_smallsort_controls','KANI_FLAGS':'bad','CARGO_ENCODED_RUSTFLAGS':'bad'}):
            env=c.clean_env()
            self.assertNotIn('RUSTFLAGS',env); self.assertNotIn('KANI_FLAGS',env)


if __name__=='__main__':
    unittest.main()
