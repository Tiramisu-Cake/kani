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
        memory = patch.object(c, 'available_bytes', return_value=16*1024**3)
        memory.start()
        self.addCleanup(memory.stop)
        self.req, roots = c.load()
        self.row = roots[0]
        self.execution = {'exit':0, 'stop':None}
        self.data = dict(schema_version='0.1.0', kani_commit=c.KANI, kani_commit_dirty=False,
            target=self.req['target'], harness_timeout_s=600, run_state='COMPLETE', outcome={'kind':'COMPLETED'},
            enabled_unstable_features=sorted(self.req['organizer_features']+['unstable-options','valid-value-checks','export-json']),
            configuration={'checks':dict(memory_safety=True,overflow=True,unwinding=True,undefined_function=True,
                assertion_reach_checks=True,ignore_global_asm=False,extra_pointer_checks=False,assert_contracts=False,prove_safety_only=False),
                'cbmc_args':['--object-bits','12'],'coverage_enabled':False},
            harness_selection=dict(requested_filters=[self.row['selector']],exact=True,unmatched_filters=[],matched_count=1),
            harnesses=[dict(contract=None,name=self.row['selector'],crate_name='core',is_automatically_generated=False,
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
        argv = c.argv_for(self.req, [self.row], Path('/tool/scripts/kani'), Path('/target'), Path('/out'))
        self.assertEqual(argv[1], 'verify-std')
        self.assertEqual(argv[argv.index('--harness') + 1], self.row['selector'])
        self.assertIn('--exact', argv)

    def test_argv_has_only_frozen_semantics_and_no_cfg(self):
        argv=c.argv_for(self.req,[self.row],Path('/export/scripts/kani'),Path('/target'),Path('/out.json'))
        self.assertEqual(argv[-3:],['--cbmc-args','--object-bits','12'])
        self.assertNotIn('--default-unwind',argv)
        self.assertNotIn('autoharness',argv)
        with patch.dict(os.environ,{'RUSTFLAGS':'--cfg kani_smallsort_controls','KANI_FLAGS':'bad','CARGO_ENCODED_RUSTFLAGS':'bad'}):
            env=c.clean_env()
            self.assertNotIn('RUSTFLAGS',env); self.assertNotIn('KANI_FLAGS',env)

    def batch_fixture(self):
        _, rows = c.load()
        rows = copy.deepcopy(rows[:2])
        data = copy.deepcopy(self.data)
        other = copy.deepcopy(data['harnesses'][0])
        other['name'] = rows[1]['selector']
        data['harnesses'].append(other)
        data['harness_selection'].update(requested_filters=[r['selector'] for r in rows], matched_count=2)
        return rows, data

    def test_batch_mixed_failure_timeout_reordered_partial_and_binding(self):
        rows, data = self.batch_fixture()
        h = data['harnesses'][1]
        p = dict(id='p.1', description="Kani currently doesn't support checking validity of `copy_nonoverlapping` for `u8`",
                 **{'class':'unsupported_construct'}, status='FAILURE')
        h.update(outcome={'kind':'COMPLETED','verdict':'FAILURE'},n_failed=1,failed_properties=[p],unsupported_constructs=[p])
        h['checks'].update(success=0,failure=['p.1'])
        execution = dict(exit=1,stop=None)
        data['harnesses'].reverse()  # Results order is source order, not selector order.
        self.assertEqual(c.classify(data, rows[0], execution, self.req, rows)['classification'], 'PASS')
        self.assertEqual(c.classify(data, rows[1], execution, self.req, rows)['classification'], 'copy Unsupported')
        h['outcome'] = {'kind':'TIMEOUT'}
        self.assertTrue(c.classify(data, rows[0], execution, self.req, rows)['complete'])
        self.assertFalse(c.classify(data, rows[1], execution, self.req, rows)['complete'])
        data['harnesses'].remove(h); data['run_state']='PARTIAL'
        self.assertTrue(c.classify(data, rows[0], execution, self.req, rows)['complete'])
        self.assertFalse(c.classify(data, rows[1], execution, self.req, rows)['complete'])
        data['harnesses'].append(copy.deepcopy(data['harnesses'][0]))
        self.assertFalse(c.classify(data, rows[0], execution, self.req, rows)['complete'])
        for value in (None, {}, [], False):
            altered=copy.deepcopy(self.data); altered['harnesses'][0]['contract']=value
            result=c.classify(altered,self.row,self.execution,self.req)
            self.assertEqual(result['complete'],value is None)
        self.data['harness_timeout_s']=60
        self.assertFalse(self.classify()['complete'])

    def test_one_group_for_all235_argv_and_orchestration_error_exports(self):
        from types import SimpleNamespace
        rows, data = self.batch_fixture()
        _, allrows = c.load()
        argv=c.argv_for(self.req,allrows,Path('/bin/kani'),Path('/target'),Path('/export'))
        self.assertEqual(argv.count('verify-std'),1)
        self.assertEqual(argv.count('--harness'),235)
        self.assertEqual(argv.count('--export-json'),1)
        self.assertEqual(argv[argv.index('--harness-timeout')+1],'600s')
        for case in ('valid','missing','null','malformed','wrong-type','oversize','exception'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                root=Path(td); out=root/'receipts'; out.mkdir()
                (out/'binary-hashes.json').write_text('{}')
                args=SimpleNamespace(out=str(out),std=str(root/'std'),export=str(root/'export'))
                def fake_guard(argv,cwd,seconds,req,marker,compile_receipt):
                    self.assertEqual(seconds,req['compile_seconds']+2*600)
                    self.assertEqual(req['root_rss_bytes'],req['aggregate_rss_bytes'])
                    self.assertEqual(argv.count('--harness'),2)
                    if case=='valid': marker.write_text(json.dumps(data))
                    elif case=='null': marker.write_text('null')
                    elif case=='wrong-type': marker.write_text('[]')
                    elif case=='malformed': marker.write_text('{')
                    elif case=='oversize': marker.write_text('x'*(req['export_cap_bytes']+1))
                    return dict(exit=None if case=='exception' else 0,stop='SPAWN_ERROR' if case=='exception' else None,
                                exception='fixture' if case=='exception' else None,compile={'status':'fixture'})
                with patch.dict(os.environ,{'GITHUB_ACTIONS':'true'}), patch.object(c,'bind',return_value={}), \
                     patch.object(c,'binary_hashes',return_value={}), patch.object(c,'guarded',side_effect=fake_guard) as guard:
                    c.run_census(args,self.req,rows)
                self.assertEqual(guard.call_count,1)
                self.assertTrue((out/'group.json').exists())
                self.assertTrue((out/'std-compile.json').exists())
                receipts=[json.loads((out/('root-%03d.json'%r['id'])).read_text()) for r in rows]
                self.assertTrue(all(r['complete']==(case=='valid') for r in receipts))
                self.assertTrue(all(r['per_root_rss_bytes']=='UNKNOWN' for r in receipts))
                self.assertFalse((root/'export-b-group.json').exists())

    def test_compile_separate_cap_marker_receipt_and_group_timeout(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); marker=root/'marker.json'; receipt=root/'compile.json'
            req=dict(self.req,compile_seconds=.12)
            def run(code, seconds=2):
                return c.guarded([sys.executable,'-c',code],root,seconds,req,marker,receipt)
            timed=run('import time; print("compile",flush=True); time.sleep(3)')
            self.assertEqual(timed['stop'],'COMPILE_TIMEOUT')
            self.assertEqual(timed['compile']['status'],'INCOMPLETE')
            self.assertIn('compile',timed['compile']['diagnostic_head'])
            self.assertEqual(json.loads(receipt.read_text()),timed['compile'])
            code='from pathlib import Path; import time; print("compile",flush=True); Path("marker.json").write_text("{}"); time.sleep(.4)'
            done=run(code)
            self.assertEqual(done['exit'],0)
            self.assertEqual(done['compile']['status'],'MARKER_OBSERVED')
            self.assertIsNone(done['stop'])
            marker.unlink()
            group=run(code, .2)
            self.assertEqual(group['stop'],'TIMEOUT')
            self.assertEqual(group['compile']['status'],'MARKER_OBSERVED')
            self.assertLessEqual(len(group['compile']['diagnostic_head'].encode()),4096)

    def test_no_memory_and_wrapper_exception_preserve_original_state(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td)
            with patch.object(c,'available_bytes',return_value=1024), patch.object(c.subprocess,'Popen') as spawn:
                result=c.guarded([sys.executable,'-c','pass'],root,1,self.req)
                self.assertEqual(result['stop'],'MEMORY_UNAVAILABLE')
                self.assertIsNone(result['exit'])
                spawn.assert_not_called()
            with patch.object(c,'rss_groups',side_effect=RuntimeError('sampling fixture')):
                result=c.guarded([sys.executable,'-c','import time; time.sleep(3)'],root,1,self.req)
                self.assertEqual(result['stop'],'WRAPPER_EXCEPTION')
                self.assertIn('sampling fixture',result['exception'])
                self.assertEqual(result['exit'],-9)
            for values in (['bad'],[self.req['std']['sha'],'bad'],
                           [self.req['std']['sha'],self.req['std']['tree'],' M library/core/src/lib.rs']):
                with patch.object(c,'git',side_effect=values):
                    with self.assertRaises(AssertionError): c.bind(root,self.req['std'])


if __name__=='__main__':
    unittest.main()
