# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""S3 source and service controls. Only small Python children, never Rust/Kani."""
import copy,errno,json,os,signal,sys,tempfile,time,unittest
from pathlib import Path
from unittest import mock
import runner as r
import s4p2r2_profile as p
import s4p2r2_policy as policy
import s4p2r2_campaign as c
import s3_runtime as rt
import s3_snapshots as snapshots
import s4p2r2_cfg_pfc as cfg
import s4p2r2_ordinary_contracts as ordinary
import s4p2r2_lexical_bindings as lexical
import check_package,pack_evidence
import test_runner as fixtures
HERE=Path(__file__).resolve().parent

def inventory(row):
    records=[]
    for i,role in enumerate(row['roles']):
        # Arbitrary producer IDs, deliberately never inferred from source ordinals.
        records.append({'id':'actual-instance.assertion.'+str(91+i) if role['class']=='assertion' else 'actual-instance.cover.'+str(41+i),
            'class':role['class'],'description':role['description'],'file':'/fresh/export/'+role['file'],
            'line':str(role['line']),'status':role['status']})
    checks=[x for x in records if x['class']!='cover'];covers=[x for x in records if x['class']=='cover'];failed=[x for x in checks if x['status']=='FAILURE']
    h={'name':row['selector'],'outcome':{'kind':'COMPLETED','verdict':'FAILURE' if failed else 'SUCCESS'},'unsupported_constructs':[],
       'n_properties':len(records),'n_failed':len(failed),'failed_properties':copy.deepcopy(failed),
       'checks':{'total':len(checks),'success':len(checks)-len(failed),'failure':[x['id'] for x in failed],**{k:[] for k in ('unreachable','undetermined','error','unknown','other')}},
       'covers':{'total':len(covers),'satisfied':[x['id'] for x in covers],**{k:[] for k in ('unsatisfiable','unreachable','undetermined','error','unknown','other')}}}
    return {'state':'RECORDED_OBSERVATION','outcome':'RECORDED','source_root':'/fresh/export','harness':h},{'name':row['selector'],'properties':records}


def supervision():
    worker={'pid':1,'pgid':1,'ppid':999,'start_ticks':11,'state':'S'}
    driver={'pid':2,'pgid':2,'ppid':1,'start_ticks':22,'state':'S'}
    return {'worker_pid':1,'worker_initial_identity':worker,'worker_exit':0,'cutoff':None,'supervisor_error':None,
       'containment':{'verified':True,'observed':[worker,driver]},'orphan_survivors_at_worker_exit':[]}


def binary():
    return {'required_hashes_present':True,'binaries':{name:{'path':'/tool/'+name,'sha256':'a'*64} for name in ('kani_driver','kani_compiler','cbmc')}}


def synthetic_capture(std,tool,req,context,epoch,shutdown=None):
    return {'schema':'ch8-s3-protected-snapshot-v1','context':copy.deepcopy(context),'epoch':epoch,'monotonic':time.monotonic(),
       'source':{k:req[k] for k in ('std_sha','std_tree','tool_sha','tool_tree','changed_file_sha256')},
       'control':{'sha':'synthetic-control','tree':'synthetic-tree','parent':req['control_parent'],'dirty':''},
       'binaries':binary(),'request_sha256':r.sha256(r.REQUEST_PATH),'errors':[],
       'state':'INCOMPLETE' if epoch.endswith('.post') and not (shutdown or {}).get('verified') else 'COMPLETE','shutdown':shutdown}


class RoleTests(unittest.TestCase):
    def test_literal_intended_roles_all_seven_dynamic_producer_ids(self):
        for row in r.load_request()['rows']:
            parsed,props=inventory(row);self.assertTrue(policy.expected_observation(row,parsed,props),row['id'])
    def test_missing_duplicate_wrong_class_status_file_line_cfg_and_unrelated_failure(self):
        for row in r.load_request()['rows']:
            original,records=inventory(row)
            for case in ('missing','duplicate','description','class','status','file','line','null','partial','unrelated','unreachable','unsupported'):
                parsed,props=copy.deepcopy(original),copy.deepcopy(records)
                if case=='missing':props['properties'].pop()
                elif case=='duplicate':props['properties'].append(copy.deepcopy(props['properties'][0]))
                elif case in ('description','class','file','line'):props['properties'][0][case]='WRONG'
                elif case in ('status','unreachable'):props['properties'][0]['status']='UNREACHABLE'
                elif case=='null':props=None
                elif case=='partial':parsed['outcome']='UNKNOWN'
                elif case=='unrelated':props['properties'].append({'id':'unrelated.assertion.123','class':'assertion','status':'FAILURE'})
                elif case=='unsupported':parsed['harness']['unsupported_constructs']=[{'id':'unsupported'}]
                with self.subTest(root=row['id'],case=case):self.assertFalse(policy.expected_observation(row,parsed,props))
    def test_loop_source_instance_set_kept(self):
        row=r.load_request()['rows'][4];parsed,props=inventory(row);extra=copy.deepcopy(props['properties'][2]);extra['id']='fresh-instance.assertion.777';props['properties'].append(extra)
        parsed['harness']['n_properties']+=1;parsed['harness']['checks']['total']+=1;parsed['harness']['checks']['success']+=1
        self.assertTrue(policy.expected_observation(row,parsed,props))
        extra['line']='1';self.assertFalse(policy.expected_observation(row,parsed,props))






class CampaignTests(unittest.TestCase):
    def setUp(self):self.req=r.load_request()
    def emit(self,out,rid,case='ok'):
        row=c.group(self.req,rid)['rows'][0];name=row['selector'];gp=out/'groups'/('s3-'+rid)
        source={**c.identity(self.req),'changed_file_sha256':self.req['changed_file_sha256']}
        parsed,props=inventory(row)
        doc={'state':'COMPLETE','group':'s3-'+rid,'request_sha256':r.sha256(r.REQUEST_PATH),'source_before':source,'source_after':source,
            'tool_fingerprints_before':binary(),'tool_fingerprints_after':binary(),'binary_identity':'MATCH','snapshot_errors':[],
            'native_start_events':[{'selector':name,'monotonic':time.monotonic()}],'native_start_verified':True,
            'execution':{'original_exit_code':1 if row['expected']=='DETECTED' else 0,'stdout_bytes':1,'stderr_bytes':0,
                         'process_identity':{'pid':2,'pgid':2,'start_ticks':22}}}
        doc.update({k:self.req[k] for k in ('std_sha','std_tree','tool_sha','tool_tree')})
        doc['source_under_test']=r.source_under_test_record(self.req,'production',{},None)
        marker=gp/'synthetic-compile-marker.json'
        monitor=r.CompileMonitor(gp/'compile/receipt.json',marker,[name],180,identities={k:self.req[k] for k in ('std_sha','std_tree','tool_sha','tool_tree')})
        marker.write_text(json.dumps(fixtures.export(selector=name)))
        monitor.poll(.01,{})
        marker.unlink()
        result={**r._row_base(row,'OBSERVED'),'target':None,'group':'s3-'+rid,'outcome':'RECORDED','export':parsed}
        sup=supervision()
        if case=='timeout':
            sup.update(cutoff='slot_wall',worker_exit=-15)
            doc.update(state='IN_PROGRESS');doc.pop('source_after');doc.pop('tool_fingerprints_after');doc.pop('binary_identity')
            doc['execution'].update(original_exit_code=-15,signal=15)
            doc['execution_exception']={'type':'SyntheticInterruption','message':'original error retained'}
            result.update(outcome='UNKNOWN')
        elif case=='supervisor':sup.update(cutoff='supervisor_exception',supervisor_error={'operation':'sample.read_status','errno':errno.ESRCH,'type':'ProcessLookupError','traceback_tail':'original traceback'},worker_exit=-15)
        elif case=='row':result['selector']='wrong::root'
        elif case=='source':doc['source_after']={}
        elif case=='orphan':sup['containment']['verified']=False
        elif case=='native':doc['native_start_events']=[{'selector':'wrong'}]
        elif case=='role':props['properties'][0]['status']='UNREACHABLE'
        elif case=='output_unknown':doc['execution'].pop('stdout_bytes')
        elif case=='durable_late':sup['monotonic_start']=time.monotonic()-721
        c.atomic(gp/'receipt.json',doc);c.atomic(gp/'properties.json',{'harnesses':[props]});c.atomic(out/rid/'receipt.json',result)
        return sup
    def run_case(self,out,cases):
        launches=[]
        def invoke(std,tool,path,request,rid,limits,slot):
            launches.append(rid);return self.emit(path,rid,cases.get(rid,'ok'))
        with mock.patch.object(c.snapshots,'capture',side_effect=synthetic_capture):
            code=c.run_campaign(Path('/std'),Path('/tool'),out,self.req,invoker=invoke)
        return code,launches,c.read(out/'receipt.json')
    def test_serial_order_fresh_context_caps_and_all_seven(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);code,launches,terminal=self.run_case(out,{})
            self.assertEqual(code,0);self.assertEqual(launches,list(p.ORDER));self.assertEqual(len(c.sealed(out)),8)
            contexts=[c.read(out/'workers'/(rid+'-lifecycle.json'))['context'] for rid in p.ORDER]
            self.assertEqual(len({x['invocation_id'] for x in contexts}),8)
            self.assertEqual([x['rank'] for x in contexts],list(range(1,9)))
            self.assertTrue(all(x['proof_credit']=='NONE' for x in terminal['rows']))
            self.assertTrue(all(x['state']=='NOT_SELECTED' for x in terminal['s3_campaign']['unselected']))
            with self.assertRaises(c.GlobalFailure):c.run_campaign(Path('/std'),Path('/tool'),out,self.req)
    def test_interrupted_worker_durable_outer_after_preserves_original_exit(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);code,launches,terminal=self.run_case(out,{p.ORDER[1]:'timeout'})
            self.assertEqual(code,1);self.assertEqual(launches,list(p.ORDER))
            life=c.read(out/'workers'/(p.ORDER[1]+'-lifecycle.json'));self.assertEqual(life['post']['state'],'COMPLETE')
            gp=c.read(out/'groups'/('s3-'+p.ORDER[1])/'receipt.json');self.assertNotIn('source_after',gp);self.assertEqual(gp['execution']['original_exit_code'],-15);self.assertEqual(gp['execution_exception']['type'],'SyntheticInterruption')
            row=c.read(out/p.ORDER[1]/'receipt.json');self.assertEqual(row['outcome'],'UNKNOWN');self.assertEqual(row['invocation_signal'],15)
    def test_real_drift_unknown_containment_wrong_target_and_selector_global_stop(self):
        for case in ('source','orphan','row','native','supervisor','output_unknown'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as d:
                out=Path(d);code,launches,terminal=self.run_case(out,{p.ORDER[2]:case})
                self.assertEqual(code,1);self.assertEqual(launches,list(p.ORDER[:3]));self.assertTrue(terminal['stop_reason'])
                self.assertTrue(all(x['status']=='NOT_RUN' for x in terminal['rows'][3:]))
                prefix={rel:r.sha256(out/rel) for seal in c.sealed(out).values() for rel in seal['files']}
                c.fallback(out,self.req)
                self.assertEqual(prefix,{rel:r.sha256(out/rel) for rel in prefix})
                self.assertTrue((out/p.ORDER[2]/'unfinished-worker-receipt.json').exists())
    def test_missing_post_is_global_stop_and_no_rebaseline(self):
        for failure in ('absent','unreadable','drift'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as d:
                out=Path(d)
                def capture(std,tool,req,ctx,epoch,shutdown=None):
                    doc=synthetic_capture(std,tool,req,ctx,epoch,shutdown)
                    if epoch=='E2.post':
                        if failure=='absent':return None
                        if failure=='unreadable':doc.update(state='INCOMPLETE',errors=[{'operation':'snapshot.hash','errno':errno.EACCES}])
                        if failure=='drift':doc['binaries']['binaries']['cbmc']['sha256']='b'*64
                    return doc
                launches=[]
                def invoke(std,tool,path,req,rid,limits,slot):launches.append(rid);return self.emit(path,rid)
                with mock.patch.object(c.snapshots,'capture',side_effect=capture):
                    self.assertEqual(c.run_campaign(Path('/std'),Path('/tool'),out,self.req,invoker=invoke),1)
                self.assertEqual(launches,list(p.ORDER[:2]));self.assertEqual(c.read(out/'baseline.json')['binaries'],binary())
    def test_role_unreachable_rejects_without_historical_rewrite(self):
        frozen=r.sha256(HERE/'fixtures/r5-request.json')
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);code,_,_=self.run_case(out,{p.ORDER[2]:'role'});self.assertEqual(code,1)
            self.assertFalse(c.read(out/p.ORDER[2]/'receipt.json')['s3_expected_match'])
        self.assertEqual(r.sha256(HERE/'fixtures/r5-request.json'),frozen)
    def test_prefix_tamper_symlink_and_upload_only_seals(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);self.run_case(out,{p.ORDER[2]:'source'});prefix=c.sealed(out)
            pack_evidence.pack(out)
            import gzip,hashlib
            packed=json.loads(gzip.decompress((out/pack_evidence.NAME).read_bytes()))
            def reader(path):return packed['files'][str(path.relative_to(out))]['text'].encode()
            self.assertEqual(set(c.sealed(out,reader,list(prefix))),set(prefix))
            path=out/p.ORDER[0]/'receipt.json';path.write_text('{}')
            with self.assertRaises(c.GlobalFailure):c.sealed(out)
    def test_fallback_without_launch_explicit_not_run(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);c.fallback(out,self.req);terminal=c.read(out/'receipt.json')
            self.assertTrue(all(x['status']=='NOT_RUN' for x in terminal['rows']))
    def test_late_publication_keeps_supervision_lifecycle_and_seal_identical(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);code,_,_=self.run_case(out,{p.ORDER[2]:'durable_late'})
            self.assertEqual(code,1)
            rid=p.ORDER[2];row=c.read(out/rid/'receipt.json')
            self.assertTrue(row['durable_publication_cutoff']);self.assertEqual(row['outcome'],'UNKNOWN')
            sup=c.read(out/'workers'/(rid+'-supervision.json'))
            life=c.read(out/'workers'/(rid+'-lifecycle.json'))
            seal=c.read(out/'completed'/(rid+'.json'))
            self.assertEqual(sup,life['supervision']);self.assertEqual(sup,seal['supervision'])
            self.assertEqual(sup,row['s3_supervision']);self.assertIsNone(sup['cutoff'])
            self.assertFalse(seal['expected_match']);pack_evidence.pack(out)
            import gzip
            packed=json.loads(gzip.decompress((out/pack_evidence.NAME).read_bytes()))
            self.assertEqual(set(c.sealed(out,lambda path:packed['files'][str(path.relative_to(out))]['text'].encode())),set(p.ORDER))
    def test_fresh_prefix_and_aggregate_partial_capture_controls(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);(out/'old-evidence.json').write_text('{}')
            with self.assertRaisesRegex(c.GlobalFailure,'fresh prefix'):
                c.run_campaign(Path('/std'),Path('/tool'),out,self.req)
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);gp=out/'groups/partial';gp.mkdir(parents=True)
            c.atomic(gp/'receipt.json',{'state':'IN_PROGRESS'})
            (gp/'stdout.log').write_bytes(b'partial')
            self.assertEqual(c.usage(out)['stdout_bytes'],7)


class WorkflowTests(unittest.TestCase):
    def test_one_job_caps_stock_tool_and_ancestry_depths(self):
        doc=check_package.load_yaml((HERE.parent/'.github/workflows/ch8-s2.yml').read_text());check_package.check_scalar_types(doc)
        import s4p2r2_package
        self.assertEqual(s4p2r2_package.check_yaml(doc)['checkout_depths'],{'control':8,'export':6,'tool':2})
        for mutate in (lambda q:q['jobs']['s3_leaf']['steps'][2].update(**{'timeout-minutes':1}),lambda q:q['jobs']['s3_leaf']['steps'][9].update(run='echo wrong'),lambda q:q['jobs']['s3_leaf'].update(strategy={}),lambda q:q['permissions'].update(contents='write')):
            bad=copy.deepcopy(doc);mutate(bad)
            with self.assertRaises(AssertionError):s4p2r2_package.check_yaml(bad)
    def test_multi_root_legacy_entry_refused(self):
        with tempfile.TemporaryDirectory() as d,self.assertRaisesRegex(r.RunnerError,'S3 multi-root'):
            r.run_rows(Path('/std'),Path('/tool'),Path(d),r.load_request())


class SingletonRunnerTests(unittest.TestCase):
    def exercise(self,case='success',rid=None):
        req=r.load_request();rid=rid or p.ORDER[4];group=c.group(req,rid);row=group['rows'][0]
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);root=Path(tmp.name);std=root/'std';std.mkdir();tool=root/'tool';out=root/'out';calls=[]
        def execute(argv,cwd,dest,timeout,**kw):
            calls.append((argv,kw['env'],timeout))
            self.assertEqual([argv[i+1] for i,a in enumerate(argv) if a=='--harness'],[row['selector']])
            data=fixtures.batch_export([row],req['source_bindings'])
            data['harnesses'][0]['resolved_unwind']=row['unwind']
            initial=copy.deepcopy(data);initial['run_state']='INCOMPLETE';initial.pop('harnesses')
            kw['export_path'].write_text(json.dumps(initial));kw['compile_monitor'].poll(.01,{})
            fixtures.feed_regular(kw['rich_parser'],data)
            native=Path(kw['env']['CARGO_TARGET_DIR'])/'debug/deps/core.kani-metadata.json';native.parent.mkdir(parents=True,exist_ok=True)
            native.write_text(json.dumps({'crate_name':'core','proof_harnesses':[{'pretty_name':row['selector'],'crate_name':'core','attributes':data['harnesses'][0]['attributes'],'contract':data['harnesses'][0]['contract']}]}))
            if case=='exception':raise ProcessLookupError(errno.ESRCH,'synthetic unknown syscall')
            if case=='null':data=None
            elif case=='wrong_type':data=[]
            elif case=='partial':data['run_state']='INCOMPLETE'
            elif case=='NOT_RUN':data['harnesses'][0]['outcome']={'kind':'NOT_RUN'}
            elif case=='source':data['harnesses'][0]['file']='wrong.rs'
            elif case=='target':data['harnesses'][0]['attributes']['kind']={'ProofForContract':{'target_fn':'wrong'}}
            if case!='missing':kw['export_path'].write_text(json.dumps(data))
            else:kw['export_path'].unlink()
            return {'original_exit_code':-15 if case=='signal' else 0,'signal':15 if case=='signal' else None,
                'timed_out':case=='timeout','termination_reason':'timeout' if case=='timeout' else None,
                'elapsed_seconds':.02,'stdout_bytes':20,'stderr_bytes':0,'child_shutdown_verified':True,
                'process_identity':{'pid':2,'pgid':2,'start_ticks':22}}
        source={**c.identity(req),'changed_file_sha256':req['changed_file_sha256']}
        with mock.patch.object(r,'verify_source',return_value=source),mock.patch.object(r,'binary_fingerprints',return_value=binary()),mock.patch.object(r,'group_memory_budget',return_value={'group_cap_kib':6*1024*1024}),mock.patch.object(r,'_run_variant',return_value=(None,{})),mock.patch.object(r,'execute',side_effect=execute):
            results,fatal=r._run_group(std,tool,out,req,group,time.monotonic()+710,isolated_limits={'stdout_bytes':100000,'stderr_bytes':100000,'export_bytes':100000})
        gp=c.read(out/'groups'/group['id']/'receipt.json')
        return results,fatal,gp,calls
    def test_s3_singleton_uses_real_new_pins_cfg_bounds_fresh_target_and_after(self):
        for rid in p.ORDER[4:]:
            results,fatal,gp,calls=self.exercise(rid=rid)
            self.assertIsNone(fatal);self.assertEqual(results[0]['outcome'],'RECORDED')
            self.assertEqual(gp['std_sha'],r.load_request()['std_sha']);self.assertEqual(gp['effective_cfg'],p.CFG)
            self.assertEqual(gp['compile_limit_seconds'],180);self.assertEqual(gp['timeout_seconds'],600)
            self.assertTrue(gp['native_start_verified']);self.assertIn(gp['invocation_id'],gp['cargo_target_dir'])
            self.assertEqual(gp['tool_fingerprints_after']['phase'],'AFTER_CHILD_SHUTDOWN')
    def test_original_positive_rejects_fake_pfc_and_preserves_null_target(self):
        for rid in p.ORDER[4:]:
            results,fatal,gp,_=self.exercise('target',rid=rid)
            self.assertTrue(fatal);self.assertEqual(results[0]['outcome'],'UNKNOWN')
    def test_s3_errors_partial_missing_null_notrun_and_source_stage_target_mismatch(self):
        for case in ('timeout','signal','null','wrong_type','partial','NOT_RUN','missing','source','target','exception'):
            with self.subTest(case=case):
                results,fatal,gp,calls=self.exercise(case)
                self.assertTrue(fatal);self.assertEqual(results[0]['outcome'],'UNKNOWN');self.assertEqual(gp['binary_identity'],'MATCH')
                if case=='signal':self.assertEqual(gp['execution']['original_exit_code'],-15)
                if case=='exception':self.assertEqual(gp['execution_exception']['errno'],errno.ESRCH);self.assertEqual(gp['execution_exception']['operation'],'runner.execute')
