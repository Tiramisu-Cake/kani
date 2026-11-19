"""S3 source and service controls. Only small Python children, never Rust/Kani."""
import copy,errno,json,os,signal,sys,tempfile,time,unittest
from pathlib import Path
from unittest import mock
import runner as r
import s32_profile as p
import s32_policy as policy
import s32_campaign as c
import s3_runtime as rt
import s3_snapshots as snapshots
import s32_cfg_pfc as cfg
import s32_ordinary_contracts as ordinary
import s32_lexical_bindings as lexical
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


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.req=r.load_request();self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for rel,text in json.loads((HERE/'S32-SOURCE.json').read_text()).items():
            f=self.root/rel;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(text)
    def replace(self,rel,old,new):
        f=self.root/rel;self.assertIn(old,f.read_text());f.write_text(f.read_text().replace(old,new,1))
    def gate_request(self):
        req=copy.deepcopy(self.req)
        for key in ('cfg_pfc_source_sha256','ordinary_contract_source_sha256','contract_stack_source_sha256','lexical_source_sha256'):req.pop(key)
        return req
    def test_complete_new_cfg_all_gates_and_literal22(self):
        self.assertEqual(policy.validate_source(self.root,self.req)['status'],'STATIC_PASS')
        self.assertEqual((self.root/policy.BATCH).read_text().count('kani::assert('),22)
    def test_missing_role_is_detected_from_actual_source(self):
        req=copy.deepcopy(self.req);row=req['rows'][3];removed=row['roles'].pop(1);row['required_success_messages'].remove(removed['description'])
        with self.assertRaises(AssertionError):policy.validate_roles(self.root,req)
    def test_wrong_or_duplicate_role_anchor_rejected(self):
        for case in ('wrong-line','duplicate','wrong-source'):
            req=copy.deepcopy(self.req);role=req['rows'][3]['roles'][0]
            if case=='wrong-line':role['line']+=1
            if case=='duplicate':req['rows'][3]['roles'].append(copy.deepcopy(role))
            if case=='wrong-source':role['source_sha256']='f'*64;req['source_bindings'][p.ORDER[3]]['sha256']='f'*64
            with self.subTest(case=case),self.assertRaises(AssertionError):policy.validate_roles(self.root,req)
    def test_missing_provider_rejects_unselected_compiled_consumer(self):
        self.replace(policy.BATCH,'#[kani::proof_for_contract(sort8_stable)]','#[kani::proof]')
        with self.assertRaisesRegex(ValueError,'no active matching'):cfg.check(self.root,self.gate_request())
    def test_wrong_cfg_leaf_module_rejected(self):
        self.replace(policy.VERIFY,'kani_smallsort_s3_leaf))]','kani_smallsort_s3_absent))]')
        with self.assertRaises(ValueError):cfg.check(self.root,self.gate_request())
    def test_contracted_ordinary_target_rejected(self):
        self.replace(policy.BATCH,'#[kani::stub(s2_swap_seam,weak_swap)]','#[kani::stub(swap_if_less,weak_swap)]')
        with self.assertRaisesRegex(ValueError,'active contract'):ordinary.check(self.root,self.gate_request())
    def test_lexical_wrong_name_in_new_body_rejected(self):
        self.replace(policy.LEAF,'unsafe { insert_tail(p,', 'unsafe { missing_insert_tail(p,')
        with self.assertRaisesRegex(ValueError,'unresolved static path'):lexical.check(self.root,self.gate_request())
    def test_alias_chain_resolves_full_target(self):
        self.replace(policy.BATCH,'#[kani::stub(s2_swap_seam,weak_swap)]','#[kani::stub(alias_two,weak_swap)]')
        f=self.root/policy.BATCH;f.write_text(f.read_text()+'\nuse self::s2_swap_seam as alias_one;\nuse self::alias_one as alias_two;\n')
        rep=ordinary.check(self.root,self.gate_request())
        self.assertTrue(any(x['target'].endswith('::s2_swap_seam') for x in rep['checked_active_ordinary_uses']))
        self.replace(policy.BATCH,'use self::s2_swap_seam as alias_one;','use super::super::swap_if_less as alias_one;')
        with self.assertRaisesRegex(ValueError,'active contract'):ordinary.check(self.root,self.gate_request())
    def test_request_fullbyte_selection_and_caps_reject_mutations(self):
        for mutate in (lambda q:q['rows'].pop(),lambda q:q['flags'].update(RUSTFLAGS=''),lambda q:q['unreachable_admission'].update(enabled=True),lambda q:q['s3']['caps'].update(child_seconds=1),lambda q:q['source_parent'] is None):
            req=copy.deepcopy(self.req);mutate(req)
            if req==self.req:continue
            with self.assertRaises((AssertionError,ValueError,KeyError,TypeError)):p.validate(req)


class RoleTests(unittest.TestCase):
    def test_literal_intended_roles_all_eight_dynamic_producer_ids(self):
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
        row=r.load_request()['rows'][3];parsed,props=inventory(row);extra=copy.deepcopy(props['properties'][2]);extra['id']='fresh-instance.assertion.777';props['properties'].append(extra)
        parsed['harness']['checks']['total']+=1;parsed['harness']['checks']['success']+=1
        self.assertTrue(policy.expected_observation(row,parsed,props))
        extra['line']='1';self.assertFalse(policy.expected_observation(row,parsed,props))


class LifecycleTests(unittest.TestCase):
    def owner(self,rec=None):
        owner=object.__new__(rt.Owned);owner.known={};owner.events=rt.Events();owner.signals=[];owner.reaped=[];owner.parent=999
        if rec:owner.known[rec['pid']]=rec
        return owner
    def rec(self):return {'pid':12345,'start_ticks':77,'state':'S','ppid':999,'pgid':12345}
    def test_vanished_at_sampling_has_exact_operation_errno_identity(self):
        rec=self.rec();owner=self.owner(rec)
        with mock.patch.object(rt,'census',side_effect=[{rec['pid']:rec},{}]),mock.patch.object(Path,'read_text',side_effect=ProcessLookupError(errno.ESRCH,'gone')):
            self.assertEqual(owner.rss([rec]),0)
        event=owner.events[-1];self.assertEqual(event['operation'],'sample.read_status');self.assertEqual(event['errno'],errno.ESRCH);self.assertEqual(event['start_ticks'],77);self.assertIn('ProcessLookupError',event['traceback_tail'])
    def test_vanished_at_pidfd_open_and_send(self):
        for operation in ('open','send'):
            rec=self.rec();owner=self.owner(rec)
            with mock.patch.object(os,'pidfd_open',side_effect=ProcessLookupError(errno.ESRCH,'gone') if operation=='open' else None,return_value=8),mock.patch.object(signal,'pidfd_send_signal',side_effect=ProcessLookupError(errno.ESRCH,'gone')),mock.patch.object(os,'close'),mock.patch.object(rt,'census',side_effect=([{}] if operation=='open' else [{rec['pid']:rec},{}])):
                owner.send(rec,signal.SIGTERM)
            self.assertEqual(owner.events[-1]['operation'],'signal.pidfd_'+('open' if operation=='open' else 'send_signal'))
    def test_live_recycled_unknown_and_wrong_errno_fail_closed(self):
        rec=self.rec()
        for table,exc,known in [({rec['pid']:rec},ProcessLookupError(errno.ESRCH,'gone'),True),({rec['pid']:{**rec,'start_ticks':78}},ProcessLookupError(errno.ESRCH,'gone'),True),({},ProcessLookupError(errno.ESRCH,'gone'),False),({},ProcessLookupError(errno.EPERM,'bad errno'),True)]:
            owner=self.owner(rec if known else None)
            with mock.patch.object(rt,'census',return_value=table),self.assertRaises((rt.ContainmentError,ProcessLookupError)):owner.vanished(exc,'test.operation',rec)
    def test_cleanup_vanished_owned_signal_then_reap(self):
        rec=self.rec();owner=self.owner(rec);proc=mock.Mock(pid=rec['pid'],returncode=-15)
        with mock.patch.object(owner,'observe',side_effect=[([rec],{rec['pid']:rec}),([], {})]),mock.patch.object(os,'pidfd_open',side_effect=ProcessLookupError(errno.ESRCH,'gone')),mock.patch.object(rt,'census',return_value={}):
            result=owner.cleanup(proc)
        self.assertTrue(result['verified']);self.assertEqual(owner.events[-1]['operation'],'signal.pidfd_open')
    def test_bounded_lifecycle_diagnostics_count_omissions(self):
        events=rt.Events()
        for i in range(100):events.append({'number':i})
        self.assertEqual(len(events),64);self.assertEqual(events.omitted,36)
    def test_small_real_python_children_success_timeout_and_detached_descendant(self):
        for case,code,timeout in [('success','pass',2),('timeout','import time;time.sleep(2)',.15),('orphan','import subprocess,sys;subprocess.Popen([sys.executable,"-c","import time;time.sleep(2)"],start_new_session=True)',2)]:
            with tempfile.TemporaryDirectory() as d:
                sup=rt.supervise([sys.executable,'-c',code],Path(d),dict(os.environ),timeout,12*1024*1024,Path(d)/'stderr')
            self.assertTrue(sup['containment']['verified'],sup)
            if case=='timeout':self.assertTrue(sup['cutoff'])
            if case=='orphan':self.assertTrue(any(x['pgid']!=sup['worker_pid'] for x in sup['containment']['observed']))


class SnapshotTests(unittest.TestCase):
    def pair(self):
        req=r.load_request();ctx={'campaign_id':'c','root':p.ORDER[0],'epoch':'E1','rank':1,'invocation_id':'i','source_parent':req['source_parent'],'control_parent':req['control_parent'],'request_sha256':r.sha256(r.REQUEST_PATH),'baseline_context':{'campaign_id':'c'}}
        ctx['baseline_context']={k:ctx[k] for k in ('campaign_id','source_parent','control_parent','request_sha256')}
        return ctx,synthetic_capture(None,None,req,ctx['baseline_context'],'E0'),synthetic_capture(None,None,req,ctx,'E1.pre'),synthetic_capture(None,None,req,ctx,'E1.post',{'verified':True})
    def test_complete_pair_and_original_baseline_unchanged(self):
        ctx,base,pre,post=self.pair();old=copy.deepcopy(base);self.assertTrue(snapshots.validate_pair(base,pre,post,ctx));self.assertEqual(base,old)
    def test_drift_unreadable_missing_null_wrong_epoch_parent_and_path_reject(self):
        for case in ('drift','unreadable','missing','null','array','epoch','parent','path','shutdown'):
            ctx,base,pre,post=self.pair()
            if case=='drift':post['source']['std_tree']='drift'
            elif case=='unreadable':post['errors']=[{'operation':'hash','errno':errno.EACCES}]
            elif case=='missing':post.pop('binaries')
            elif case=='null':post=None
            elif case=='array':post=[]
            elif case=='epoch':post['epoch']='E2.post'
            elif case=='parent':post['context']['control_parent']='wrong'
            elif case=='path':post['binaries']['binaries']['cbmc']['path']='/wrong/same-digest'
            elif case=='shutdown':post['shutdown']['verified']=False
            with self.subTest(case=case),self.assertRaises(ValueError):snapshots.validate_pair(base,pre,post,ctx)
    def test_post_not_captured_without_shutdown(self):
        req=r.load_request();doc=snapshots.capture(Path('/unused'),Path('/unused'),req,{},'E1.post',{'verified':False})
        self.assertEqual(doc['state'],'INCOMPLETE');self.assertIsNone(doc['source'])
    def test_capture_preserves_multiple_errors_and_other_fields(self):
        req=r.load_request()
        with mock.patch.object(r,'verify_source',side_effect=PermissionError(errno.EACCES,'unreadable')),mock.patch.object(r,'git',side_effect=RuntimeError('git error')),mock.patch.object(r,'snapshot_binaries',return_value=binary()):
            doc=snapshots.capture(Path('/unused'),Path('/unused'),req,{},'E1.post',{'verified':True})
        self.assertEqual(len(doc['errors']),2);self.assertEqual(doc['errors'][0]['operation'],'snapshot.source');self.assertEqual(doc['errors'][0]['errno'],errno.EACCES);self.assertEqual(doc['binaries'],binary())


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
        result={**r._row_base(row,'OBSERVED'),'group':'s3-'+rid,'outcome':'RECORDED','export':parsed}
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
    def test_serial_order_fresh_context_caps_and_all_eight(self):
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
        import s32_package
        self.assertEqual(s32_package.check_yaml(doc)['checkout_depths'],{'control':7,'export':5,'tool':2})
        for mutate in (lambda q:q['jobs']['s3_leaf']['steps'][2].update(**{'timeout-minutes':1}),lambda q:q['jobs']['s3_leaf']['steps'][9].update(run='echo wrong'),lambda q:q['jobs']['s3_leaf'].update(strategy={}),lambda q:q['permissions'].update(contents='write')):
            bad=copy.deepcopy(doc);mutate(bad)
            with self.assertRaises(AssertionError):s32_package.check_yaml(bad)
    def test_multi_root_legacy_entry_refused(self):
        with tempfile.TemporaryDirectory() as d,self.assertRaisesRegex(r.RunnerError,'S3 multi-root'):
            r.run_rows(Path('/std'),Path('/tool'),Path(d),r.load_request())


class SingletonRunnerTests(unittest.TestCase):
    def exercise(self,case='success',rid=None):
        req=r.load_request();rid=rid or p.ORDER[3];group=c.group(req,rid);row=group['rows'][0]
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
            elif case=='target':data['harnesses'][0]['attributes']['kind']['ProofForContract']['target_fn']='wrong'
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
        for rid in (p.ORDER[3],p.ORDER[7]):
            results,fatal,gp,calls=self.exercise(rid=rid)
            self.assertIsNone(fatal);self.assertEqual(results[0]['outcome'],'RECORDED')
            self.assertEqual(gp['std_sha'],r.load_request()['std_sha']);self.assertEqual(gp['effective_cfg'],p.CFG)
            self.assertEqual(gp['compile_limit_seconds'],180);self.assertEqual(gp['timeout_seconds'],600)
            self.assertTrue(gp['native_start_verified']);self.assertIn(gp['invocation_id'],gp['cargo_target_dir'])
            self.assertEqual(gp['tool_fingerprints_after']['phase'],'AFTER_CHILD_SHUTDOWN')
    def test_s3_errors_partial_missing_null_notrun_and_source_stage_target_mismatch(self):
        for case in ('timeout','signal','null','wrong_type','partial','NOT_RUN','missing','source','target','exception'):
            with self.subTest(case=case):
                results,fatal,gp,calls=self.exercise(case)
                self.assertTrue(fatal);self.assertEqual(results[0]['outcome'],'UNKNOWN');self.assertEqual(gp['binary_identity'],'MATCH')
                if case=='signal':self.assertEqual(gp['execution']['original_exit_code'],-15)
                if case=='exception':self.assertEqual(gp['execution_exception']['errno'],errno.ESRCH);self.assertEqual(gp['execution_exception']['operation'],'runner.execute')


class PortableReplayTests(unittest.TestCase):
    def test_same_invocation_stock_rich_metadata_and_upload_only_replay(self):
        self.exercise()
    def exercise(self,fault=None,replay_hook=None):
        req=r.load_request()
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);std=root/'std';std.mkdir();tool=root/'tool';out=root/'out'
            source={**c.identity(req),'changed_file_sha256':req['changed_file_sha256']}
            def execute(argv,cwd,dest,timeout,**kw):
                selector=argv[argv.index('--harness')+1];row=next(x for x in req['rows'] if x['selector']==selector);binding=req['source_bindings'][row['id']]
                parsed,props=inventory(row)
                for prop in props['properties']:prop['file']=str(std/binding['file'])
                h=parsed['harness'];h['failed_properties']=[copy.deepcopy(x) for x in props['properties'] if x['status']=='FAILURE']
                data=fixtures.export(selector=selector,mode='pfc' if row['mode']=='PFC' else 'original')
                base=data['harnesses'][0];base.update(h,file=binding['file'],line=binding['locations'][0]['line'],resolved_unwind=row['unwind'])
                if row['mode']=='PFC':base['attributes']['kind']['ProofForContract']['target_fn']=binding['target']
                initial=copy.deepcopy(data);initial['run_state']='INCOMPLETE';initial.pop('harnesses')
                kw['export_path'].write_text(json.dumps(initial));kw['compile_monitor'].poll(.01,{})
                # Render the exact full property set rather than fabricated native results.
                lines=['Checking harness '+selector+'...','RESULTS:']
                for index,prop in enumerate(props['properties']):
                    lines += ['Check '+str(index+1)+': '+prop['id'],'\t - Status: '+prop['status'],'\t - Description: "'+prop['description']+'"','\t - Location: '+prop['file']+':'+prop['line']+' in function synthetic']
                lines += ['SUMMARY:'];kw['rich_parser'].feed(('\n'.join(lines)+'\n').encode());kw['rich_parser'].finish()
                kw['export_path'].write_text(json.dumps(data))
                native=Path(kw['env']['CARGO_TARGET_DIR'])/'debug/deps/core.kani-metadata.json';native.parent.mkdir(parents=True,exist_ok=True)
                native.write_text(json.dumps({'crate_name':'core','proof_harnesses':[{'pretty_name':selector,'crate_name':'core','attributes':base['attributes'],'contract':base['contract']}]}))
                return {'original_exit_code':1 if h['n_failed'] else 0,'signal':None,'timed_out':False,'elapsed_seconds':.02,
                        'stdout_bytes':sum(len(x)+1 for x in lines),'stderr_bytes':0,'child_shutdown_verified':True,'process_identity':{'pid':2,'pgid':2,'start_ticks':22}}
            def invoke(std,tool,path,request,rid,limits,slot):
                r._run_group(std,tool,path,req,c.group(req,rid),time.monotonic()+710,isolated_limits=limits)
                if fault is not None:fault(path,rid)
                return supervision()
            with mock.patch.object(r,'verify_source',return_value=source),mock.patch.object(r,'binary_fingerprints',return_value=binary()),mock.patch.object(r,'group_memory_budget',return_value={'group_cap_kib':6*1024*1024}),mock.patch.object(r,'_run_variant',return_value=(None,{})),mock.patch.object(r,'execute',side_effect=execute),mock.patch.object(c.snapshots,'capture',side_effect=synthetic_capture):
                self.assertEqual(c.run_campaign(std,tool,out,req,invoker=invoke),0 if fault is None else 1)
            collected=c.collect([out],req);self.assertEqual(len(collected['rows']),9)
            if fault is None:self.assertTrue(all(x.get('s3_expected_match') is True for x in collected['rows']))
            else:self.assertTrue(collected['global_stop']);self.assertTrue(collected['global_stops'])
            pack_evidence.pack(out)
            upload=root/'upload';upload.mkdir();(upload/pack_evidence.NAME).write_bytes((out/pack_evidence.NAME).read_bytes())
            if replay_hook is not None:replay_hook(out,upload,req)
            replay=c.collect([upload],req);self.assertEqual(replay,collected)
            return collected
