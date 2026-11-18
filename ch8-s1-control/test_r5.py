"""r5 service regressions. Only bounded synthetic/Python children; never Rust/CI."""
import copy,json,os,sys,tempfile,time,unittest
from pathlib import Path
from unittest import mock
import runner as r
import r5_profile as p
import r5_campaign as c
import r5_runtime as rt
import test_runner as fixtures
import check_package,pack_evidence

def synthetic_supervision():
    worker={'pid':1,'pgid':1,'start_ticks':11}
    driver={'pid':2,'pgid':2,'start_ticks':22}
    return {'worker_pid':1,'worker_initial_identity':worker,'worker_exit':0,'cutoff':None,'supervisor_error':None,
            'containment':{'verified':True,'observed':[worker,driver]},'orphan_survivors_at_worker_exit':[]}

class CampaignTests(unittest.TestCase):
    def setUp(self):self.req=r.load_request()
    def emit(self,out,rid,case='ok'):
        row=c.group(self.req,rid)['rows'][0];name=row['selector'];gp=out/'groups'/('r5-'+rid)
        source={**c.identity(self.req),'changed_file_sha256':self.req['changed_file_sha256']}
        doc={'state':'FAILED','group':'r5-'+rid,'request_sha256':r.sha256(r.REQUEST_PATH),'source_before':source,'source_after':source,
             'binary_identity':'MATCH','snapshot_errors':[],'native_start_events':[{'selector':name,'monotonic':time.monotonic()}],
             'native_start_verified':True,'execution':{'original_exit_code':0,'stdout_bytes':1,'stderr_bytes':0,'process_identity':{'pid':2,'pgid':2,'start_ticks':22}}}
        result={**r._row_base(row,'UNKNOWN'),'group':'r5-'+rid,'outcome':'UNKNOWN','reason':case}
        if case in ('ok','unexpected','negative_wrong'):
            doc['state']='COMPLETE'
            h={'outcome':{'kind':'COMPLETED','verdict':'SUCCESS'},'checks':{'success':1,'total':1,
              **{k:[] for k in ('failure','unreachable','undetermined','error','unknown','other')}},
              'covers':{'total':row['required_cover_count'],**{k:[] for k in ('unsatisfiable','unreachable','undetermined','error','unknown','other')}}}
            props=[{'id':str(i),'description':s,'class':'assertion','status':'SUCCESS'} for i,s in enumerate(row.get('required_success_messages',[]))]
            props += [{'id':'c'+str(i),'description':s,'class':'cover','status':'SATISFIED'} for i,s in enumerate(row['required_cover_messages'])]
            if row['expected']=='DETECTED':
                h=fixtures.batch_export([row],self.req['source_bindings'])['harnesses'][0];props=copy.deepcopy(h['failed_properties'])
                if case=='negative_wrong':props[0]['description']='UNEXPECTED_ASSERTION'
            if case=='unexpected':h['outcome']={'kind':'COMPLETED','verdict':'FAILURE'}
            result.update(status='OBSERVED',outcome='RECORDED',export={'state':'RECORDED_OBSERVATION','outcome':'RECORDED','harness':h})
            c.atomic(gp/'properties.json',{'harnesses':[{'name':name,'properties':props}]})
        if case=='source':doc['source_after']={}
        if case=='binary':doc['binary_identity']='UNKNOWN'
        if case=='wrong_start':doc['native_start_events']=[{'selector':'wrong'}]
        gp.mkdir(parents=True,exist_ok=True)
        if case=='export_cap':(gp/'export.json').write_bytes(b'0'*(p.CAPS['export_bytes']+1))
        c.atomic(gp/'receipt.json',doc);c.atomic(out/rid/'receipt.json',result)
        return synthetic_supervision()
    def run_cases(self,case='rss',position=0):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);launched=[]
            def call(std,tool,out,request,rid,limits,slot):
                launched.append(rid);return self.emit(out,rid,case if len(launched)-1==position else 'ok')
            code=c.run_campaign(Path('/std'),Path('/tool'),out,self.req,invoker=call)
            terminal=c.read(out/'receipt.json');before={rid:seal['files'] for rid,seal in c.sealed(out).items()}
            check_package.fallback(out)
            self.assertEqual(before,{rid:seal['files'] for rid,seal in c.sealed(out).items()})
            return code,launched,terminal
    def test_first_middle_last_local_errors_continue(self):
        for case in ('rss','timeout','compile_exit42','compile_timeout','missing_RESULTS','partial','null','wrong_type','decoder_error','unexpected'):
            for pos in (0,4,8):
                with self.subTest(case=case,pos=pos):
                    _,launched,term=self.run_cases(case,pos)
                    self.assertEqual(launched,list(p.ORDER));self.assertEqual(len(term['r5_campaign']['completed']),9)
                    self.assertEqual([x['id'] for x in term['rows'] if x['status']=='DEFERRED_NOT_SELECTED'],list(p.DEFERRED))
    def test_identity_start_and_containment_abort(self):
        for case in ('source','binary','wrong_start'):
            with self.subTest(case=case):
                code,launched,term=self.run_cases(case,1)
                self.assertEqual(launched,list(p.ORDER[:2]));self.assertEqual(code,1)
                self.assertEqual(term['r5_campaign']['completed'],[p.ORDER[0]])
        for sup in ({'containment':{'verified':False}}, {'containment':{'verified':True},'orphan_survivors_at_worker_exit':[{'pid':123}]}):
            with tempfile.TemporaryDirectory() as d:
                out=Path(d);self.emit(out,p.ORDER[0])
                with self.assertRaises(c.GlobalFailure):c.root_outcome(out,self.req,p.ORDER[0],sup)
    def test_exact_negative_not_generic_failure_and_no_late_success(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);rid=p.ORDER[0];result=c.root_outcome(out,self.req,rid,self.emit(out,rid,'negative_wrong'))
            self.assertFalse(result['r5_expected_match']);self.assertEqual(result['export']['harness']['outcome']['verdict'],'FAILURE')
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);rid=p.ORDER[0];sup=self.emit(out,rid);sup['cutoff']='slot_wall_during_cleanup'
            result=c.root_outcome(out,self.req,rid,sup);self.assertEqual(result['outcome'],'UNKNOWN');self.assertFalse(result['r5_expected_match'])
    def test_global_clock_and_aggregate_export_cap(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);launched=[]
            def invoke(*args):launched.append(args[4]);return self.emit(args[2],args[4])
            code=c.run_campaign(Path('/std'),Path('/tool'),out,self.req,invoker=invoke,clock=mock.Mock(side_effect=[0,181,181]))
            self.assertEqual(code,1);self.assertFalse(launched);self.assertIn('global_budget',c.read(out/'receipt.json')['stop_reason'])
        _,launched,term=self.run_cases('export_cap',0)
        self.assertEqual(launched,[p.ORDER[0]]);self.assertIn('aggregate_output',term['stop_reason'])
    def test_missing_request_after_launch_keeps_original_identity_and_packs(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'request.json';path.write_bytes(r.REQUEST_PATH.read_bytes());original=r.sha256(path);out=Path(d)/'out'
            def invoke(*args):
                sup=self.emit(args[2],args[4]);path.unlink();return sup
            with mock.patch.object(r,'REQUEST_PATH',path):
                self.assertEqual(c.run_campaign(Path('/std'),Path('/tool'),out,self.req,invoker=invoke),1)
                self.assertEqual(c.read(out/'receipt.json')['request_sha256'],original)
                c.fallback(out,self.req);pack_evidence.pack(out)
                self.assertTrue((out/pack_evidence.NAME).exists())
    def test_request_and_completed_storage_drift(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);c.root_outcome(out,self.req,p.ORDER[0],self.emit(out,p.ORDER[0]));(out/p.ORDER[0]/'receipt.json').write_text('{}')
            with self.assertRaisesRegex(c.GlobalFailure,'storage drift'):c.fallback(out,self.req)
        with tempfile.TemporaryDirectory() as d:
            request=Path(d)/'request.json';request.write_bytes(r.REQUEST_PATH.read_bytes());out=Path(d)/'out';launched=[]
            def invoke(*args):
                launched.append(args[4]);result=self.emit(args[2],args[4]);request.write_text('{}');return result
            with mock.patch.object(r,'REQUEST_PATH',request):
                self.assertEqual(c.run_campaign(Path('/std'),Path('/tool'),out,self.req,invoker=invoke),1)
                self.assertIn('request drift',c.read(out/'receipt.json')['stop_reason'])
            self.assertEqual(len(launched),1)
    def test_prefix_packed_and_fallback_preserves_exact_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);rid=p.ORDER[0];c.root_outcome(out,self.req,rid,self.emit(out,rid));c.finalize(out,self.req,'later failure')
            before=(out/rid/'receipt.json').read_bytes();c.fallback(out,self.req)
            self.assertEqual((out/rid/'receipt.json').read_bytes(),before);pack_evidence.pack(out)
            self.assertTrue((out/pack_evidence.NAME).exists());self.assertEqual(c.sealed(out)[rid]['files'][rid+'/receipt.json'],c.digest(before))
    def test_exited_detached_group_cannot_reuse_pgid_only_after_snapshot(self):
        doc={'execution':{'process_identity':{'pid':2,'pgid':2,'start_ticks':22}}}
        sup=synthetic_supervision()
        c.validate_owned_groups(doc,sup)
        sup['containment']['observed'].append({'pid':3,'pgid':3,'state':'Z'})
        with self.assertRaisesRegex(c.GlobalFailure,'unexpected_process_group'):c.validate_owned_groups(doc,sup)
    def test_unsealed_worker_or_launch_intent_is_not_claimed_unstarted(self):
        for status in ('IN_PROGRESS','INTENT_ONLY'):
            with self.subTest(status=status),tempfile.TemporaryDirectory() as d:
                out=Path(d);rid=p.ORDER[0];row=c.group(self.req,rid)['rows'][0]
                if status=='IN_PROGRESS':c.atomic(out/rid/'receipt.json',{**r._row_base(row,'IN_PROGRESS'),'group':'r5-'+rid})
                else:c.atomic(out/'workers'/(rid+'-launch.json'),{'id':rid})
                term=c.finalize(out,self.req,'controller interrupted')
                affected=next(x for x in term['rows'] if x['id']==rid)
                self.assertEqual(affected['status'],'INTERRUPTED' if status=='IN_PROGRESS' else 'UNSEALED_INVOCATION_UNKNOWN')
                self.assertEqual(affected['outcome'],'UNKNOWN');self.assertIn('UNKNOWN',affected['native_root_start'])
    def test_global_abort_keeps_supervision_and_interrupted_status(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)
            def invoke(std,tool,out,req,rid,limits,slot):
                sup=self.emit(out,rid,'binary');sup['worker_pid']=12345
                sup['worker_initial_identity']={'pid':12345,'pgid':12345,'start_ticks':777}
                return sup
            self.assertEqual(c.run_campaign(Path('/std'),Path('/tool'),out,self.req,invoker=invoke),1)
            terminal=c.read(out/'receipt.json');affected=next(x for x in terminal['rows'] if x['id']==p.ORDER[0])
            self.assertEqual(affected['status'],'INTERRUPTED');self.assertEqual(affected['outcome'],'UNKNOWN')
            retained=c.read(out/'workers'/(p.ORDER[0]+'-supervision.json'))
            self.assertEqual(retained['worker_initial_identity']['start_ticks'],777)
            self.assertEqual(affected['invocation_supervision'],retained)
            self.assertTrue(all(x['status']=='NOT_RUN' for x in terminal['rows'] if x['id'] in p.ORDER[1:]))
    def test_explicit_legacy_group_api_cannot_overwrite_active_r5_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);rid=p.ORDER[0];c.root_outcome(out,self.req,rid,self.emit(out,rid));c.finalize(out,self.req,'later failure')
            original=(out/rid/'receipt.json').read_bytes()
            check_package.fallback(out,['s2-batch3probes-u34'])
            self.assertEqual((out/rid/'receipt.json').read_bytes(),original)
            self.assertEqual(c.read(out/'receipt.json')['schema'],'ch8-s2-r5-campaign-v1')
    def test_finish_packs_prefix_even_if_fallback_errors(self):
        import contextlib,io
        with tempfile.TemporaryDirectory() as d,mock.patch.object(sys,'argv',['r5_campaign','finish','--out',d]),mock.patch.object(c,'fallback',side_effect=c.GlobalFailure('synthetic storage failure')),mock.patch.object(pack_evidence,'pack') as pack,contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(c.main(),1);pack.assert_called_once_with(Path(d))
    def test_post_cleanup_deadline_and_shared_export_remainder(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);rid=p.ORDER[0];sup=self.emit(out,rid);sup['monotonic_start']=time.monotonic()-721
            result=c.root_outcome(out,self.req,rid,sup)
            self.assertEqual(result['outcome'],'UNKNOWN');self.assertEqual(result['r5_supervision']['cutoff'],'durable_slot_cutoff')
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);launches=[]
            def invoke(std,tool,out,req,rid,limits,slot):
                launches.append(rid)
                if len(launches)==2:self.assertEqual(limits['export_bytes'],3*1024*1024)
                sup=self.emit(out,rid,'partial');gp=out/'groups'/('r5-'+rid)
                (gp/'export.json').write_bytes(b'0'*(5*1024*1024));return sup
            self.assertEqual(c.run_campaign(Path('/std'),Path('/tool'),out,self.req,invoker=invoke),1)
            self.assertEqual(launches,list(p.ORDER[:2]));self.assertEqual(len(c.sealed(out)),2)
    def test_global_clock_is_not_reset_after_first_root(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);launches=[]
            def invoke(*args):launches.append(args[4]);return self.emit(args[2],args[4])
            clock=mock.Mock(side_effect=[0,0,0,1,1,901,901])
            self.assertEqual(c.run_campaign(Path('/std'),Path('/tool'),out,self.req,invoker=invoke,clock=clock),1)
            self.assertEqual(launches,[p.ORDER[0]]);self.assertIn('global_budget',c.read(out/'receipt.json')['stop_reason'])
    def test_profile_legacy_strict_and_full_union(self):
        p.validate(self.req);legacy=fixtures.legacy_request();r.s2_policy.validate_request(legacy)
        with tempfile.TemporaryDirectory() as d,self.assertRaises(r.RunnerError):r.run_rows(Path('/std'),Path('/tool'),Path(d),self.req)
        self.assertEqual(len(r.group_rows(legacy['rows'],legacy['execution_groups'])),1)
        for field,value in [('selected',list(reversed(p.ORDER))),('deferred',[]),('caps',{})]:
            bad=copy.deepcopy(self.req);bad['r5'][field]=value
            with self.assertRaises(AssertionError):p.validate(bad)
        bad=copy.deepcopy(legacy);bad['execution_groups']=p.groups(self.req)
        with self.assertRaises(AssertionError):r.s2_policy.validate_request(bad)
        self.assertEqual(sum(x['required_cover_count'] for x in self.req['rows'] if x['id'] in p.ORDER),16)
        self.assertEqual(sum(x['required_cover_count'] for x in self.req['rows']),20)
    def test_native_start_filter_and_compile_cutoff(self):
        parser=rt.NativeStarts(['chosen'],Path('/'));parser.feed(b'Checking harness wrong...\n')
        self.assertIn('unexpected',parser.error);self.assertEqual(parser.starts[0]['selector'],'wrong')
        parser=rt.NativeStarts(['chosen'],Path('/'));parser.feed(b'Checking harness chosen...\nChecking harness chosen...\n')
        self.assertEqual(len(parser.starts),2);self.assertIn('duplicate',parser.error)
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);export=root/'export.json';row=self.req['rows'][0];monitor=r.CompileMonitor(root/'compile.json',export,[row['selector']],seconds=180)
            export.write_text(json.dumps(fixtures.batch_export([row],self.req['source_bindings'])))
            self.assertTrue(monitor.poll(180,{}));monitor.finish({'elapsed_seconds':181,'original_exit_code':0},{})
            self.assertEqual(monitor.receipt['state'],'FAILED')
    def test_isolated_pipeline_singleton_namespace_caps(self):
        req=self.req;row=c.group(req,p.ORDER[0])['rows'][0];targets=[]
        fp={'required_hashes_present':True,'binaries':{k:{'path':'/'+k,'sha256':'a'*64} for k in ('kani_driver','kani_compiler','cbmc')}}
        source={**c.identity(req),'changed_file_sha256':req['changed_file_sha256']}
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);std=base/'std';tool=base/'tool'
            def execute(argv,cwd,out,timeout,**kw):
                self.assertEqual(argv.count('--harness'),1);self.assertEqual(argv[argv.index('--harness')+1],row['selector'])
                self.assertEqual(timeout,600);self.assertEqual(kw['rss_cap_kib'],6*1024*1024);self.assertEqual(kw['compile_monitor'].seconds,180)
                self.assertTrue(kw['record_identity']);targets.append(kw['env']['CARGO_TARGET_DIR'])
                stock=fixtures.batch_export([row],req['source_bindings']);kw['export_path'].write_text(json.dumps(stock));kw['compile_monitor'].poll(1,{})
                fixtures.feed_regular(kw['rich_parser'],stock)
                target=Path(kw['env']['CARGO_TARGET_DIR'])
                (target/'core.kani-metadata.json').write_text(json.dumps({'proof_harnesses':[{'pretty_name':row['selector'],'crate_name':'core'}]}))
                return {'original_exit_code':1,'elapsed_seconds':2,'stdout_bytes':1,'stderr_bytes':0,'child_shutdown_verified':True,'process_identity':{'pid':2,'pgid':2,'start_ticks':22}}
            with mock.patch.object(r,'verify_source',return_value=source),mock.patch.object(r,'binary_fingerprints',return_value=fp),mock.patch.object(r,'group_memory_budget',return_value={'group_cap_kib':12*1024*1024}),mock.patch.object(r,'execute',side_effect=execute):
                for index in range(2):
                    out=base/str(index)
                    r._run_group(std,tool,out,req,c.group(req,p.ORDER[0]),time.monotonic()+720,isolated_limits={'stdout_bytes':10000,'stderr_bytes':1000,'export_bytes':100000})
                    sup=synthetic_supervision()
                    result=c.root_outcome(out,req,p.ORDER[0],sup)
                    self.assertEqual(result['outcome'],'RECORDED')
                    c.finalize(out,req)
                    replay=c.collect([out],req)
                    observed=next(x for x in replay['rows'] if x['id']==p.ORDER[0])
                    self.assertEqual(observed['outcome'],'RECORDED');self.assertFalse(replay['full_inventory_complete'])
                    gp=out/'groups'/('r5-'+p.ORDER[0])/'receipt.json'
                    doc=c.read(gp);doc['native_start_verified']=False;c.atomic(gp,doc)
                    seal_path=out/'completed'/(p.ORDER[0]+'.json');seal=c.read(seal_path)
                    seal['files'][str(gp.relative_to(out))]=r.sha256(gp);c.atomic(seal_path,seal)
                    with self.assertRaises(c.GlobalFailure):c.collect([out],req)
            self.assertNotEqual(targets[0],targets[1]);self.assertTrue(all('/target/ch8-s1-cargo/' in x for x in targets))

class ProcessTests(unittest.TestCase):
    def supervise(self,script,slot=.15):
        with tempfile.TemporaryDirectory() as d:
            return rt.supervise([sys.executable,'-c',script],Path(d),dict(os.environ),slot,12*1024*1024,Path(d)/'worker.stderr')
    def test_pid_identity_failure_still_reaps_before_snapshot_boundary(self):
        with tempfile.TemporaryDirectory() as d,mock.patch.object(rt,'census',side_effect=OSError('synthetic proc identity read error')):
            result=r.execute([sys.executable,'-c','import time;time.sleep(30)'],Path(d),Path(d)/'child',2,record_identity=True)
            self.assertEqual(result['termination_reason'],'runner_exception')
            self.assertEqual(result['runner_exception']['type'],'OSError')
            self.assertTrue(result['child_shutdown_verified']);self.assertIsNotNone(result['original_exit_code'])
    def test_real_timeout_python_tree_reaped(self):
        result=self.supervise('import time;time.sleep(30)')
        self.assertEqual(result['cutoff'],'slot_wall');self.assertTrue(result['containment']['verified'])
        self.assertTrue(result['containment']['signals']);self.assertIsNotNone(result['worker_initial_identity']['start_ticks'])
    def escaped_case(self,delayed=False,missing_ready=False):
        import contextlib,select,socket
        # The child publishes identity only after setsid; readiness never relies
        # on scheduling delays. Alarm bounds a child even if fixture setup fails.
        child_script="""import json,os,signal,sys
os.setsid();signal.alarm(15)
raw=open('/proc/self/stat').read();tail=raw[raw.rfind(')')+2:].split()
identity={'pid':os.getpid(),'pgid':os.getpgrp(),'start_ticks':int(tail[19])}
if sys.argv[2]=='ready':
    os.write(int(sys.argv[1]),json.dumps(identity).encode());os.close(int(sys.argv[1]))
signal.pause()
"""
        worker_script="""import json,os,select,socket,subprocess,sys
from pathlib import Path
control=None;child=None;complete=False
try:
    if sys.argv[1]=='delayed':
        control=socket.socket(socket.AF_UNIX);control.settimeout(2);control.connect('control.sock')
        assert control.recv(1)==b'G'
    readfd,writefd=os.pipe()
    try:
        child=subprocess.Popen([sys.executable,'-c',sys.argv[3],str(writefd),sys.argv[2]],pass_fds=(writefd,))
    finally:os.close(writefd)
    try:
        assert select.select([readfd],[],[],2)[0], 'child-ready timeout'
        identity=json.loads(os.read(readfd,4096))
    finally:os.close(readfd)
    assert identity['pid']==child.pid and identity['pgid']==child.pid and identity['start_ticks']>0
    Path('child-ready.json').write_text(json.dumps(identity))
    if control is not None:
        control.sendall(b'R');assert control.recv(1)==b'E'
    complete=True
finally:
    if control is not None:control.close()
    if child is not None and not complete:
        child.terminate()
        try:child.wait(timeout=1)
        except subprocess.TimeoutExpired:child.kill();child.wait(timeout=1)
"""
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);listener=None;calls=[];original=rt.Owned.observe
            if delayed:
                listener=socket.socket(socket.AF_UNIX);listener.settimeout(2)
                listener.bind(str(root/'control.sock'));listener.listen(1)
            def delayed_observe(owned,pid):
                sample=original(owned,pid)
                if not calls:
                    calls.append(True)
                    # Hold spawn until AFTER the live sample, then wait for
                    # ready and worker exit BEFORE returning that stale sample.
                    connection,_=listener.accept()
                    with connection:
                        connection.settimeout(2);connection.sendall(b'G')
                        self.assertEqual(connection.recv(1),b'R');connection.sendall(b'E')
                        fd=os.pidfd_open(pid)
                        try:self.assertTrue(select.select([fd],[],[],2)[0], 'worker-exit timeout')
                        finally:os.close(fd)
                return sample
            try:
                context=mock.patch.object(rt.Owned,'observe',delayed_observe) if delayed else contextlib.nullcontext()
                with context:
                    result=rt.supervise([sys.executable,'-c',worker_script,'delayed' if delayed else 'normal',
                        'missing' if missing_ready else 'ready',child_script],root,dict(os.environ),6,12*1024*1024,root/'worker.stderr')
                ready=json.loads((root/'child-ready.json').read_text()) if (root/'child-ready.json').exists() else None
                return result,ready
            finally:
                if listener is not None:listener.close()
    def assert_escaped_cleanup(self,result,child):
        self.assertIsNotNone(child);self.assertNotEqual(child['pgid'],result['worker_pid'])
        self.assertEqual(child['pid'],child['pgid']);self.assertGreater(child['start_ticks'],0)
        self.assertEqual(result['worker_exit'],0);self.assertIsNone(result['cutoff']);self.assertIsNone(result['supervisor_error'])
        cleanup=result['containment'];self.assertTrue(cleanup['verified'])
        self.assertTrue(any(all(rec[k]==child[k] for k in ('pid','pgid','start_ticks')) for rec in cleanup['observed']))
        self.assertTrue(any(rec['pid']==child['pid'] and rec['start_ticks']==child['start_ticks'] for rec in cleanup['signals']))
        self.assertTrue(any(rec['pid']==child['pid'] for rec in cleanup['reaped_adopted']))
        self.assertNotIn(child['pid'],rt.census())
        doc={'state':'COMPLETE','execution':{'process_identity':result['worker_initial_identity']}}
        with self.assertRaisesRegex(c.GlobalFailure,'unexpected_process_group_containment_gap'):c.validate_owned_groups(doc,result)
    def test_escaped_setsid_child_found_and_reaped(self):
        self.assert_escaped_cleanup(*self.escaped_case())
    def test_escaped_child_adopted_after_early_snapshot(self):
        result,child=self.escaped_case(delayed=True)
        self.assertEqual(result['orphan_survivors_at_worker_exit'],[])
        self.assert_escaped_cleanup(result,child)
    def test_escaped_fixture_missing_ready_cleans_child(self):
        result,child=self.escaped_case(missing_ready=True)
        self.assertIsNone(child);self.assertNotEqual(result['worker_exit'],0)
        self.assertTrue(result['containment']['verified']);self.assertIsNone(result['supervisor_error'])
    def test_zero_exit_during_cleanup_does_not_clear_cutoff(self):
        script="import signal,sys,time;signal.signal(signal.SIGTERM,lambda *args:sys.exit(0));time.sleep(30)"
        result=self.supervise(script,.2)
        self.assertEqual(result['worker_exit'],0);self.assertEqual(result['cutoff'],'slot_wall');self.assertTrue(result['limit_initiated'])
    def test_unrelated_child_never_signalled(self):
        import subprocess
        child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'])
        try:
            with self.assertRaises(rt.ContainmentError):self.supervise('pass')
            self.assertIsNone(child.poll())
        finally:child.terminate();child.wait(timeout=3)
    def test_real_local_rss_timeout_then_next_root(self):
        request=r.load_request()
        for kind in ('rss','timeout'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as d:
                out=Path(d);helper=CampaignTests();helper.req=request;started=[]
                def invoke(std,tool,out,req,rid,limits,slot):
                    started.append(rid)
                    if len(started)==1:
                        execution=r.execute([sys.executable,'-c','import time;time.sleep(30)'],Path(d),out/'python-child',.12,rss_cap_kib=1 if kind=='rss' else 6*1024*1024,record_identity=True)
                        self.assertTrue(execution['child_shutdown_verified']);self.assertEqual(execution['termination_reason'],'rss_cap' if kind=='rss' else 'timeout')
                    return helper.emit(out,rid,kind if len(started)==1 else 'ok')
                c.run_campaign(Path('/std'),Path('/tool'),out,request,invoker=invoke);self.assertEqual(started,list(p.ORDER))


class PortablePrefixTests(unittest.TestCase):
    """Real control/packer/collector; only native execution/source sampling are fixtures."""
    def make_pair(self,base):
        import collect as collector
        request=r.load_request();out=base/'local';std=base/'std';tool=base/'tool'
        fp={'required_hashes_present':True,'binaries':{name:{'path':'/'+name,'sha256':'a'*64} for name in ('kani_driver','kani_compiler','cbmc')}}
        source={**c.identity(request),'changed_file_sha256':request['changed_file_sha256']}
        rid=p.ORDER[0]
        for index,current in enumerate(p.ORDER[:2]):
            row=c.group(request,current)['rows'][0]
            def execute(argv,cwd,dest,timeout,**kw):
                stock=fixtures.batch_export([row],request['source_bindings'])
                if index:stock.update(run_state='INCOMPLETE',harnesses=[])
                kw['export_path'].write_text(json.dumps(stock));kw['compile_monitor'].poll(1,{})
                if index:
                    raw=('Checking harness '+row['selector']+'...\n').encode()
                    kw['rich_parser'].feed(raw);kw['rich_parser'].finish()
                else:
                    fixtures.feed_regular(kw['rich_parser'],stock)
                    raw=fixtures.render_regular(list(kw['rich_parser'].records.items()))
                (dest/'stdout.log').write_bytes(raw);(dest/'stderr.log').write_bytes(b'local synthetic stderr capture\n')
                target=Path(kw['env']['CARGO_TARGET_DIR'])
                (target/'core.kani-metadata.json').write_text(json.dumps({'proof_harnesses':[{'pretty_name':row['selector'],'crate_name':'core'}]}))
                return {'original_exit_code':1,'elapsed_seconds':2,'stdout_bytes':len(raw),'stderr_bytes':len(b'local synthetic stderr capture\n'),
                        'child_shutdown_verified':True,'process_identity':{'pid':2,'pgid':2,'start_ticks':22}}
            with mock.patch.object(r,'verify_source',return_value=source),mock.patch.object(r,'binary_fingerprints',return_value=fp),mock.patch.object(r,'group_memory_budget',return_value={'group_cap_kib':12*1024*1024}),mock.patch.object(r,'execute',side_effect=execute):
                results,fatal=r._run_group(std,tool,out,request,c.group(request,current),time.monotonic()+720,
                    isolated_limits={'stdout_bytes':100000,'stderr_bytes':10000,'export_bytes':100000})
            if index:self.assertIsNotNone(fatal);self.assertEqual(results[0]['outcome'],'UNKNOWN')
            else:self.assertIsNone(fatal);self.assertEqual(results[0]['outcome'],'RECORDED')
            c.root_outcome(out,request,current,synthetic_supervision())
            if not index:prefix=(out/rid/'receipt.json').read_bytes()
        c.finalize(out,request,'synthetic later failure');c.fallback(out,request)
        self.assertEqual((out/rid/'receipt.json').read_bytes(),prefix)
        self.assertTrue(c.read(out/rid/'receipt.json')['r5_expected_match'])
        pack_evidence.pack(out)
        return out,request,rid,prefix
    def upload_only(self,base,out):
        import shutil
        uploaded=base/'uploaded';uploaded.mkdir();shutil.copyfile(out/pack_evidence.NAME,uploaded/pack_evidence.NAME)
        return uploaded
    def archive_doc(self,uploaded):
        import gzip
        return json.loads(gzip.decompress((uploaded/pack_evidence.NAME).read_bytes()))
    def write_archive(self,uploaded,doc):
        import gzip
        (uploaded/pack_evidence.NAME).write_bytes(gzip.compress(json.dumps(doc,separators=(',',':')).encode(),mtime=0))
    def assert_rejected(self,uploaded,request,rid):
        import collect as collector
        for operation in (lambda:c.sealed(uploaded,collector.read_bytes,[rid]),lambda:collector.collect([uploaded],request)):
            with self.assertRaises((c.GlobalFailure,r.RunnerError,KeyError,ValueError)):operation()
    def test_archive_only_prefix_exact_seal_and_collect_after_later_failure(self):
        import collect as collector
        import shutil
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);out,request,rid,prefix=self.make_pair(base)
            seal=c.sealed(out)[rid];self.assertTrue(seal['local_only_file_digests'])
            self.assertTrue(all(name.endswith('.json') for name in seal['files']))
            uploaded=self.upload_only(base,out);doc=self.archive_doc(uploaded)
            self.assertEqual(doc['state'],'PACKAGED')
            self.assertFalse(any(name.endswith('.log') for name in doc['files']))
            # Frozen old protocol would require these absent raw payloads (review022b repro).
            for name in seal['local_only_file_digests']:
                self.assertNotIn(name,doc['files'])
                with self.assertRaises(KeyError):collector.read_bytes(uploaded/name)
            shutil.rmtree(out) # proves the upload cannot fall back to producer-side files
            replayed=c.sealed(uploaded,collector.read_bytes,[rid]);self.assertEqual(replayed[rid],seal)
            self.assertEqual(collector.read_bytes(uploaded/rid/'receipt.json'),prefix)
            result=collector.collect([uploaded],request)
            first=next(row for row in result['rows'] if row['id']==rid)
            later=next(row for row in result['rows'] if row['id']==p.ORDER[1])
            self.assertEqual(first['outcome'],'RECORDED');self.assertTrue(first['r5_expected_match'])
            self.assertEqual(later['outcome'],'UNKNOWN');self.assertFalse(result['full_inventory_complete'])
            self.assertEqual(result['proof_credit'],'NONE')
    def test_missing_required_structured_member_rejects_archive(self):
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);out,request,rid,prefix=self.make_pair(base);uploaded=self.upload_only(base,out);doc=self.archive_doc(uploaded)
            del doc['files']['groups/r5-'+rid+'/export.json'];self.write_archive(uploaded,doc)
            self.assert_rejected(uploaded,request,rid)
    def test_mutated_structured_member_with_updated_entry_hash_still_rejects(self):
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);out,request,rid,prefix=self.make_pair(base);uploaded=self.upload_only(base,out);doc=self.archive_doc(uploaded)
            entry=doc['files']['groups/r5-'+rid+'/properties.json'];changed=json.loads(entry['text']);changed['tampered']=True
            data=json.dumps(changed).encode();entry.update(text=data.decode(),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())
            self.write_archive(uploaded,doc);self.assert_rejected(uploaded,request,rid)
    def test_compact_cap_omission_is_explicit_and_never_qualified(self):
        import gzip
        with tempfile.TemporaryDirectory() as d:
            base=Path(d);out,request,rid,prefix=self.make_pair(base)
            # Non-required synthetic payload forces the bounded omission path;
            # leave sufficient room for its explicit fallback receipt envelope.
            (out/'extra.json').write_text(json.dumps({'padding':'x'*1000000}))
            pack_evidence.pack(out)
            original_size=len(gzip.decompress((out/pack_evidence.NAME).read_bytes()))
            with mock.patch.object(pack_evidence,'UNCOMPRESSED_CAP',original_size//2):result=pack_evidence.pack(out)
            self.assertEqual(result['state'],'INCOMPLETE')
            self.assertEqual((out/rid/'receipt.json').read_bytes(),prefix)
            uploaded=self.upload_only(base,out);self.assertEqual(self.archive_doc(uploaded)['state'],'INCOMPLETE')
            self.assert_rejected(uploaded,request,rid)

if __name__=='__main__':unittest.main()
