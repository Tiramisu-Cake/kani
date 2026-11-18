# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Real file/hash/capture/argv/writer regression; no dummy file is executed.

Git identities, resource telemetry and native execution/supervision are synthetic.
Source validation, binary writers, controller capture and readers are real.
"""
import copy,errno,json,os,shlex,signal,tempfile,time,unittest
from contextlib import ExitStack,contextmanager
from pathlib import Path
from unittest import mock
import runner as r
import s3_campaign as c
import s3_evidence as ev
import test_s3 as f
import test_runner as native
import pack_evidence

class RealPathWriterTests(unittest.TestCase):
    @contextmanager
    def fixture(self,arg='tool',fault=None,interrupted=False):
        req=r.load_request()
        with tempfile.TemporaryDirectory() as d,ExitStack() as stack:
            root=Path(d);std=root/'export';tool=root/'tool';out=root/'out'
            for rel,text in json.loads((r.HERE/'S3-SOURCE.json').read_text()).items():
                path=std/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
            for directory in ('tool','wrong'):
                for name in ('kani-driver','kani-compiler'):
                    path=root/directory/'target/kani/bin'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(('bounded-dummy-'+name).encode())
            bin_dir=root/'bin';bin_dir.mkdir();cbmc=bin_dir/'cbmc';cbmc.write_bytes(b'bounded-dummy-cbmc');cbmc.chmod(0o700)
            (root/'nested').mkdir();(root/'alias').symlink_to(tool,target_is_directory=True)
            previous=Path.cwd();os.chdir(root);stack.callback(os.chdir,previous)
            stack.enter_context(mock.patch.dict(os.environ,{'PATH':str(bin_dir)}))
            # Git identities are fixture data. verify_source itself still checks
            # source hashes, anchors, siblings and every runtime dependency.
            def git(repo,*args):
                repo=Path(repo).resolve();prefix='std' if repo==std else 'tool'
                if args==('status','--porcelain=v1'):return ''
                if args==('cat-file','-t',req[prefix+'_sha']):return 'commit'
                if args==('rev-parse','HEAD'):return req[prefix+'_sha'] if repo in (std,tool) else 'c'*40
                if args==('rev-parse','HEAD^{tree}'):return req[prefix+'_tree'] if repo in (std,tool) else 'd'*40
                if args==('rev-parse','HEAD^'):return req['control_parent']
                raise AssertionError((repo,args))
            stack.enter_context(mock.patch.object(r,'git',side_effect=git))
            stack.enter_context(mock.patch.object(r,'group_memory_budget',return_value={'group_cap_kib':6*1024*1024}))
            launches=[];commands=[]
            def execute(argv,cwd,dest,timeout,**kw):
                selector=argv[argv.index('--harness')+1];row=next(x for x in req['rows'] if x['selector']==selector);binding=req['source_bindings'][row['id']]
                parsed,props=f.inventory(row)
                for prop in props['properties']:prop['file']=str(std/binding['file'])
                h=parsed['harness'];h['failed_properties']=[copy.deepcopy(x) for x in props['properties'] if x['status']=='FAILURE']
                data=native.export(selector=selector,mode='pfc' if row['mode']=='PFC' else 'original')
                base=data['harnesses'][0];base.update(h,file=binding['file'],line=binding['locations'][0]['line'],resolved_unwind=row['unwind'])
                if row['mode']=='PFC':base['attributes']['kind']['ProofForContract']['target_fn']=binding['target']
                initial=copy.deepcopy(data);initial['run_state']='INCOMPLETE';initial.pop('harnesses')
                kw['export_path'].write_text(json.dumps(initial));kw['compile_monitor'].poll(.01,{})
                lines=['Checking harness '+selector+'...','RESULTS:']
                for index,prop in enumerate(props['properties']):
                    lines+=['Check '+str(index+1)+': '+prop['id'],'\t - Status: '+prop['status'],'\t - Description: "'+prop['description']+'"','\t - Location: '+prop['file']+':'+prop['line']+' in function synthetic']
                lines+=['SUMMARY:'];kw['rich_parser'].feed(('\n'.join(lines)+'\n').encode());kw['rich_parser'].finish()
                kw['export_path'].write_text(json.dumps(data))
                meta=Path(kw['env']['CARGO_TARGET_DIR'])/'debug/deps/core.kani-metadata.json';meta.parent.mkdir(parents=True,exist_ok=True)
                meta.write_text(json.dumps({'crate_name':'core','proof_harnesses':[{'pretty_name':selector,'crate_name':'core','attributes':base['attributes'],'contract':base['contract']}]}))
                return {'original_exit_code':1 if h['n_failed'] else 0,'signal':None,'timed_out':False,'elapsed_seconds':.02,
                        'stdout_bytes':sum(len(x)+1 for x in lines),'stderr_bytes':0,'child_shutdown_verified':True,'process_identity':{'pid':2,'pgid':2,'start_ticks':22}}
            stack.enter_context(mock.patch.object(r,'execute',side_effect=execute))
            def supervise(argv,cwd,env,slot,rss,stderr,cap):
                commands.append(argv[:]);rid=argv[argv.index('--root')+1];launches.append(rid)
                val=lambda name:Path(argv[argv.index(name)+1])
                self.assertEqual(c.worker(val('--std'),val('--tool'),val('--out'),req,rid,c.read(val('--limits'))),0)
                sup=f.supervision();gp=out/'groups'/('s3-'+rid)/'receipt.json'
                if interrupted and rid==c.p.ORDER[2]:
                    # Truncate the actual writer record at process death before
                    # AFTER; no recorded error is cleared to permit recovery.
                    doc=c.read(gp);doc.update(state='IN_PROGRESS');doc['execution'].update(original_exit_code=-15,signal=15)
                    for key in ('source_after','tool_fingerprints_after','binary_identity'):doc.pop(key,None)
                    doc['execution_exception']={'type':'SyntheticInterruption','message':'original interruption'}
                    c.atomic(gp,doc);sup.update(worker_exit=-15,cutoff='slot_wall')
                if fault:fault(root,out,rid,val('--tool'),sup)
                return sup
            stack.enter_context(mock.patch.object(c.rt,'supervise',side_effect=supervise))
            yield root,std,tool,out,req,tool if arg=='ABSOLUTE' else Path(arg),launches,commands

    def run_fixture(self,fix):
        code=c.run_campaign(Path('export'),fix[5],fix[3],fix[4])
        return code,c.read(fix[3]/'receipt.json')

    def equal_captures(self,fix):
        root,std,tool,out,req,arg,launches,commands=fix;base=c.read(out/'baseline.json');self.assertEqual(base['state'],'COMPLETE')
        for rid,command in zip(launches,commands):
            self.assertEqual(command[command.index('--tool')+1],str(tool))
            life=c.read(out/'workers'/(rid+'-lifecycle.json'));doc=c.read(out/'groups'/('s3-'+rid)/'receipt.json')
            for snap in (life['pre']['binaries'],life['post']['binaries'],doc['tool_fingerprints_before'],doc.get('tool_fingerprints_after',doc['tool_fingerprints_before'])):
                self.assertTrue(r.fingerprints_match(base['binaries'],snap))
                for name,suffix in (('kani_driver','kani-driver'),('kani_compiler','kani-compiler')):
                    self.assertEqual(snap['binaries'][name]['path'],str(tool/'target/kani/bin'/suffix))
                    self.assertEqual(snap['binaries'][name]['sha256'],r.sha256(tool/'target/kani/bin'/suffix))

    def portable(self,fix):
        out=fix[3];local=c.collect([out],fix[4]);pack_evidence.pack(out)
        upload=fix[0]/'upload';upload.mkdir();(upload/pack_evidence.NAME).write_bytes((out/pack_evidence.NAME).read_bytes())
        self.assertEqual(c.collect([upload],fix[4]),local);return local

    def test_workflow_relative_entry_real_writer_and_portable_replay(self):
        workflow=f.check_package.load_yaml((r.HERE.parent/'.github/workflows/ch8-s2.yml').read_text())
        command=next(step['run'] for step in workflow['jobs']['s3_leaf']['steps'] if step['name']=='Run S3 actual leaves with bounded observations')
        argv=shlex.split(command);tool_arg=argv[argv.index('--tool')+1]
        self.assertEqual(tool_arg,'tool');self.assertEqual(argv[argv.index('--std')+1],'export')
        with self.fixture(tool_arg) as fix:
            code,terminal=self.run_fixture(fix);self.assertEqual(code,0,terminal['stop_reason']);self.equal_captures(fix)
            self.assertEqual(terminal['s3_campaign']['completed'],list(c.p.ORDER))
            self.assertTrue(all(x.get('s3_expected_match') for x in self.portable(fix)['rows']))
            self.assertTrue(all(x['proof_credit']=='NONE' for x in terminal['rows']))

    def test_absolute_parent_cwd_and_directory_symlink_inputs(self):
        for arg in ('ABSOLUTE','./tool','nested/../tool','alias'):
            with self.subTest(arg=arg),self.fixture(arg) as fix:
                code,terminal=self.run_fixture(fix);self.assertEqual(code,0,terminal['stop_reason']);self.equal_captures(fix)

    def test_unrepaired_relative_controller_absolute_worker_shape(self):
        with self.fixture() as fix:
            controller=c.snapshots.capture(Path('export'),Path('tool'),fix[4],{},'E0');worker=r.snapshot_binaries(fix[2],{},'before')
            self.assertEqual(controller['state'],'COMPLETE');self.assertFalse(r.fingerprints_match(controller['binaries'],worker))
            for name in ('kani_driver','kani_compiler'):
                self.assertEqual(controller['binaries']['binaries'][name]['sha256'],worker['binaries'][name]['sha256'])
                self.assertFalse(Path(controller['binaries']['binaries'][name]['path']).is_absolute());self.assertTrue(Path(worker['binaries'][name]['path']).is_absolute())

    def test_wrong_directory_with_same_bytes_still_rejects(self):
        def fault(root,out,rid,tool,sup):
            if rid!=c.p.ORDER[2]:return
            gp=out/'groups'/('s3-'+rid)/'receipt.json';doc=c.read(gp);doc['tool_fingerprints_before']=r.snapshot_binaries(root/'wrong',{},'before');c.atomic(gp,doc)
        with self.fixture(fault=fault) as fix:
            code,terminal=self.run_fixture(fix);self.assertEqual(code,1);self.assertIn('binary drift: before',terminal['stop_reason']);self.prefix(fix,terminal)

    def prefix(self,fix,terminal):
        self.assertEqual(terminal['s3_campaign']['completed'],list(c.p.ORDER[:2]));self.assertEqual(fix[6],list(c.p.ORDER[:3]))
        self.assertTrue(all(x['status']=='NOT_RUN' for x in terminal['rows'][3:]))

    def test_real_hash_mutation_global_stop_and_portable_prefix(self):
        def fault(root,out,rid,tool,sup):
            if rid==c.p.ORDER[2]:(tool/'target/kani/bin/kani-driver').write_bytes(b'real mutation')
        with self.fixture(fault=fault) as fix:
            code,terminal=self.run_fixture(fix);self.assertEqual(code,1);self.assertIn('binary drift',terminal['stop_reason']);self.prefix(fix,terminal)
            self.assertTrue(self.portable(fix)['global_stop'])

    def test_missing_binary_and_real_read_error_fail_closed(self):
        for case in ('missing','read_error'):
            def fault(root,out,rid,tool,sup):
                if rid!=c.p.ORDER[2]:return
                target=tool/'target/kani/bin/kani-driver';gp=out/'groups'/('s3-'+rid)/'receipt.json';doc=c.read(gp)
                if case=='missing':target.unlink();snap=r.snapshot_binaries(tool,doc,'after')
                else:
                    original=Path.open
                    def denied(path,*a,**kw):
                        if path==target:raise PermissionError(errno.EACCES,'fixture denied',str(path))
                        return original(path,*a,**kw)
                    with mock.patch.object(Path,'open',denied):snap=r.snapshot_binaries(tool,doc,'after')
                self.assertEqual(snap['state'],'INCOMPLETE');self.assertTrue(doc['snapshot_errors']);c.atomic(gp,doc)
            with self.subTest(case=case),self.fixture(fault=fault) as fix:
                code,terminal=self.run_fixture(fix);self.assertEqual(code,1);self.assertTrue(terminal['stop_reason']);self.prefix(fix,terminal)

    def test_all_states_recorded_drift_cannot_use_controller_recovery(self):
        for state in ('COMPLETE','FAILED','IN_PROGRESS','INTERRUPTED',None,'UNKNOWN'):
            def fault(root,out,rid,tool,sup):
                if rid!=c.p.ORDER[2]:return
                gp=out/'groups'/('s3-'+rid)/'receipt.json';doc=c.read(gp);doc['state']=state
                (root/'wrong/target/kani/bin/kani-driver').write_bytes(b'recorded real drift')
                doc['tool_fingerprints_after']=r.snapshot_binaries(root/'wrong',{},'after')
                doc['execution'].update(original_exit_code=-15,signal=15);doc['reason']='original failed worker';c.atomic(gp,doc);sup.update(worker_exit=-15,cutoff='slot_wall')
            with self.subTest(state=state),self.fixture(fault=fault) as fix:
                code,terminal=self.run_fixture(fix);self.assertEqual(code,1);self.prefix(fix,terminal)
                doc=c.read(fix[3]/'groups'/('s3-'+c.p.ORDER[2])/'receipt.json')
                self.assertEqual(doc['execution']['original_exit_code'],-15);self.assertEqual(doc['reason'],'original failed worker')
                self.assertEqual(c.read(fix[3]/'workers'/(c.p.ORDER[2]+'-lifecycle.json'))['post']['state'],'COMPLETE')

    def test_real_writer_malformed_missing_error_and_state_tamper_reject(self):
        with self.fixture() as fix:
            self.assertEqual(self.run_fixture(fix)[0],0);rid=c.p.ORDER[0];out=fix[3];req=fix[4]
            doc=c.read(out/'groups'/('s3-'+rid)/'receipt.json');baseline=c.read(out/'baseline.json');sup=f.supervision()
            for field,value in (('tool_fingerprints_before','MISSING'),('tool_fingerprints_before',None),('tool_fingerprints_after',[]),('snapshot_errors',None),('source_after_error',{}),('state','NOT_RUN')):
                bad=copy.deepcopy(doc)
                if value=='MISSING':bad.pop(field)
                else:bad[field]=value
                with self.subTest(field=field,value=value),self.assertRaises(ev.EvidenceError):ev.protected(bad,req,baseline,sup,r.sha256(r.REQUEST_PATH))
            for field,value in (('state','INCOMPLETE'),('snapshot_completed',False),('required_hashes_present',False),('binaries',{})):
                bad=copy.deepcopy(doc);bad['tool_fingerprints_after'][field]=value
                with self.subTest(field=field),self.assertRaises(ev.EvidenceError):ev.protected(bad,req,baseline,sup,r.sha256(r.REQUEST_PATH))

    def test_actual_killed_python_worker_has_genuinely_absent_after(self):
        with self.fixture() as fix:
            root,std,tool,out,req,_,_,_=fix;rid=c.p.ORDER[0]
            base_context={'campaign_id':'actual-kill','request_sha256':r.sha256(r.REQUEST_PATH),'source_parent':req['source_parent'],'control_parent':req['control_parent']}
            context={**base_context,'baseline_context':base_context,'invocation_id':'kill-worker','root':rid,'rank':1,'epoch':'E1'}
            base=c.snapshots.capture(std,tool,req,base_context,'E0')
            pre=c.snapshots.capture(std,tool,req,context,'E1.pre')
            def stop_before_native(*args,**kw):
                os.kill(os.getpid(),signal.SIGSTOP)
                raise AssertionError('native callback must never resume')
            with mock.patch.object(r,'execute',side_effect=stop_before_native):
                pid=os.fork()
                if pid==0:
                    try:
                        os.setsid();c.worker(std,tool,out,req,rid,{'stdout_bytes':100000,'stderr_bytes':100000,'export_bytes':100000})
                    except BaseException:os._exit(2)
                    os._exit(3)
                reaped=False
                try:
                    waited,status=os.waitpid(pid,os.WUNTRACED)
                    if os.WIFEXITED(status) or os.WIFSIGNALED(status):reaped=True
                    self.assertEqual(waited,pid);self.assertTrue(os.WIFSTOPPED(status))
                    os.kill(pid,signal.SIGKILL);waited,status=os.waitpid(pid,0);reaped=True
                    self.assertTrue(os.WIFSIGNALED(status));self.assertEqual(os.WTERMSIG(status),signal.SIGKILL)
                finally:
                    if not reaped:
                        try:os.kill(pid,signal.SIGKILL)
                        except ProcessLookupError:pass
                        os.waitpid(pid,0)
            # This test child has no descendants and has been waited/reaped.
            sup={'worker_exit':-signal.SIGKILL,'containment':{'verified':True}}
            post=c.snapshots.capture(std,tool,req,context,'E1.post',sup['containment'])
            self.assertTrue(c.snapshots.validate_pair(base,pre,post,context))
            path=out/'groups'/('s3-'+rid)/'receipt.json';original=path.read_bytes();doc=json.loads(original)
            self.assertEqual(doc['state'],'IN_PROGRESS');self.assertNotIn('tool_fingerprints_after',doc)
            self.assertNotIn('source_after',doc);self.assertNotIn('binary_identity',doc)
            result=ev.protected(doc,req,base,sup,r.sha256(r.REQUEST_PATH))
            self.assertTrue(result['controller_recovery_used']);self.assertFalse(result['observed_errors_ignored'])
            self.assertEqual(path.read_bytes(),original)
            for changed in ({'worker_exit':0,'containment':{'verified':True}},{'worker_exit':-9,'containment':{'verified':False}}):
                with self.assertRaises(ev.EvidenceError):ev.protected(doc,req,base,changed,r.sha256(r.REQUEST_PATH))

    def test_genuine_absent_after_interruption_and_original_exit_preserved(self):
        with self.fixture(interrupted=True) as fix:
            code,terminal=self.run_fixture(fix);self.assertEqual(code,1);self.assertIsNone(terminal['stop_reason']);self.equal_captures(fix)
            row=terminal['rows'][2];self.assertTrue(row['worker_protected_evidence']['controller_recovery_used']);self.assertEqual(row['invocation_original_exit'],-15)
            self.assertEqual(row['invocation_signal'],15);self.assertEqual(row['outcome'],'UNKNOWN');self.assertFalse(row['s3_expected_match'])
            doc=c.read(fix[3]/'groups'/('s3-'+c.p.ORDER[2])/'receipt.json');self.assertNotIn('tool_fingerprints_after',doc)
            self.assertEqual(doc['execution_exception']['message'],'original interruption')
            for sup in ({**f.supervision(),'worker_exit':0,'cutoff':None},{**f.supervision(),'worker_exit':-15,'containment':{'verified':False}}):
                with self.assertRaises(ev.EvidenceError):ev.protected(doc,fix[4],c.read(fix[3]/'baseline.json'),sup,r.sha256(r.REQUEST_PATH))

if __name__=='__main__':unittest.main()
