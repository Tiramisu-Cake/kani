"""R14 distinguishing regressions: actual writers, all states, portable readers."""
import copy,gzip,hashlib,json,tempfile,time,unittest
from pathlib import Path
from unittest import mock
import runner as r
import s3_campaign as c
import s3_evidence as ev
import test_s3 as f
import collect as collector
import pack_evidence


class ProvenanceRepairTests(unittest.TestCase):
    def actual(self):
        writes=[];original=r._write_json;case=f.SingletonRunnerTests()
        def record(path,value):
            writes.append((str(path),copy.deepcopy(value)));return original(path,value)
        try:
            with mock.patch.object(r,'_write_json',side_effect=record):rows,fatal,gp,_=case.exercise()
            self.assertIsNone(fatal)
            compiles=[v for path,v in writes if path.endswith('/compile/receipt.json')]
            self.assertTrue(compiles)
            return r.load_request(),gp,compiles
        finally:case.doCleanups()
    def test_actual_writers_and_metadata_use_request_not_legacy_patch_base(self):
        req,gp,compiles=self.actual();wanted=ev.identity(req)
        self.assertNotEqual(req['std_sha'],r.STD_SHA)
        for comp in compiles:self.assertEqual({k:comp[k] for k in ev.IDENTITIES},wanted)
        self.assertEqual({k:gp['source_under_test'][k] for k in ev.IDENTITIES},wanted)
        self.assertEqual(gp['source_under_test']['base_std_sha'],req['std_sha'])
        self.assertEqual(gp['source_under_test']['historical_patch_base_std_sha'],req['base_std_sha'])
        self.assertTrue(ev.provenance(gp,compiles[-1],req,req['rows'][3]['id'],r.sha256(r.REQUEST_PATH)))
    def test_provenance_readers_reject_missing_null_wrong_type_stale_source_tool(self):
        req,gp,compiles=self.actual();rid=req['rows'][3]['id'];comp=compiles[-1]
        for location in ('compile','source_under_test','group'):
            for key in ev.IDENTITIES:
                for value in ('MISSING',None,[],17,r.STD_SHA if key.startswith('std') else 'f'*40):
                    doc=copy.deepcopy(gp);compile_doc=copy.deepcopy(comp)
                    target=compile_doc if location=='compile' else doc['source_under_test'] if location=='source_under_test' else doc
                    if value=='MISSING':target.pop(key)
                    else:target[key]=value
                    with self.subTest(location=location,key=key,value=value),self.assertRaises(ev.EvidenceError):
                        ev.provenance(doc,compile_doc,req,rid,r.sha256(r.REQUEST_PATH))
        for key in ('base_std_sha','historical_patch_base_std_sha'):
            doc=copy.deepcopy(gp);doc['source_under_test'][key]=None
            with self.assertRaises(ev.EvidenceError):ev.provenance(doc,comp,req,rid,r.sha256(r.REQUEST_PATH))
    def test_local_finalizer_rejects_faults_in_actual_compile_writer(self):
        req=r.load_request()
        for field,value in (('std_sha',r.STD_SHA),('tool_sha',None),('std_tree',[]),('tool_tree','MISSING')):
            fixture=f.CampaignTests();fixture.setUp();original=r._write_json
            def badwrite(path,doc):
                if str(path).endswith('s3-'+c.p.ORDER[2]+'/compile/receipt.json'):
                    doc=copy.deepcopy(doc)
                    if value=='MISSING':doc.pop(field,None)
                    else:doc[field]=value
                return original(path,doc)
            with tempfile.TemporaryDirectory() as d,mock.patch.object(r,'_write_json',side_effect=badwrite):
                code,launches,terminal=fixture.run_case(Path(d),{})
                self.assertEqual(code,1);self.assertEqual(launches,list(c.p.ORDER[:3]));self.assertIn('compile identity',terminal['stop_reason'])
    def test_local_finalizer_rejects_actual_source_under_test_writer_fault(self):
        original=r.source_under_test_record
        def bad(*args):
            value=original(*args);value['base_std_sha']=r.STD_SHA;return value
        fixture=f.CampaignTests();fixture.setUp()
        with tempfile.TemporaryDirectory() as d,mock.patch.object(r,'source_under_test_record',side_effect=bad):
            code,launches,terminal=fixture.run_case(Path(d),{})
            self.assertEqual(code,1);self.assertEqual(launches,list(c.p.ORDER[:1]));self.assertIn('base_std_sha',terminal['stop_reason'])
    def test_legacy_compile_and_source_under_test_defaults_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d);mon=r.CompileMonitor(path/'receipt.json',path/'export.json',['legacy'])
            self.assertEqual(mon.receipt['std_sha'],r.STD_SHA);self.assertEqual(mon.receipt['tool_sha'],r.TOOL_SHA)
            self.assertNotIn('std_tree',mon.receipt)
            under=r.source_under_test_record({'changed_file_sha256':{}},'production',{},None)
            self.assertEqual(under['base_std_sha'],r.STD_SHA);self.assertNotIn('historical_patch_base_std_sha',under)


class SnapshotRepairTests(unittest.TestCase):
    def test_recorded_errors_stop_in_every_state_with_matching_controller_post(self):
        for state in ('COMPLETE','FAILED','IN_PROGRESS','INTERRUPTED',None,'UNKNOWN'):
            for error in ('source_after_error','binary_unreadable','source_mismatch'):
                fixture=f.CampaignTests();fixture.setUp();launches=[]
                def invoke(std,tool,out,request,rid,limits,slot):
                    launches.append(rid);sup=fixture.emit(out,rid)
                    if rid==c.p.ORDER[2]:
                        gp=out/'groups'/('s3-'+rid)/'receipt.json';doc=c.read(gp)
                        doc.update(state=state,status='FAILED',reason='original protected failure')
                        doc['execution'].update(original_exit_code=-15,signal=15)
                        if error=='source_after_error':
                            doc.pop('source_after');doc['source_after_error']={'operation':'snapshot.source_after','message':'std HEAD drift','errno':5}
                        elif error=='binary_unreadable':
                            doc['snapshot_errors']=[{'stage':'after','binary':'cbmc','error':'unreadable'}];doc['binary_identity']='UNKNOWN';doc['tool_fingerprints_after']['required_hashes_present']=False
                        else:doc['source_after']={}
                        c.atomic(gp,doc)
                    return sup
                with self.subTest(state=state,error=error),tempfile.TemporaryDirectory() as d:
                    out=Path(d)
                    with mock.patch.object(c.snapshots,'capture',side_effect=f.synthetic_capture):
                        self.assertEqual(c.run_campaign(Path('/std'),Path('/tool'),out,fixture.req,invoker=invoke),1)
                    self.assertEqual(launches,list(c.p.ORDER[:3]));terminal=c.read(out/'receipt.json')
                    self.assertTrue(terminal['stop_reason']);self.assertEqual(len(c.sealed(out)),2)
                    self.assertTrue(all(x['status']=='NOT_RUN' for x in terminal['rows'][3:]))
                    doc=c.read(out/'groups'/('s3-'+c.p.ORDER[2])/'receipt.json')
                    self.assertEqual(doc['execution']['original_exit_code'],-15);self.assertEqual(doc['reason'],'original protected failure')
                    self.assertEqual(c.read(out/'workers'/(c.p.ORDER[2]+'-lifecycle.json'))['post']['state'],'COMPLETE')
    def test_malformed_and_unknown_worker_protected_records_reject(self):
        fixture=f.CampaignTests();fixture.setUp()
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);sup=fixture.emit(out,c.p.ORDER[0]);doc=c.read(out/'groups'/('s3-'+c.p.ORDER[0])/'receipt.json');base={'binaries':f.binary()}
            self.assertFalse(ev.protected(doc,fixture.req,base,sup,r.sha256(r.REQUEST_PATH))['controller_recovery_used'])
            for field,value in [('snapshot_errors',None),('snapshot_errors',{}),('source_after',None),('source_before',[]),('tool_fingerprints_after',None),('binary_identity','UNKNOWN'),('state',None),('request_sha256',None),('source_after_error',{}),('source_before_error',None)]:
                bad=copy.deepcopy(doc);bad[field]=value
                with self.subTest(field=field,value=value),self.assertRaises(ev.EvidenceError):ev.protected(bad,fixture.req,base,sup,r.sha256(r.REQUEST_PATH))
    def test_missing_after_requires_real_verified_interruption_not_failed_label(self):
        fixture=f.CampaignTests();fixture.setUp()
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);sup=fixture.emit(out,c.p.ORDER[0],'timeout');doc=c.read(out/'groups'/('s3-'+c.p.ORDER[0])/'receipt.json');base={'binaries':f.binary()}
            self.assertTrue(ev.protected(doc,fixture.req,base,sup,r.sha256(r.REQUEST_PATH))['controller_recovery_used'])
            for changed in ({'worker_exit':0,'cutoff':None},{'containment':{'verified':False}}):
                with self.assertRaises(ev.EvidenceError):ev.protected(doc,fixture.req,base,{**sup,**changed},r.sha256(r.REQUEST_PATH))
            doc['source_after_error']={'message':'unreadable'}
            with self.assertRaises(ev.EvidenceError):ev.protected(doc,fixture.req,base,sup,r.sha256(r.REQUEST_PATH))


class PortableRepairTests(unittest.TestCase):
    def test_stopped_failure_remains_visible_in_local_and_upload_only_replay(self):
        def fault(out,rid):
            if rid!=c.p.ORDER[2]:return
            path=out/'groups'/('s3-'+rid)/'receipt.json';doc=c.read(path);doc.update(state='FAILED')
            doc.pop('source_after');doc['source_after_error']={'operation':'snapshot.source_after','message':'original drift'};c.atomic(path,doc)
        result=f.PortableReplayTests().exercise(fault=fault)
        records=result['global_stops'][0]['worker_evidence']
        self.assertEqual(records[0]['source_after_error']['message'],'original drift')
        self.assertEqual(records[0]['original_exit_code'],0)
    def test_resealed_portable_missing_null_wrong_type_stale_compile_and_source_ids_reject(self):
        def hook(out,upload,req):
            archive=upload/pack_evidence.NAME;original=archive.read_bytes();raw=json.loads(gzip.decompress(original));rid=c.p.ORDER[0];gid='s3-'+rid
            def encode(value):return json.dumps(value,indent=2,sort_keys=True).encode()+b'\n'
            for location in ('compile','source_under_test'):
                for value in ('MISSING',None,[],r.STD_SHA):
                    packet=copy.deepcopy(raw)
                    def read(name):return json.loads(packet['files'][name]['text'])
                    def put(name,obj):
                        data=encode(obj);packet['files'][name]={'text':data.decode(),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'encoding':'utf-8'}
                    group_name='groups/'+gid+'/receipt.json';meta_name='groups/'+gid+'/binding-metadata.json';compile_name='groups/'+gid+'/compile/receipt.json'
                    gp=read(group_name);meta=read(meta_name);comp=read(compile_name)
                    target=comp if location=='compile' else gp['source_under_test']
                    if value=='MISSING':target.pop('std_sha')
                    else:target['std_sha']=value
                    if location=='compile':
                        put(compile_name,comp)
                        for item in meta['artifacts']:
                            if item['path']=='compile/receipt.json':item.update(bytes=packet['files'][compile_name]['bytes'],sha256=packet['files'][compile_name]['sha256'])
                    else:meta['source_under_test']=copy.deepcopy(gp['source_under_test'])
                    put(meta_name,meta);gp['binding_metadata'].update(bytes=packet['files'][meta_name]['bytes'],sha256=packet['files'][meta_name]['sha256']);put(group_name,gp)
                    seal_name='completed/'+rid+'.json';seal=read(seal_name)
                    for name in seal['files']:seal['files'][name]=packet['files'][name]['sha256']
                    put(seal_name,seal);archive.write_bytes(gzip.compress(json.dumps(packet).encode(),mtime=0))
                    with self.subTest(location=location,value=value),self.assertRaisesRegex(c.GlobalFailure,'replay protected/provenance'):
                        c.collect([upload],req)
            archive.write_bytes(original)
        f.PortableReplayTests().exercise(replay_hook=hook)
