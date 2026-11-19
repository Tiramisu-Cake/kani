# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""S1-07 synthetic finalization/location regressions; no compiler or verifier."""
import copy
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import collect
import binding_metadata
import pack_evidence
import gzip
import rich_evidence as rich
import runner as r
import test_runner as runner_tests
from test_runner import row, binding, batch_export, feed_regular, render_regular
from test_s105 import stock_for


class FinalizationTests(unittest.TestCase):
    def run_case(self, root, case='success', snapshot='success'):
        std=root/'std'; std.mkdir(); tool=root/'tool'; out=root/'out'
        selected=row(); request={'rows':[selected], 'changed_file_sha256':{},
                               'source_bindings':{selected['id']:binding(selected)}, 'variants':{}}
        group=r.group_rows(request['rows'])[0]
        events=[]
        fp={'required_hashes_present':True, 'binaries':{
            name:{'path':name,'sha256':'a'*64} for name in ('kani_driver','kani_compiler','cbmc')}}
        def fingerprint(tool, export):
            self.assertEqual(export,{})
            stage='before' if not events else 'after'
            events.append(stage)
            if stage=='after':
                self.assertIn('child_stopped', events)
                if snapshot=='error': raise OSError('synthetic snapshot error')
                changed=copy.deepcopy(fp)
                if snapshot=='missing':
                    changed['binaries']['cbmc']['sha256']=None
                    changed['required_hashes_present']=False
                if snapshot=='drift':changed['binaries']['cbmc']['sha256']='b'*64
                return changed
            return copy.deepcopy(fp)
        def execute(argv, cwd, dest, timeout, **kw):
            events.append('child_started')
            data=batch_export([selected],request['source_bindings'])
            kw['export_path'].write_text(json.dumps(data))
            kw['compile_monitor'].poll(0.01,{})
            feed_regular(kw['rich_parser'],data)
            native=Path(kw['env']['CARGO_TARGET_DIR'])/'debug/deps/core.kani-metadata.json'
            native.parent.mkdir(parents=True,exist_ok=True)
            native.write_text(json.dumps({'crate_name':'core','proof_harnesses':[
                {'pretty_name':selected['selector'],'crate_name':'core','mangled_name':'observed_wrapper',
                 'attributes':data['harnesses'][0]['attributes'],'contract':data['harnesses'][0]['contract']}]}))
            (Path(kw['env']['CARGO_TARGET_DIR']).parent/'stale.kani-metadata.json').write_text('{"stale":true}')
            events.append('child_stopped')
            if case=='exception':raise OSError('original execution exception')
            if case=='partial':data={'run_state':'PARTIAL'}
            if case=='null':data=None
            if case=='wrong_type':data=[]
            if case=='NOT_RUN':data['harnesses'][0]['outcome']={'kind':'NOT_RUN'}
            if case=='target_mismatch':data['harnesses'][0]['attributes']['kind']['ProofForContract']['target_fn']='wrong'
            if case=='source_mismatch':data['harnesses'][0]['file']='wrong.rs'
            if case=='stage_mismatch':data['run_state']='INCOMPLETE'
            if case=='missing':kw['export_path'].unlink()
            else:kw['export_path'].write_text(json.dumps(data))
            code=42 if case=='error' else 1 if case=='NOT_RUN' else 0
            return {'original_exit_code':code,'signal':None,'rss_peak_kib':1,'elapsed_seconds':0.02,
                    'timed_out':case=='timeout', 'termination_reason':'timeout' if case=='timeout' else None}
        validate=rich.RegularEvidence.validate
        def validating(parser, stock):
            events.append('rich_validation')
            self.assertIn('after',events)
            if case=='rich_error':raise ValueError('original rich error')
            return validate(parser,stock)
        with mock.patch.object(r,'binary_fingerprints',side_effect=fingerprint), \
             mock.patch.object(r,'verify_source',return_value={}), \
             mock.patch.object(r,'group_memory_budget',return_value={'group_cap_kib':1024}), \
             mock.patch.object(r,'_run_variant',return_value=(None,{})), \
             mock.patch.object(r,'execute',side_effect=execute), \
             mock.patch.object(rich.RegularEvidence,'validate',validating):
            rows,fatal=r._run_group(std,tool,out,request,group,time.monotonic()+5000)
        dest=out/'groups'/group['id']
        return rows,fatal,json.loads((dest/'receipt.json').read_text()),json.loads((dest/'properties.json').read_text()),events

    def test_snapshot_before_validation_for_all_termination_and_export_shapes(self):
        for case in ('success','error','timeout','exception','rich_error','partial','missing','null',
                     'wrong_type','NOT_RUN','source_mismatch','stage_mismatch','target_mismatch'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                rows,fatal,receipt,properties,events=self.run_case(Path(tmp),case)
                self.assertEqual(events[:4],['before','child_started','child_stopped','after'])
                self.assertEqual(receipt['binary_identity'],'MATCH')
                self.assertEqual(receipt['snapshot_errors'],[])
                self.assertEqual(receipt['tool_fingerprints_after']['phase'],'AFTER_CHILD_SHUTDOWN')
                self.assertTrue(receipt['tool_fingerprints_after']['snapshot_completed'])
                self.assertEqual(receipt['tool_fingerprints_after']['missing_binaries'],[])
                self.assertEqual(receipt['binding_metadata']['native_files'],1)
                self.assertEqual(len(properties['harnesses'][0]['properties']),6)
                if case=='success':
                    self.assertIsNone(fatal); self.assertEqual(rows[0]['outcome'],'RECORDED')
                else:self.assertEqual(rows[0]['outcome'],'UNKNOWN')
                if case=='exception':
                    self.assertEqual(receipt['execution_exception']['message'],'original execution exception')
                    self.assertEqual(receipt['original_exception']['type'],'OSError')
                else:self.assertEqual(receipt['execution']['original_exit_code'],42 if case=='error' else 1 if case=='NOT_RUN' else 0)

    def test_snapshot_error_missing_and_drift_cannot_hide_original_failure(self):
        for case in ('success','error','exception','rich_error'):
            for snapshot in ('error','missing','drift'):
                with self.subTest(case=case,snapshot=snapshot),tempfile.TemporaryDirectory() as tmp:
                    rows,fatal,receipt,properties,_=self.run_case(Path(tmp),case,snapshot)
                    self.assertEqual(rows[0]['outcome'],'UNKNOWN')
                    self.assertEqual(receipt['binary_identity'],'UNKNOWN')
                    self.assertIn('tool_binary_missing_drift_or_snapshot_error',fatal)
                    self.assertEqual(len(properties['harnesses'][0]['properties']),6)
                    if snapshot!='drift':self.assertEqual(receipt['snapshot_errors'][0]['stage'],'after')
                    if case=='exception':self.assertIn('original execution exception',receipt['reason'])
                    if case=='rich_error':self.assertIn('original rich error',receipt['reason'])
                    if case=='error':self.assertEqual(receipt['execution']['original_exit_code'],42)

    def test_native_metadata_manifest_and_unavailable_instance_edges_survive_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            _,_,receipt,_,_=self.run_case(Path(tmp),'exception')
            path=Path(tmp)/'out/groups/production-u4/binding-metadata.json'
            data=path.read_bytes();metadata=json.loads(data)
            self.assertEqual(receipt['binding_metadata']['sha256'],binding_metadata.digest(data))
            self.assertEqual(receipt['binding_metadata']['bytes'],len(data))
            self.assertEqual(metadata['execution_exception']['message'],'original execution exception')
            self.assertEqual(metadata['invocation_id'],receipt['invocation_id'])
            self.assertIsNone(metadata['compilation_id'])
            self.assertEqual(metadata['rows'][0]['binding_gaps']['resolved_target'],binding_metadata.UNKNOWN)
            self.assertEqual(len(metadata['rows'][0]['native_harness_records']),1)
            for entry in metadata['native_metadata']:
                raw=entry['text'].encode()
                self.assertEqual(entry['sha256'],binding_metadata.digest(raw))
                self.assertEqual(entry['bytes'],len(raw))

    def test_metadata_capture_failure_keeps_original_exit_exception_and_rich_records(self):
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(r,'capture_binding_metadata',side_effect=OSError('metadata capture failed')):
            rows,fatal,receipt,properties,_=self.run_case(Path(tmp),'error')
            self.assertEqual(receipt['execution']['original_exit_code'],42)
            self.assertIn('group_exit_export_mismatch',receipt['original_exception']['message'])
            self.assertIn('metadata capture failed',receipt['binding_metadata_error'])
            self.assertEqual(rows[0]['outcome'],'UNKNOWN')
            self.assertEqual(len(properties['harnesses'][0]['properties']),6)

    def test_native_partial_null_wrong_type_missing_and_cap_are_explicit(self):
        for case in ('partial','null','wrong_type','missing','cap','unmatched','duplicate','invalid_utf8'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                def capture(dest,target,request,group,receipt):
                    native=next(target.rglob('*.kani-metadata.json'))
                    if case=='partial':native.write_text('{')
                    if case=='null':native.write_text('null')
                    if case=='wrong_type':native.write_text('{"proof_harnesses":null}')
                    if case=='missing':native.unlink()
                    if case=='invalid_utf8':native.write_bytes(b'\xff{')
                    if case in ('unmatched','duplicate'):
                        value=json.loads(native.read_text())
                        if case=='unmatched':value['proof_harnesses'][0]['pretty_name']='foreign'
                        else:value['proof_harnesses']*=2
                        native.write_text(json.dumps(value))
                    with mock.patch.object(binding_metadata,'NATIVE_BYTES_CAP',1 if case=='cap' else 8*1024*1024):
                        return binding_metadata.capture(dest,target,request,group,receipt)
                with mock.patch.object(r,'capture_binding_metadata',side_effect=capture):
                    rows,_,receipt,_,_=self.run_case(Path(tmp))
                metadata=json.loads((Path(tmp)/'out/groups/production-u4/binding-metadata.json').read_text())
                self.assertEqual(metadata['compiler_identity_status'],binding_metadata.UNKNOWN)
                self.assertEqual(rows[0]['outcome'],'UNKNOWN')
                self.assertTrue(receipt['binding_metadata']['errors'])
                if case=='missing':
                    self.assertEqual(metadata['native_metadata_state'],'MISSING_OR_NOT_PRODUCED')
                    self.assertEqual(receipt['binding_metadata']['native_files'],0)
                if case=='invalid_utf8':
                    entry=metadata['native_metadata'][0]
                    raw=base64.b64decode(entry['text'],validate=True)
                    self.assertEqual(raw,b'\xff{')
                    self.assertEqual(entry['sha256'],binding_metadata.digest(raw))
                    self.assertEqual(entry['bytes'],len(raw))

    def test_partial_export_pack_retains_later_rich_and_metadata_without_completion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/'export.json').write_text('{')
            for name in ('properties.json','receipt.json','binding-metadata.json'):
                (root/name).write_text(json.dumps({'retained':name}))
            packed=pack_evidence.pack(root)
            self.assertEqual(packed['state'],'INCOMPLETE')
            doc=json.loads(gzip.decompress((root/pack_evidence.NAME).read_bytes()))
            self.assertEqual(set(doc['files']),{'export.json','properties.json','receipt.json','binding-metadata.json'})
            self.assertEqual(doc['files']['export.json']['text'],'{')
            (root/'export.json').write_bytes(b'\xff{')
            self.assertEqual(pack_evidence.pack(root)['state'],'INCOMPLETE')
            doc=json.loads(gzip.decompress((root/pack_evidence.NAME).read_bytes()))
            self.assertIn('properties.json',doc['files'])
            self.assertEqual(doc['files']['export.json']['encoding'],'base64')

    def test_individual_hash_error_keeps_other_required_measurements_without_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool=Path(tmp)
            for name in ('kani-driver','kani-compiler'):
                path=tool/'target/kani/bin'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(name.encode())
            cbmc=tool/'cbmc';cbmc.write_bytes(b'cbmc')
            original=r.sha256
            def hashing(path):
                if path.name=='kani-driver':raise OSError('driver unavailable')
                return original(path)
            with mock.patch.object(r.shutil,'which',return_value=str(cbmc)),mock.patch.object(r,'sha256',side_effect=hashing):
                receipt={};fp=r.snapshot_binaries(tool,receipt,'after')
            self.assertFalse(fp['required_hashes_present'])
            self.assertIsNone(fp['binaries']['kani_driver']['sha256'])
            for name in ('kani_compiler','cbmc'):self.assertEqual(len(fp['binaries'][name]['sha256']),64)
            self.assertIn('driver unavailable',receipt['snapshot_errors'][0]['error'])

    def test_monitor_exception_reaps_synthetic_child_and_keeps_original_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            monitor=mock.Mock();monitor.poll.side_effect=OSError('original monitor failure')
            started=[];popen=subprocess.Popen
            def spawning(*args,**kw):
                proc=popen(*args,**kw);started.append(proc);return proc
            with mock.patch.object(r.subprocess,'Popen',side_effect=spawning):
                result=r.execute([sys.executable,'-c','import time; time.sleep(20)'],
                                 Path(tmp),Path(tmp)/'exec',5,compile_monitor=monitor)
            self.assertEqual(result['runner_exception']['message'],'original monitor failure')
            self.assertIsNotNone(result['original_exit_code'])
            self.assertEqual(started[0].poll(),result['original_exit_code'])
            self.assertFalse(r._group_has_live_members(started[0].pid))

    def test_snapshot_flags_cannot_replace_required_paths_and_hashes(self):
        valid={'required_hashes_present':True,'binaries':{
            name:{'path':name,'sha256':'a'*64} for name in ('kani_driver','kani_compiler','cbmc')}}
        self.assertTrue(r.fingerprints_match(valid,copy.deepcopy(valid)))
        for value in (None,[],{}, {'required_hashes_present':True,'binaries':{}},
                      {**valid,'required_hashes_present':1}):
            self.assertFalse(r.fingerprints_match(valid,value))
        for field,value in (('path',None),('path',''),('sha256',None),('sha256','wrong'),('error','error')):
            changed=copy.deepcopy(valid);changed['binaries']['cbmc'][field]=value
            self.assertFalse(r.fingerprints_match(changed,changed))


class LocationTests(unittest.TestCase):
    def document(self, name, pid):
        p={'id':pid,'display_id':pid,'class':'unreachable','description':'unreachable code',
           'status':'SUCCESS','file':None,'line':None,
           'location_display':'library/core/src/lib.rs:0:0 in function '+pid.removesuffix('.unreachable.1')}
        stock=stock_for([p]);stock['harnesses'][0]['name']=name
        parser=rich.RegularEvidence([name],Path('/std'))
        emitted={**p,'file':'library/core/src/lib.rs','line':'0:0 in function '+pid.removesuffix('.unreachable.1')}
        parser.feed(render_regular([(name,[emitted])]))
        parser.finish();parser.validate(stock)
        return parser,stock

    def test_exact_two_ids_and_all_authorized_rows_keep_nullable_site_and_receipt(self):
        self.assertEqual(len(set(rich.LOCATION_EXCEPTION_BINDINGS.values())),2)
        self.assertEqual(len(rich.LOCATION_EXCEPTION_BINDINGS),17)
        for name,pid in rich.LOCATION_EXCEPTION_BINDINGS.items():
            parser,stock=self.document(name,pid)
            doc=parser.document();self.assertEqual(doc['state'],'COMPLETE')
            p=doc['harnesses'][0]['properties'][0]
            self.assertIsNone(p['file']);self.assertIsNone(p['line'])
            self.assertEqual(doc['location_exceptions'][0]['property'],p)
            self.assertEqual(doc['qualified_acceptance'],'PENDING_OFFLINE_ACCEPTANCE')
            replay=rich.RegularEvidence([name],Path('/'));replay.records=parser.records;replay.finished=True
            replay.validate(stock);self.assertEqual(replay.location_exceptions(),doc['location_exceptions'])

    def test_every_changed_exception_field_and_foreign_harness_fail_closed(self):
        name,pid=next(iter(rich.LOCATION_EXCEPTION_BINDINGS.items()))
        parser,stock=self.document(name,pid)
        for field,value in (('id',pid+'x'),('display_id',pid+'x'),('class','assertion'),
                            ('status','UNREACHABLE'),('description','different'),('file','lib.rs'),
                            ('line','0'),('location_display','lib.rs:0:0'),('location_display',None)):
            replay=rich.RegularEvidence([name],Path('/'));replay.records=copy.deepcopy(parser.records);replay.finished=True
            replay.records[name][0][field]=value
            with self.subTest(field=field,value=value),self.assertRaises(ValueError):replay.validate(stock)
        replay=rich.RegularEvidence(['foreign'],Path('/'));replay.records={'foreign':parser.records[name]};replay.finished=True
        stock['harnesses'][0]['name']='foreign'
        with self.assertRaises(ValueError):replay.validate(stock)

    def test_collector_rechecks_snapshots_and_exact_exception_receipts(self):
        request=runner_tests.legacy_request()
        helper=runner_tests.GroupTests('test_all35_rows_fourteen_invocations_record_only_without_oracle_classification')
        with tempfile.TemporaryDirectory() as tmp:
            original=runner_tests.feed_regular
            def with_nullable_sites(parser,stock):
                original(parser,stock)
                entries=[]
                for name,props in parser.records.items():
                    props=copy.deepcopy(props)
                    if name in rich.LOCATION_EXCEPTION_BINDINGS:
                        pid=rich.LOCATION_EXCEPTION_BINDINGS[name]
                        p=next(p for p in props if p['status']=='SUCCESS')
                        p.update(id=pid,**{'class':'unreachable'},description='unreachable code',
                                 file='library/core/src/lib.rs',
                                 line='0:0 in function '+pid.removesuffix('.unreachable.1'))
                    entries.append((name,props))
                # Decode the actual synthetic display, rather than inserting a
                # previously accepted exception into the collector's records.
                replacement=rich.RegularEvidence(parser.selectors,parser.cwd)
                replacement.feed(render_regular(entries));replacement.finish()
                parser.__dict__.update(replacement.__dict__)
            with mock.patch.object(runner_tests,'feed_regular',side_effect=with_nullable_sites):
                code,_,_,out=helper.run_mock_batch(Path(tmp),request)
            self.assertEqual(code,0)
            source={k:request[k] for k in ('std_sha','std_tree','tool_sha','tool_tree','changed_file_sha256')}
            for group in request['execution_groups']:
                path=out/'groups'/group['id']/'receipt.json'
                receipt=json.loads(path.read_text());receipt.update(source_before=source,source_after=source)
                path.write_text(json.dumps(receipt))
            result=collect.collect([out],request)
            self.assertTrue(all(x['outcome']=='RECORDED' for x in result['rows']))
            self.assertEqual(result['proof_credit'],'NONE')
            group=request['execution_groups'][0];path=out/'groups'/group['id']/'receipt.json'
            baseline=json.loads(path.read_text())
            for mutation in ('missing','null','wrong_type','drift','snapshot_error'):
                receipt=copy.deepcopy(baseline)
                if mutation=='missing':receipt.pop('tool_fingerprints_after')
                if mutation=='null':receipt['tool_fingerprints_after']=None
                if mutation=='wrong_type':receipt['tool_fingerprints_after']=[]
                if mutation=='drift':receipt['tool_fingerprints_after']['binaries']['cbmc']={'sha256':'changed'}
                if mutation=='snapshot_error':receipt['snapshot_errors']=[{'stage':'after','error':'error'}]
                path.write_text(json.dumps(receipt))
                result=collect.collect([out],request);byid={x['id']:x for x in result['rows']}
                self.assertTrue(all(byid[rid]['outcome']=='UNKNOWN' for rid in group['row_ids']))
            receipt=copy.deepcopy(baseline);receipt['location_exceptions']=[{'policy':'forged'}]
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(r.RunnerError,'location exception receipt mismatch'):collect.collect([out],request)
            receipt=copy.deepcopy(baseline);receipt['binding_metadata']['sha256']='wrong'
            path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(r.RunnerError,'binding metadata identity/digest mismatch'):collect.collect([out],request)
            native_path=path.parent/'binding-metadata.json'
            original=json.loads(native_path.read_text())
            for case in ('missing','unmatched','duplicate','wrong_ref','entry_digest'):
                metadata=copy.deepcopy(original)
                if case=='missing':metadata['native_metadata']=[]
                if case=='duplicate':metadata['native_metadata']*=2
                if case=='wrong_ref':metadata['rows'][0]['native_harness_records']=[]
                if case=='entry_digest':metadata['native_metadata'][0]['sha256']='wrong'
                if case=='unmatched':
                    entry=metadata['native_metadata'][0];value=json.loads(entry['text'])
                    value['proof_harnesses'][0]['pretty_name']='foreign';entry['text']=json.dumps(value)
                    raw=entry['text'].encode();entry.update(bytes=len(raw),sha256=binding_metadata.digest(raw))
                raw=json.dumps(metadata).encode();native_path.write_bytes(raw)
                receipt=copy.deepcopy(baseline)
                receipt['binding_metadata'].update(bytes=len(raw),sha256=binding_metadata.digest(raw))
                path.write_text(json.dumps(receipt))
                with self.subTest(native=case),self.assertRaisesRegex(r.RunnerError,'native'):
                    collect.collect([out],request)


if __name__=='__main__':unittest.main()
