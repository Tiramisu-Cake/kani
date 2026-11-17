# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Frozen retry regressions; child execution is synthetic, never Kani."""
import copy
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import check_package as c
import cell_retry_profile as p
import runner as r
import rich_evidence
import test_runner as f
import test_s105
import test_s107
import test_package

HERE=Path(__file__).resolve().parent

FALLBACK_CONTROLS = [
    'test_fallback_terminal_after_setup_failure_and_mid_run_interruption',
    'test_fallback_preserves_receipt_materializes_tail_and_bounds',
]


def overwrite_mutation_result():
    """Mutate only an in-memory function, below request/payload hash gates."""
    source=inspect.getsource(c.fallback)
    needle='if not receipt.exists():'
    assert source.count(needle)==1
    mutated=source.replace(needle,'if True:',1)
    namespace=dict(c.__dict__)
    exec(compile(mutated,'<cell-fallback-overwrite-mutation>','exec'),namespace)
    fn=namespace['fallback']
    before=hashlib.sha256(Path(c.__file__).read_bytes()).hexdigest()
    suite=unittest.TestSuite(test_package.PackageTests(name) for name in FALLBACK_CONTROLS)
    result=unittest.TestResult()
    with mock.patch.object(c,'fallback',fn):suite.run(result)
    assert result.testsRun==2 and len(result.failures)==2 and not result.errors, str(result.errors+result.failures)
    assert not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses
    assert all('None != 42' in detail for _,detail in result.failures), str(result.failures)
    with tempfile.TemporaryDirectory() as tmp:
        out=Path(tmp);dest=out/p.ROW_IDS[0];dest.mkdir()
        original={'id':p.ROW_IDS[0],'status':'OBSERVED','outcome':'UNKNOWN','original_exit':42,'signal':15,
                  'original_exception':{'type':'OSError','message':'captured synthetic outcome'}}
        (dest/'receipt.json').write_text(json.dumps(original));fn(out)
        overwritten=json.loads((dest/'receipt.json').read_text())
    assert original['original_exit']==42 and overwritten.get('original_exit') is None
    assert hashlib.sha256(Path(c.__file__).read_bytes()).hexdigest()==before
    return {'status':'PASS_MUTATION_REJECTED','mutation':'sole if not receipt.exists(): -> if True:',
            'placement':'in-memory fallback function only, below payload hash gates; no preflight hash failure',
            'controls_run':result.testsRun,'failed_controls':[test.id() for test,_ in result.failures],
            'failure_assertions':['None != 42' for _ in result.failures],'errors':len(result.errors),'skipped':len(result.skipped),
            'observed':{'original_exit_before':original['original_exit'],'original_exit_after':overwritten.get('original_exit'),
                        'status_after':overwritten['status']},
            'original_function_sha256':hashlib.sha256(source.encode()).hexdigest(),
            'mutant_function_sha256':hashlib.sha256(mutated.encode()).hexdigest(),
            'on_disk_fallback_module_sha256':before,'on_disk_files_changed':False}


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.request=r.load_request();self.group=r.select_groups(self.request)[0]

    def test_exact_pair_and_reject_extra_missing_wrong_selector_group(self):
        self.assertEqual(r.select_groups(self.request,[p.GROUP]),[self.group])
        self.assertEqual([g['id'] for g in r.select_groups(self.request)],[p.GROUP])
        self.assertEqual([x['id'] for x in self.group['rows']],p.ROW_IDS)
        bad_ids=[[],[p.GROUP,p.GROUP],['unknown'],[p.GROUP,'light-model-u5']]
        bad_ids += [[g['id']] for g in self.request['execution_groups'] if g['id']!=p.GROUP]
        for ids in bad_ids:
            with self.assertRaises(r.RunnerError):r.select_groups(self.request,ids)
        for mutate in (lambda g:g['rows'].pop(),lambda g:g['rows'].append(g['rows'][0]),
                       lambda g:g['rows'].reverse(),lambda g:g.update(id='other'),
                       lambda g:g['rows'][0].update(selector='wrong'),lambda g:g['rows'][0].update(mode='Original')):
            g=copy.deepcopy(self.group);mutate(g)
            with self.assertRaises(ValueError):p.validate_group(g)

    def test_argv_parser_and_invalid_timeout(self):
        argv=r.build_argv(Path('/std'),Path('/tool'),p.SELECTORS,34,Path('/tmp/e.json'))
        self.assertEqual(argv[argv.index('--harness-timeout')+1],'1200s')
        self.assertEqual([argv[i+1] for i,x in enumerate(argv) if x=='--harness'],p.SELECTORS)
        self.assertIn('--jobs=1',argv);self.assertIn('--exact',argv)
        for selectors,unwind in ((p.SELECTORS[:1],34),(p.SELECTORS+['wrong'],34),
                                (list(reversed(p.SELECTORS)),34),(['wrong'],34),(p.SELECTORS,33)):
            with self.assertRaises(r.RunnerError):r.build_argv(Path('/std'),Path('/tool'),selectors,unwind,Path('/tmp/e'))
        value=f.batch_export(self.group['rows'],self.request['source_bindings']);value['harness_timeout_s']=1200.0
        row=self.group['rows'][0]
        def parse(v):
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'e.json';path.write_text(json.dumps(v))
                return r.parse_export(path,row,source_binding=self.request['source_bindings'][row['id']],std=Path('/std'),group_selectors=p.SELECTORS)
        self.assertEqual(parse(value)['outcome'],'RECORDED')
        for selectors in (p.SELECTORS[:1],p.SELECTORS+['wrong'],list(reversed(p.SELECTORS))):
            bad=copy.deepcopy(value);bad['harness_timeout_s']=600
            self.assertFalse(r._selection_matches(bad,selectors))
        for timeout in (600,0,-1,1201,'1200',True,None):
            bad=copy.deepcopy(value);bad['harness_timeout_s']=timeout
            self.assertEqual(parse(bad)['outcome'],'UNKNOWN')
        for kind in ('TIMEOUT','NOT_RUN','ERROR'):
            bad=copy.deepcopy(value);next(h for h in bad['harnesses'] if h['name']==row['selector'])['outcome']={'kind':kind}
            result=parse(bad);self.assertEqual(result['state'],'NOT_COMPLETED')
            self.assertEqual(result['outcome'],'UNKNOWN');self.assertEqual(result['reported_outcome'],{'kind':kind})

    def test_request_timeout_and_proof_settings_fail_closed(self):
        for rid in p.ROW_IDS:
            for timeout in (600,0,-1,1201,'1200',True,None):
                bad=copy.deepcopy(self.request);next(x for x in bad['rows'] if x['id']==rid)['timeout_seconds']=timeout
                with tempfile.TemporaryDirectory() as tmp:
                    path=Path(tmp)/'r.json';path.write_text(json.dumps(bad))
                    with self.assertRaises(r.RunnerError):r.load_request(path)
        mutations=[lambda x:x['rows'].pop(),lambda x:x['rows'].append(x['rows'][0]),
                   lambda x:next(r for r in x['rows'] if r['id'] not in p.ROW_IDS).update(timeout_seconds=1200),lambda x:x['rows'][-1].update(selector='wrong'),
                   lambda x:x['flags'].update(solver='other'),lambda x:x['budgets'].update(group_child_seconds=2100),
                   lambda x:x['budgets'].update(group_rss_max_kib=1),lambda x:x['source_bindings'][p.ROW_IDS[0]].update(target='wrong'),
                   lambda x:x.update(workflow_stages={'s1_light':['light-model-u5']}),
                   lambda x:x['execution_scope'].update(selected_groups=['light-model-u5'])]
        for mutate in mutations:
            bad=copy.deepcopy(self.request);mutate(bad)
            with self.assertRaises((ValueError,KeyError,TypeError)):p.validate_request(bad)

    def test_envelope_and_cell_only_fallback(self):
        b=self.request['budgets'];self.assertEqual(r.COMPILE_SECONDS+sum(x['timeout_seconds'] for x in self.group['rows']),3300)
        self.assertEqual(b['group_envelope_seconds'],3300+r.PHASE_CLEANUP_MARGIN)
        self.assertLessEqual(b['group_envelope_seconds'],r.PHASE_SECONDS)
        self.assertEqual(b['setup_seconds']+b['phase_seconds']+b['reserve_seconds'],180*60)
        self.assertEqual((r.COMPILE_SECONDS,r.GROUP_RSS_MAX_KIB,r.MEMORY_RESERVE_KIB),(900,12*1024**2,2*1024**2))
        with tempfile.TemporaryDirectory() as tmp:
            out=Path(tmp);c.fallback(out)
            self.assertEqual({x.name for x in (out/'groups').iterdir()},{p.GROUP})
            terminal=json.loads((out/'receipt.json').read_text())
            self.assertEqual(terminal['selected_groups'],[p.GROUP]);self.assertEqual([x['id'] for x in terminal['rows']],p.ROW_IDS)
            self.assertTrue(all(x['outcome']=='UNKNOWN' and x['status']=='NOT_RUN' for x in terminal['rows']))
            for ids in (['light-model-u5'],[p.GROUP,'light-model-u5']):
                with self.assertRaises(r.RunnerError):c.fallback(out,ids)

    def test_yaml_scope_caps_types(self):
        path=HERE.parent/'.github/workflows/ch8-s1.yml';self.assertEqual(c.check_yaml(path)['yaml'],'PASS')
        doc=c.load_yaml(path.read_text())
        mutations=[lambda d:d['jobs'].update(other=copy.deepcopy(d['jobs']['s1_cell'])),
                   lambda d:d['jobs']['s1_cell']['strategy']['matrix'].update(group=['light-model-u5']),
                   lambda d:d['jobs']['s1_cell'].update(needs='s1_light'),lambda d:d['concurrency'].update({'cancel-in-progress':True}),
                   lambda d:d['jobs']['s1_cell'].update({'timeout-minutes':179}),
                   lambda d:d['jobs']['s1_cell']['steps'][1]['with'].update({'fetch-depth':2}),
                   lambda d:d['jobs']['s1_cell']['steps'][1]['with'].update({'fetch-depth':'5'}),
                   lambda d:d['jobs']['s1_cell']['strategy'].update({'max-parallel':2}),lambda d:d['on'].update(workflow_dispatch={})]
        import yaml
        for mutate in mutations:
            bad=copy.deepcopy(doc);mutate(bad)
            with tempfile.TemporaryDirectory() as tmp:
                path=Path(tmp)/'bad.yml';path.write_text(yaml.safe_dump(bad))
                with self.assertRaises(AssertionError):c.check_yaml(path)

    def test_reuse_existing_export_and_rich_controls(self):
        suite=unittest.defaultTestLoader.loadTestsFromTestCase(f.ExportTests)
        suite.addTests(test_s105.RichTests(name) for name in unittest.defaultTestLoader.getTestCaseNames(test_s105.RichTests)
                       if name!='test_complete_matrix_survives_compact_collection')
        result=unittest.TestResult();suite.run(result)
        self.assertTrue(result.wasSuccessful(),str(result.errors+result.failures))

    def test_fallback_overwrite_mutation_is_detected(self):
        receipt=overwrite_mutation_result()
        self.assertEqual(receipt['status'],'PASS_MUTATION_REJECTED')

    def test_reuse_existing_service_preflight_controls(self):
        # Keep the original small process/build/snapshot controls in preflight.
        # Matrix-wide fixtures are replaced by exact pair service cases below.
        suite=unittest.TestSuite()
        for cls in (f.ExecutionTests,f.CompileTests,f.NoListBindingTests):
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(cls))
        cases={f.RequestTests:['test_source_binding_and_dirty_or_file_drift','test_rejects_unpinned_rustflags'],
               f.GroupTests:['test_group_memory_budget_host_and_cgroup'],
               test_package.PackageTests:['test_control_guards_and_payload_drift','test_build_wrapper_receipts_and_errors_without_build',
                   'test_fallback_terminal_after_setup_failure_and_mid_run_interruption',
                   'test_fallback_preserves_receipt_materializes_tail_and_bounds'],
               test_s107.FinalizationTests:['test_partial_export_pack_retains_later_rich_and_metadata_without_completion',
                   'test_individual_hash_error_keeps_other_required_measurements_without_export',
                   'test_monitor_exception_reaps_synthetic_child_and_keeps_original_exit',
                   'test_snapshot_flags_cannot_replace_required_paths_and_hashes'],
               test_s107.LocationTests:['test_exact_two_ids_and_all_authorized_rows_keep_nullable_site_and_receipt',
                   'test_every_changed_exception_field_and_foreign_harness_fail_closed']}
        for cls,names in cases.items():suite.addTests(cls(name) for name in names)
        result=unittest.TestResult();suite.run(result)
        self.assertTrue(result.wasSuccessful(),str(result.errors+result.failures))

class ServiceTests(unittest.TestCase):
    def run_case(self,root,case='success',snapshot='success'):
        request=r.load_request();group=r.select_groups(request)[0]
        std=root/'std';std.mkdir();tool=root/'tool';out=root/'out';events=[]
        fp={'required_hashes_present':True,'binaries':{name:{'path':name,'sha256':'a'*64} for name in ('kani_driver','kani_compiler','cbmc')}}
        def fingerprint(tool,export):
            events.append('after' if events else 'before')
            if events[-1]=='after':
                self.assertIn('child_stopped',events)
                if snapshot=='error':raise OSError('snapshot error')
                if snapshot=='missing':return {'required_hashes_present':False,'binaries':{}}
                if snapshot=='drift':return {**fp,'binaries':{**fp['binaries'],'cbmc':{'path':'cbmc','sha256':'b'*64}}}
            return copy.deepcopy(fp)
        def execute(argv,cwd,dest,timeout,**kw):
            self.assertEqual(timeout,3300);self.assertEqual(argv[argv.index('--harness-timeout')+1],'1200s')
            events.append('child_started');value=f.batch_export(group['rows'],request['source_bindings']);value['harness_timeout_s']=1200.0
            kw['export_path'].write_text(json.dumps(value));kw['compile_monitor'].poll(0.01,{})
            if case!='missing_RESULTS':f.feed_regular(kw['rich_parser'],value)
            else:
                kw['rich_parser'].feed(('Checking harness '+p.SELECTORS[0]+'...\n').encode());kw['rich_parser'].finish()
                next(h for h in value['harnesses'] if h['name']==p.SELECTORS[0])['outcome']={'kind':'TIMEOUT'}
            native=Path(kw['env']['CARGO_TARGET_DIR'])/'debug/deps/core.kani-metadata.json';native.parent.mkdir(parents=True,exist_ok=True)
            native.write_text(json.dumps({'crate_name':'core','proof_harnesses':[
                {'pretty_name':h['name'],'crate_name':'core','mangled_name':'synthetic_'+h['name'],'attributes':h['attributes'],'contract':h['contract']} for h in value['harnesses']]}))
            if case.startswith('native_'):
                shape=case.removeprefix('native_')
                if shape=='missing':native.unlink()
                elif shape=='partial':native.write_text('{')
                elif shape=='null':native.write_text('null')
                elif shape=='wrong_type':native.write_text('[]')
                elif shape=='unmatched':native.write_text('{"proof_harnesses": []}')
                elif shape=='invalid_utf8':native.write_bytes(b'\xff{')
                elif shape=='duplicate':
                    data=json.loads(native.read_text());data['proof_harnesses']*=2;native.write_text(json.dumps(data))
            events.append('child_stopped')
            if case=='exception':raise OSError('original execution exception')
            if case=='partial':value={'run_state':'PARTIAL'}
            if case=='null':value=None
            if case=='wrong_type':value=[]
            if case=='wrong600':value['harness_timeout_s']=600
            if case in ('NOT_RUN','TIMEOUT'):value['harnesses'][0]['outcome']={'kind':case}
            if case=='target_mismatch':value['harnesses'][0]['attributes']['kind']['ProofForContract']['target_fn']='wrong'
            if case=='source_mismatch':value['harnesses'][0]['file']='wrong.rs'
            if case=='stage_mismatch':value['run_state']='INCOMPLETE'
            if case=='missing':kw['export_path'].unlink()
            else:kw['export_path'].write_text(json.dumps(value))
            return {'original_exit_code':42 if case=='error' else 1 if case in ('NOT_RUN','TIMEOUT','missing_RESULTS') else 0,
                    'signal':None,'rss_peak_kib':1,'elapsed_seconds':0.02,'timed_out':case=='timeout',
                    'termination_reason':'timeout' if case=='timeout' else None}
        validate=rich_evidence.RegularEvidence.validate
        def validating(parser,stock):
            self.assertEqual(events[-1],'after');return validate(parser,stock)
        with mock.patch.object(r,'binary_fingerprints',side_effect=fingerprint),mock.patch.object(r,'verify_source',side_effect=[{},r.RunnerError('post source drift')] if case=='post_source' else None,return_value={}), \
             mock.patch.object(r,'group_memory_budget',return_value={'group_cap_kib':r.GROUP_RSS_MAX_KIB}), \
             mock.patch.object(r,'_run_variant',return_value=(None,{})),mock.patch.object(r,'execute',side_effect=execute), \
             mock.patch.object(rich_evidence.RegularEvidence,'validate',validating):
            code=r.run_rows(std,tool,out,request)
        return code,json.loads((out/'receipt.json').read_text()),json.loads((out/'groups'/p.GROUP/'receipt.json').read_text()),events

    def test_success_errors_timeout_partial_original_exit_and_snapshots(self):
        for case in ('success','error','exception','timeout','partial','missing','null','wrong_type','NOT_RUN','TIMEOUT',
                     'missing_RESULTS','source_mismatch','stage_mismatch','target_mismatch','wrong600','post_source'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as tmp:
                code,terminal,receipt,events=self.run_case(Path(tmp),case)
                self.assertEqual(events,['before','child_started','child_stopped','after'])
                self.assertEqual(terminal['selected_groups'],[p.GROUP]);self.assertEqual(terminal['proof_credit'],'NONE')
                self.assertEqual(receipt['group_budget_seconds'],3300);self.assertEqual(receipt['timeout_seconds'],3300)
                self.assertEqual(receipt['binding_metadata']['native_files'],1)
                selected=[x for x in terminal['rows'] if x['id'] in p.ROW_IDS]
                self.assertTrue(all(x['root_timeout_seconds']==1200 for x in selected))
                self.assertTrue(all(x['status']=='NOT_SELECTED' for x in terminal['rows'] if x['id'] not in p.ROW_IDS))
                if case=='success':
                    self.assertEqual(code,0,terminal['stop_reason'])
                    self.assertTrue(all(x['root_timeout_seconds']==1200 and x['outcome']=='RECORDED' for x in selected))
                else:self.assertEqual(code,1);self.assertTrue(any(x['outcome']=='UNKNOWN' for x in selected))
                if case=='exception':self.assertEqual(receipt['execution_exception']['message'],'original execution exception')
                else:self.assertEqual(receipt['execution']['original_exit_code'],42 if case=='error' else 1 if case in ('NOT_RUN','TIMEOUT','missing_RESULTS') else 0)
                if case=='missing_RESULTS':self.assertIn('missing regular harness RESULTS',receipt['reason'])
        for snapshot in ('error','missing','drift'):
            with tempfile.TemporaryDirectory() as tmp:
                code,_,receipt,_=self.run_case(Path(tmp),'error',snapshot)
                self.assertEqual(code,1);self.assertEqual(receipt['binary_identity'],'UNKNOWN');self.assertEqual(receipt['execution']['original_exit_code'],42)

    def test_native_error_shapes_keep_unknown_and_metadata(self):
        for shape in ('missing','partial','null','wrong_type','unmatched','duplicate','invalid_utf8'):
            with self.subTest(shape=shape),tempfile.TemporaryDirectory() as tmp:
                code,terminal,receipt,_=self.run_case(Path(tmp),'native_'+shape)
                self.assertEqual(code,1)
                self.assertTrue(receipt['binding_metadata']['errors'])
                self.assertTrue(all(x['outcome']=='UNKNOWN' for x in terminal['rows'] if x['id'] in p.ROW_IDS))
                self.assertEqual(receipt['execution']['original_exit_code'],0)
        with tempfile.TemporaryDirectory() as tmp,mock.patch.object(r,'capture_binding_metadata',side_effect=OSError('metadata capture failed')):
            code,_,receipt,_=self.run_case(Path(tmp),'error')
            self.assertEqual(code,1);self.assertEqual(receipt['execution']['original_exit_code'],42)
            self.assertIn('metadata capture failed',receipt['binding_metadata_error'])

if __name__=='__main__':unittest.main()
