# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Synthetic runner tests; they never build or invoke Kani, rustc, or CBMC."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack

RUNNER_PATH = Path(__file__).with_name('runner.py')
spec = importlib.util.spec_from_file_location('issue_mre_runner', RUNNER_PATH)
runner = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(runner)


def example(specification, defs):
    if isinstance(specification, list): return []
    if isinstance(specification, dict):
        return {k: example(v, defs) for k, v in specification.items() if not k.startswith('_')}
    if specification.startswith('ref:'): return example(defs[specification[4:]], defs)
    if specification.endswith('?'): return None
    if specification == 'string': return 'value'
    if specification in ('integer', 'number'): return 0
    if specification == 'boolean': return False
    if specification.startswith('enum:'): return specification[5:].split('|')[0]
    if specification.startswith('pattern:'): return '2026-01-02T03:04:05Z'
    if specification == 'named:attribute_kind': return 'Proof'
    if specification == 'named:solver': return 'solver'
    raise AssertionError(specification)


def valid_export(row, source):
    schema = json.loads((runner.REPO/'tests/json-handler/schema-validation/kani_json_schema.json').read_text())
    defs = schema['_defs']
    value = {k: example(v, defs) for k, v in schema.items() if not k.startswith('_')}
    h = example(schema['harnesses'][0], defs)
    value['harnesses'] = [h]
    value.update(schema_version='0.1.0', kani_commit=runner.PIN['sha'], kani_commit_dirty=False,
                 enabled_unstable_features=sorted({'export-json'} | set(row['flags'][1::2])),
                 harness_selection={'requested_filters':[row['harness']], 'exact':True,
                                    'unmatched_filters':[], 'matched_count':1},
                 harness_timeout_s=None, run_state='COMPLETE', outcome={'kind':'COMPLETED'},
                 tools={'kani':'kani 0aac16e','rustc':'rustc 1','cbmc':'cbmc 1'})
    value['configuration']['checks'].update(memory_safety=True, overflow=True, unwinding=True,
        undefined_function=True, assertion_reach_checks=False, ignore_global_asm=False,
        extra_pointer_checks=False, assert_contracts=True, prove_safety_only=False)
    h.update(name=row['harness'], crate_name='fixture', file=str(source.resolve()), line=1,
             is_automatically_generated=False, has_loop_contracts=False, is_bounded=True,
             outcome={'kind':'COMPLETED','verdict':'SUCCESS'}, failure_kind='NONE',
             n_properties=1, n_failed=0, unsupported_constructs=[], failed_properties=[])
    h['contract'] = None if row['contract'] is None else {'contracted_function_name':'fixture::'+row['contract'], 'recursion_tracker':None}
    h['attributes'].update(kind=('Proof' if row['kind']=='Proof' else
        {'ProofForContract':{'target_fn':'fixture::'+row['contract']} }), should_panic=False,
        verified_stubs=['fixture::'+x for x in row['verified_stubs']], stubs=[])
    h['checks'].update(total=1, success=1, failure=[], unreachable=[], undetermined=[], error=[], unknown=[], other=[])
    h['covers'].update(total=0, satisfied=[], unsatisfiable=[], unreachable=[], undetermined=[], error=[], unknown=[], other=[])
    value['summary'].update(total=1, successful=1, failed=0, checks_total=1, checks_success=1,
                            covers_total=0, covers_satisfied=0)
    return value


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root/'fixture.rs'
        self.source.write_text('fn harness() {}\n')
        self.success_row = {'id':'success','file':'fixture.rs','harness':'harness','flags':['-Z','function-contracts','-Z','uninit-checks','-Z','stubbing'],
            'expected':'SUCCESS','desired':'SUCCESS','kind':'Proof','contract':None,'verified_stubs':[],
            'failure_description':None}
        self.uninit_row = self.success_row | {'id':'uninit','expected':'UNINIT_FAILURE',
            'failure_description':'Undefined Behavior: Reading from an uninitialized pointer of type `*const u8`'}

    def tearDown(self): self.temp.cleanup()

    def write_export(self, row, value=None, raw=None):
        path = self.root/'export.json'
        if raw is not None: path.write_text(raw)
        else: path.write_text(json.dumps(value if value is not None else valid_export(row, self.source)))
        return path

    def parse(self, row, value=None, run=None, raw=None, path=None):
        path = path or self.write_export(row, value, raw)
        return runner.parse_export(path, row, self.source,
            run or {'cwd':str(self.root),'original_exit_code':0,'signal':None})

    def failure_export(self, row, descriptions, unreachable=0):
        value = valid_export(row, self.source)
        h = value['harnesses'][0]
        props = [{'id':f'p{i+1}','class':'safety_check',
                  'description':desc,'file':str(self.source.resolve()),'line':str(i+1),
                  'trace_available':False,'status':'FAILURE'} for i, desc in enumerate(descriptions)]
        h.update(outcome={'kind':'COMPLETED','verdict':'FAILURE'}, failure_kind='OTHER',
                 n_properties=len(props)+unreachable, n_failed=len(props), failed_properties=props)
        h['checks'].update(total=len(props)+unreachable, success=0, failure=[p['id'] for p in props],
                           unreachable=[f'u{i+1}' for i in range(unreachable)])
        value['summary'].update(successful=0, failed=1, checks_total=len(props)+unreachable, checks_success=0)
        return value

    def test_success_exact_metadata_and_proof_credit_none(self):
        parsed = self.parse(self.success_row)
        self.assertEqual((parsed['state'],parsed['outcome']),('VALIDATED','SUCCESS'))
        self.assertTrue(parsed['expected_match'])
        self.assertEqual(parsed['proof_credit'],'NONE')

    def test_failure_exact_oracle_records_all_property_identity(self):
        row = self.uninit_row
        parsed = self.parse(row, self.failure_export(row,[row['failure_description'],row['failure_description']],unreachable=1),
                            {'cwd':str(self.root),'original_exit_code':1,'signal':None})
        self.assertEqual(parsed['outcome'],'UNINIT_FAILURE')
        self.assertEqual([p['id'] for p in parsed['failed_properties']],['p1','p2'])
        self.assertEqual([p['class'] for p in parsed['failed_properties']],['safety_check']*2)
        self.assertEqual(parsed['unreachable_ids'],['u1'])
        self.assertEqual(parsed['proof_credit'],'NONE')

    def test_exact_failure_description_rejects_mixed_oracle(self):
        row = self.uninit_row
        value = self.failure_export(row,[row['failure_description'],'different property failure'])
        parsed = self.parse(row,value,{'cwd':str(self.root),'original_exit_code':1,'signal':None})
        self.assertEqual(parsed['state'],'UNCLASSIFIED_FAILURE')
        self.assertEqual(len(parsed['failed_properties']),2)

    def test_uninit_failure_exact_description(self):
        row = self.uninit_row
        parsed = self.parse(row,self.failure_export(row,[row['failure_description']]),
                            {'cwd':str(self.root),'original_exit_code':1,'signal':None})
        self.assertEqual(parsed['outcome'],'UNINIT_FAILURE')

    def test_missing_null_wrong_type_partial_and_schema_mismatch(self):
        path = self.root/'missing.json'
        self.assertEqual(runner.parse_export(path,self.success_row,self.source,{'original_exit_code':0})['state'],'MISSING')
        for raw, state in [('null','NULL'),('[]','WRONG_TOP_LEVEL_TYPE'),('{','INVALID_OR_PARTIAL')]:
            path.write_text(raw)
            self.assertEqual(runner.parse_export(path,self.success_row,self.source,{'original_exit_code':0})['state'],state)
        value = valid_export(self.success_row,self.source); del value['summary']['total']
        self.assertEqual(self.parse(self.success_row,value)['state'],'SCHEMA_INVALID')

    def test_export_mismatched_filter_source_feature_metadata_and_exit_stay_unknown(self):
        mutations = [
            lambda v: v['harness_selection'].update(requested_filters=['other']),
            lambda v: v['harnesses'][0].update(file=str(self.root/'other.rs')),
            lambda v: v.update(enabled_unstable_features=['export-json']),
            lambda v: v['harnesses'][0]['attributes'].update(verified_stubs=['wrong::stub']),
        ]
        for mutate in mutations:
            value=valid_export(self.success_row,self.source); mutate(value)
            self.assertEqual(self.parse(self.success_row,value)['outcome'],'UNKNOWN')
        value=valid_export(self.success_row,self.source)
        self.assertEqual(self.parse(self.success_row,value,{'cwd':str(self.root),'original_exit_code':5})['outcome'],'UNKNOWN')

    def test_timeout_and_runner_error_never_accept_complete_export(self):
        path=self.write_export(self.success_row)
        for run in ({'timed_out':True},{'termination_reason':'rss_cap'},{'runner_error':'boom'},
                    {'output_truncated':True}):
            self.assertEqual(runner.parse_export(path,self.success_row,self.source,run)['state'],'EXECUTION_INCOMPLETE')

    def test_flags_are_exact_allowlist(self):
        request={'rows_sha256':'', 'payload_sha256':{'fixture.rs':runner.sha256(self.source)}}
        original=runner.ROWS
        try:
            for flags, valid in ((['-Z','valid-value-checks'],False),(['-Z','function-contracts','-Z','uninit-checks'],False),
                                 (['-Z','function-contracts','-Z','uninit-checks','-Z','stubbing'],True),
                                 (['-Z','uninit-checks','--jobs','8'],False)):
                row=self.success_row | {'flags':flags}
                data=json.dumps([row]).encode(); path=self.root/'rows.json'; path.write_bytes(data)
                request['rows_sha256']=__import__('hashlib').sha256(data).hexdigest(); runner.ROWS=path
                with patch.object(runner,'HERE',self.root):
                    if valid: runner.load_rows(request)
                    else:
                        with self.assertRaises(runner.RunnerError): runner.load_rows(request)
        finally: runner.ROWS=original

    def test_actual_sibling_tool_layout_and_prefixed_payload_lookup(self):
        workspace=self.root/'workspace'
        control=workspace/'control'/'ch8-issue-mre2-control'
        tool=workspace/'tool'
        control.mkdir(parents=True); tool.mkdir(parents=True)
        def fake_git(repo,*args):
            if args == ('rev-parse','HEAD'): return runner.PIN['sha']
            if args == ('rev-parse','HEAD^{tree}'): return runner.PIN['tree']
            if args == ('cat-file','-t',runner.PIN['sha']): return 'commit'
            if args[:1] == ('status',): return ''
            raise AssertionError(args)
        with patch.object(runner,'HERE',control), patch.object(runner,'git',side_effect=fake_git):
            self.assertEqual(runner.verify_tool(tool)['sha'],runner.PIN['sha'])
            self.assertEqual(runner._row_payload_hash({'payload_sha256':{
                'ch8-issue-mre2-control/fixtures/x.rs':'a'*64}},'fixtures/x.rs'),'a'*64)

    def test_execute_exit_capture_caps_and_timeout(self):
        out=self.root/'output'
        run=runner.execute([sys.executable,'-c',"import sys;sys.stdout.write('x'*1100000);sys.exit(7)"],self.root,out,10)
        self.assertEqual(run['original_exit_code'],7)
        self.assertTrue(run['stdout_truncated'])
        self.assertLessEqual((out/'stdout.log').stat().st_size,runner.LOG_CAP)
        self.assertLessEqual((out/'stdout.tail.log').stat().st_size,runner.LOG_TAIL)
        out=self.root/'timeout'
        run=runner.execute([sys.executable,'-c','import time;time.sleep(4)'],self.root,out,1)
        self.assertTrue(run['timed_out'])
        self.assertIsInstance(run['original_exit_code'],int)

    def test_fallback_synthesizes_not_run_and_preserves_partial_original(self):
        row=self.success_row
        request={'payload_sha256':{f'{self.root.name}/fixture.rs':runner.sha256(self.source)}}
        out=self.root/'fallback'; out.mkdir()
        original=out/'run.json'; original.write_text('{')
        stack=ExitStack()
        try:
            stack.enter_context(patch.object(runner,'HERE',self.root))
            stack.enter_context(patch.object(runner,'load_request',return_value=(request,'reqsha')))
            stack.enter_context(patch.object(runner,'load_rows',return_value=([row],'rowsha')))
            self.assertEqual(runner.fallback(out),0)
            self.assertEqual(original.read_text(),'{')
            missing=json.loads((out/'missing-not-run.json').read_text())['receipts']
            self.assertEqual(missing[0]['status'],'NOT_RUN')
            recovered=json.loads((out/'recovered-receipts.json').read_text())
            self.assertEqual(recovered['receipts'],[])
        finally: stack.close()

    def test_fallback_promotes_running_receipt_to_unknown(self):
        row=self.success_row
        request={'payload_sha256':{'fixture.rs':runner.sha256(self.source)}}
        out=self.root/'fallback-running'; (out/'rows/success').mkdir(parents=True)
        (out/'run.json').write_text(json.dumps({'status':'RUNNING','receipts':[]}))
        (out/'rows/success/receipt.json').write_text(json.dumps({'id':'success','status':'RUNNING'}))
        with ExitStack() as stack:
            stack.enter_context(patch.object(runner,'HERE',self.root))
            stack.enter_context(patch.object(runner,'load_request',return_value=(request,'req')))
            stack.enter_context(patch.object(runner,'load_rows',return_value=([row],'rows')))
            self.assertEqual(runner.fallback(out),0)
        recovered=json.loads((out/'recovered-receipts.json').read_text())['receipts'][0]
        self.assertEqual(recovered['status'],'UNKNOWN')

    def test_fallback_preserves_executed_run_and_exception_as_unknown(self):
        row=self.success_row
        request={'payload_sha256':{'fixture.rs':runner.sha256(self.source)}}
        out=self.root/'fallback-executed'; (out/'rows/success').mkdir(parents=True)
        (out/'run.json').write_text(json.dumps({'status':'RUNNING','receipts':[]}))
        original={'id':'success','status':'EXECUTED','argv':['kani','--harness','harness'],
                  'run':{'original_exit_code':9,'cwd':str(out)},'error':'synthetic parser exception'}
        (out/'rows/success/receipt.json').write_text(json.dumps(original))
        with ExitStack() as stack:
            stack.enter_context(patch.object(runner,'HERE',self.root))
            stack.enter_context(patch.object(runner,'load_request',return_value=(request,'req')))
            stack.enter_context(patch.object(runner,'load_rows',return_value=([row],'rows')))
            self.assertEqual(runner.fallback(out),0)
        recovered=json.loads((out/'recovered-receipts.json').read_text())['receipts'][0]
        self.assertEqual(recovered['status'],'UNKNOWN')
        self.assertEqual(recovered['run']['original_exit_code'],9)
        self.assertEqual(recovered['error'],'synthetic parser exception')

    def test_runner_exception_preserves_run_and_argv_in_row_receipt(self):
        row=self.success_row
        request={'payload_sha256':{'fixture.rs':runner.sha256(self.source)}}
        binding={'pin':'upstream','sha':runner.PIN['sha'],'tree':runner.PIN['tree']}
        out=self.root/'run'; out.mkdir()
        (out/'build.json').write_text(json.dumps({'status':'COMPLETE','pin':'upstream','tool':binding,
            'request_sha256':'request','run':{'original_exit_code':0}}))
        def fake_execute(argv,cwd,dest,timeout,env=None,export_path=None):
            export_path.write_text('{}')
            return {'argv':argv,'cwd':str(cwd),'original_exit_code':0,'signal':None}
        with ExitStack() as stack:
            stack.enter_context(patch.object(runner,'HERE',self.root))
            stack.enter_context(patch.object(runner,'load_request',return_value=(request,'request')))
            stack.enter_context(patch.object(runner,'load_rows',return_value=([row],'rows')))
            stack.enter_context(patch.object(runner,'verify_tool',return_value=binding))
            stack.enter_context(patch.object(runner,'_guard_env',return_value={}))
            stack.enter_context(patch.object(runner,'execute',side_effect=fake_execute))
            stack.enter_context(patch.object(runner,'parse_export',side_effect=RuntimeError('synthetic parse failure')))
            self.assertEqual(runner.run_rows(self.root/'tool',out),1)
        receipt=json.loads((out/'rows/success/receipt.json').read_text())
        self.assertEqual(receipt['run']['original_exit_code'],0)
        self.assertIn('--exact',receipt['argv'])
        self.assertIn('synthetic parse failure',receipt['error'])
        self.assertEqual(receipt['export']['outcome'],'UNKNOWN')

    def test_keyboard_interrupt_snapshot_is_complete_and_fallback_keeps_original(self):
        row=self.success_row
        request={'payload_sha256':{'fixture.rs':runner.sha256(self.source)}}
        binding={'pin':'upstream','sha':runner.PIN['sha'],'tree':runner.PIN['tree']}
        out=self.root/'interrupted'; out.mkdir()
        (out/'build.json').write_text(json.dumps({'status':'COMPLETE','pin':'upstream','tool':binding,
            'request_sha256':'request','run':{'original_exit_code':0}}))
        slot=out/'rows/success'
        def interrupted_execute(*_args,**_kwargs): raise KeyboardInterrupt('synthetic interruption')
        with ExitStack() as stack:
            stack.enter_context(patch.object(runner,'HERE',self.root))
            stack.enter_context(patch.object(runner,'load_request',return_value=(request,'request')))
            stack.enter_context(patch.object(runner,'load_rows',return_value=([row],'rows')))
            stack.enter_context(patch.object(runner,'verify_tool',return_value=binding))
            stack.enter_context(patch.object(runner,'_guard_env',return_value={}))
            stack.enter_context(patch.object(runner,'execute',side_effect=interrupted_execute))
            with self.assertRaisesRegex(KeyboardInterrupt,'synthetic interruption'):
                runner.run_rows(self.root/'tool',out)
        receipt_path=slot/'receipt.json'
        original_bytes=receipt_path.read_bytes()
        original=json.loads(original_bytes)
        self.assertEqual(original['status'],'RUNNING')
        expected_argv=[str((self.root/'tool/scripts/kani').resolve()),*row['flags'],'--harness',row['harness'],
            '--exact',str(self.source.resolve()),'-Z','export-json','--export-json',str((slot/'export.json').resolve())]
        self.assertEqual(original['argv'],expected_argv)
        self.assertEqual(original['cwd'],str(slot.resolve()))
        self.assertEqual(original['export_path'],str((slot/'export.json').resolve()))
        self.assertEqual(original['file_sha256'],runner.sha256(self.source))
        with ExitStack() as stack:
            stack.enter_context(patch.object(runner,'HERE',self.root))
            stack.enter_context(patch.object(runner,'load_request',return_value=(request,'request')))
            stack.enter_context(patch.object(runner,'load_rows',return_value=([row],'rows')))
            self.assertEqual(runner.fallback(out),0)
        self.assertEqual(receipt_path.read_bytes(),original_bytes)
        recovered=json.loads((out/'recovered-receipts.json').read_text())['receipts'][0]
        self.assertEqual(recovered['status'],'UNKNOWN')
        for key in ('argv','cwd','export_path','file_sha256','request_sha256','rows_sha256'):
            self.assertEqual(recovered[key],original[key])


    def test_slice_havoc_requires_write_any_slice_property_id(self):
        row = self.uninit_row | {'failure_function':'write_any_slice',
            'failure_description':'Undefined Behavior: Reading from an uninitialized pointer of type `*mut [u8]`'}
        for identity, expected in (
            ('kani::internal::write_any_slice::<u8>.safety_check.1', 'UNINIT_FAILURE'),
            ('write_any_slice::<u8>.safety_check.1', 'UNINIT_FAILURE'),
            ('initialize.safety_check.1', 'UNKNOWN'),
            ('not_write_any_slice::<u8>.safety_check.1', 'UNKNOWN')):
            value = self.failure_export(row, [row['failure_description']])
            h = value['harnesses'][0]
            h['failed_properties'][0]['id'] = identity
            h['checks']['failure'] = [identity]
            parsed = self.parse(row,value,{'cwd':str(self.root),'original_exit_code':1,'signal':None})
            self.assertEqual(parsed['outcome'],expected)

    def test_failure_wrong_class_and_extra_failure_are_not_reproduction(self):
        row = self.uninit_row
        value = self.failure_export(row,[row['failure_description']])
        value['harnesses'][0]['failed_properties'][0]['class'] = 'unsupported_construct'
        self.assertEqual(self.parse(row,value,{'cwd':str(self.root),'original_exit_code':1})['outcome'],'UNKNOWN')
        value = self.failure_export(row,[row['failure_description'], 'unexpected assertion'])
        self.assertEqual(self.parse(row,value,{'cwd':str(self.root),'original_exit_code':1})['outcome'],'UNKNOWN')

    def test_new_branch_family_only(self):
        import os
        base = {'GITHUB_REPOSITORY':'Tiramisu-Cake/kani', 'GITHUB_EVENT_NAME':'push',
            'GITHUB_RUN_ATTEMPT':'1'}
        for ref, allowed in [('refs/heads/uninit-ci/ch8-issue-mre2-a',True),
                             ('refs/heads/uninit-ci/ch8-issue-mre-a',False)]:
            with patch.dict(os.environ, base | {'GITHUB_REF':ref}, clear=True):
                if allowed: self.assertEqual(runner._guard_env()['KANI_ATTEMPT'],'1')
                else:
                    with self.assertRaises(runner.RunnerError): runner._guard_env()

if __name__ == '__main__': unittest.main()
