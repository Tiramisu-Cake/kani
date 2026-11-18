# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Narrow static/synthetic S2 process and oracle controls; no compiler/verifier."""
import copy,json,os,signal,sys,tempfile,unittest
from pathlib import Path
from unittest import mock
import runner as r
import s2_policy as p
import check_package as cp
from test_runner import batch_export
import test_runner as fixtures

HERE=Path(__file__).resolve().parent
class S2Tests(unittest.TestCase):
    def test_exact_source_cfg_stubs_and_runtime_preservation(self):
        req=r.load_request()
        sources=json.loads((HERE/'S2-SOURCE.json').read_text())
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for rel,text in sources.items():
                f=root/rel;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(text)
            self.assertTrue(p.validate_source(root,req))
            for case in ('runtime','stub','oracle_line','wrong_root','post_instead_of_pre'):
                for rel,text in sources.items():(root/rel).write_text(text)
                bad=copy.deepcopy(req)
                if case=='runtime':
                    f=root/p.SMALLSORT;f.write_text(f.read_text().replace('let len = v.len();','let len = 1;',1))
                if case=='stub':
                    f=root/p.BATCH;f.write_text(f.read_text().replace('#[kani::stub_verified(swap_if_less)]','#[kani::stub(swap_if_less,weak_swap)]',1))
                if case=='oracle_line':bad['rows'][-1]['oracle']['line']-=1
                if case=='wrong_root':bad['rows'][0]['selector']='wrong'
                if case=='post_instead_of_pre':bad['source_bindings']['merge32_real']['mode']='PFC'
                with self.subTest(case=case),self.assertRaises((AssertionError,ValueError)):p.validate_source(root,bad)

    def test_strict_inventory_assurance_budget_and_group_identity(self):
        req=r.load_request()
        cases=[lambda x:x.update(schema='wrong-schema'),lambda x:x['diagnostic_assumed_inventory'].clear(),lambda x:x['formal_expected_inventory'].append('sort13_assumed'),
            lambda x:x['rows'][3].update(assurance='FORMAL'),lambda x:x['flags'].update(RUSTFLAGS='--cfg kani_smallsort_sorting'),
            lambda x:x['rows'][-1]['oracle'].update(property_id='wrong.assertion.1'),lambda x:x['rows'].pop(),
            lambda x:x['budgets'].update(compile_seconds=1200)]
        for change in cases:
            bad=copy.deepcopy(req);change(bad)
            with tempfile.TemporaryDirectory() as d:
                path=Path(d)/'request.json';path.write_text(json.dumps(bad))
                with self.assertRaises(r.RunnerError):r.load_request(path)

    def test_exact_negative_oracles_fail_closed(self):
        req=r.load_request()
        for row in req['rows'][5:]:
            h=batch_export([row],req['source_bindings'])['harnesses'][0]
            parsed={'state':'RECORDED_OBSERVATION','outcome':'RECORDED','harness':h}
            prop={'name':row['selector'],'properties':copy.deepcopy(h['failed_properties'])}
            self.assertTrue(p.expected_observation(row,parsed,prop))
            for field,value in (('id','wrong'),('file','wrong.rs'),('line','1'),('class','overflow'),('status','SUCCESS'),('description','wrong assertion')):
                bad=copy.deepcopy(prop);bad['properties'][0][field]=value
                with self.subTest(root=row['id'],field=field):self.assertFalse(p.expected_observation(row,parsed,bad))
            for field,value in (('state','MISSING'),('outcome','UNKNOWN')):
                bad=copy.deepcopy(parsed);bad[field]=value;self.assertFalse(p.expected_observation(row,bad,prop))

    def test_useful_return_covers_and_semantic_assertions_required(self):
        req=r.load_request()
        for row in req['rows'][:5]:
            checks=[{'id':'check.'+str(i),'class':'assertion','description':s,'status':'SUCCESS'} for i,s in enumerate(row['required_success_messages'])]
            covers=[{'id':'cover.'+str(i),'class':'cover','description':s,'status':'SATISFIED'} for i,s in enumerate(row['required_cover_messages'])]
            h={'outcome':{'kind':'COMPLETED','verdict':'SUCCESS'},'checks':{'total':len(checks),'success':len(checks),**{k:[] for k in ('failure','unreachable','undetermined','error','unknown','other')}},'covers':{'total':len(covers),'satisfied':[x['id'] for x in covers],**{k:[] for k in ('unsatisfiable','unreachable','undetermined','error','unknown','other')}}}
            parsed={'state':'RECORDED_OBSERVATION','outcome':'RECORDED','harness':h};props={'name':row['selector'],'properties':checks+covers}
            self.assertTrue(p.expected_observation(row,parsed,props))
            bad=copy.deepcopy(props);bad['properties'].pop();self.assertFalse(p.expected_observation(row,parsed,bad))
            bad=copy.deepcopy(props);bad['properties'][0]['description']='safety-only';self.assertFalse(p.expected_observation(row,parsed,bad))
            bad=copy.deepcopy(parsed);bad['harness']['covers']['unsatisfiable']=['useful'];self.assertFalse(p.expected_observation(row,bad,props))

    def test_workflow_caps_types_and_single_serial_job(self):
        path=HERE.parent/'.github/workflows/ch8-s2.yml'
        self.assertEqual(cp.check_yaml(path)['step_timeout_sum_minutes'],186)
        text=path.read_text()
        for before,after in [('timeout-minutes: 180','timeout-minutes: 181'),('fetch-depth: 7','fetch-depth: 6'),('persist-credentials: false','persist-credentials: true'),('timeout-minutes: 126','timeout-minutes: 135')]:
            with tempfile.TemporaryDirectory() as d:
                f=Path(d)/'bad.yml';f.write_text(text.replace(before,after,1))
                with self.assertRaises(AssertionError):cp.check_yaml(f)

    def test_timeout_caps_and_order_reject_redistribution(self):
        import yaml
        original=cp.load_yaml((HERE.parent/'.github/workflows/ch8-s2.yml').read_text())
        for case in ('validate','source','redistribute','order'):
            doc=copy.deepcopy(original);steps=doc['jobs']['s2_batch']['steps']
            if case=='validate':steps[2]['timeout-minutes']=1
            if case=='source':steps[6]['timeout-minutes']=10
            if case=='redistribute':
                steps[2]['timeout-minutes']-=1;steps[6]['timeout-minutes']+=1
            if case=='order':steps[2],steps[6]=steps[6],steps[2]
            with self.subTest(case=case),tempfile.TemporaryDirectory() as d:
                path=Path(d)/'bad.yml';path.write_text(yaml.safe_dump(doc))
                with self.assertRaises(AssertionError):cp.check_yaml(path)

    def test_setup_aggregate_remaining_boundary_without_compiler(self):
        good={'original_exit_code':0,'timed_out':False,'termination_reason':None,
              'stdout_truncated':False,'stderr_truncated':False}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);epoch=root/'epoch';epoch.write_text('1000')
            # elapsed setup includes earlier validation/source/checkout time.
            for elapsed,expected in ((0,900),(600,900),(900,900),(901,899),(1799,1)):
                with mock.patch.object(cp.time,'time',return_value=1000+elapsed),mock.patch.object(r,'execute',return_value=good.copy()) as call:
                    self.assertEqual(cp.build(root,epoch,root/str(elapsed))['setup'],'COMPLETE')
                    self.assertEqual(call.call_args.args[3],expected)
            for elapsed in (1800,1801):
                with mock.patch.object(cp.time,'time',return_value=1000+elapsed),mock.patch.object(r,'execute') as call:
                    with self.assertRaises(AssertionError):cp.build(root,epoch,root/'expired')
                    call.assert_not_called()
            with mock.patch.object(cp.time,'time',side_effect=[2799,2801]),mock.patch.object(r,'execute',return_value=good.copy()):
                with self.assertRaises(AssertionError):cp.build(root,epoch,root/'overrun')
                self.assertEqual(json.loads((root/'overrun/receipt.json').read_text())['setup_total_seconds'],1801)

    def test_sampled_component_metrics_are_group_only(self):
        with tempfile.TemporaryDirectory() as d:
            info=r.execute([sys.executable,'-c','pass'],Path(d),Path(d)/'out',2)
            self.assertEqual(info['original_exit_code'],0)
            self.assertIn('NOT_PER_ROOT',info['component_rss_scope'])
            self.assertTrue(set(info['component_group_peak_kib'])=={'driver','backend','compiler','other'})
            self.assertTrue(info['child_shutdown_verified'])

    def test_missing_results_partial_timeout_and_remaining_inventory_unknown(self):
        req=r.load_request()
        for case in ('missing','partial','timeout','not_run','wrong_target','source','post_source','exception'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as d:
                code,summary,calls,out=fixtures.GroupTests().run_mock_batch(Path(d),req,case=case)
                self.assertEqual(code,1)
                self.assertEqual([x['id'] for x in summary['rows']],list(p.ROOTS))
                self.assertTrue(any(x['outcome']=='UNKNOWN' for x in summary['rows']))
                self.assertTrue(all(x['proof_credit']=='NONE' for x in summary['rows']))

    def test_signal_spawn_and_monitor_error_preserve_exits(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            info=r.execute(['/synthetic/nonexistent'],root,root/'spawn',2)
            self.assertIsNone(info['original_exit_code']);self.assertIn('exec failed',info['runner_error'])
            info=r.execute([sys.executable,'-c','import os,signal;os.kill(os.getpid(),signal.SIGTERM)'],root,root/'sig',2)
            self.assertEqual(info['original_exit_code'],-signal.SIGTERM);self.assertEqual(info['signal'],signal.SIGTERM)

    def test_missing_results_never_accepts_even_with_successful_stock_export(self):
        import rich_evidence
        req=r.load_request();row=req['rows'][2];stock=batch_export([row],req['source_bindings'])
        parser=rich_evidence.RegularEvidence([row['selector']],Path('/std'))
        parser.feed(('Checking harness '+row['selector']+'...\nSUMMARY:\nVERIFICATION:- SUCCESS\n').encode())
        parser.finish()
        with self.assertRaises(ValueError):parser.validate(stock)
        self.assertEqual(parser.document()['state'],'INCOMPLETE')
