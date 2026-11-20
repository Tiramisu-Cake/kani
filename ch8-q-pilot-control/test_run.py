"""Synthetic q-pilot runner tests. These never compile or launch Kani."""
import copy, json, tempfile, types, unittest
from pathlib import Path
from unittest import mock
import run

class ManifestTests(unittest.TestCase):
    def test_exact_root_order_and_closed_cfg_argv(self):
        req=run.load_request()
        self.assertEqual([x['id'] for x in req['roots']],['P-1','P-2','P-3','P-4','P-5a','P-5b','P-5c'])
        self.assertIn('kani_smallsort_q_pilot',req['cfg']['positive'])
        self.assertIn('kani_smallsort_q_controls',req['cfg']['mutant'])
        self.assertNotIn('kani_smallsort_q_controls',req['cfg']['positive'])
        with tempfile.TemporaryDirectory() as d:
            root=req['roots'][0]; a=run.argv_for(root,Path(d)/'std',Path(d)/'tool',Path(d)/'target.json')
        self.assertEqual(a.count('--harness'),1); self.assertIn(root['selector'],a); self.assertIn('--exact',a)
        self.assertEqual(a[a.index('--cbmc-args')+1:],['--object-bits','12'])
        self.assertFalse(any('solver' in x.lower() for x in a))
        flags=set(a)
        self.assertNotIn('loop-contracts',flags);self.assertNotIn('quantifiers',flags)
        self.assertNotIn('uninit-checks',flags);self.assertNotIn('valid-value-checks',flags)
    def test_bad_tool_pin_and_wrong_root_order_rejected(self):
        original=run.REQ_PATH.read_text()
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'request.json'; value=json.loads(original);value['tool_sha']='f'*40;p.write_text(json.dumps(value))
            with mock.patch.object(run,'REQ_PATH',p),self.assertRaises(run.PilotError):run.load_request()
            value=json.loads(original);value['roots'][0],value['roots'][1]=value['roots'][1],value['roots'][0];p.write_text(json.dumps(value))
            with mock.patch.object(run,'REQ_PATH',p),self.assertRaises(run.PilotError):run.load_request()
    def test_launcher_rejects_arbitrary_cfg(self):
        req=run.load_request(); root=copy.deepcopy(req['roots'][0]);root['cfg']='caller-supplied'
        with self.assertRaises(run.PilotError):run.cfg_for(root,req)

class DomainAndInventoryTests(unittest.TestCase):
    def good_inventory(self,root,assigned_status='SUCCESS'):
        roles={};props=[]
        for i,label in enumerate(root['roles']):
            kind=root['role_bindings'][label]['kind']
            cls='cover' if kind=='cover' else 'assertion'
            status=('SATISFIED' if cls=='cover' else 'SUCCESS')
            if label==root['assigned_property']: status=assigned_status
            prop={'id':f'{cls}.{i+1}','class':cls,'status':status,'description':label,
                  'file':'/source/'+root['role_bindings'][label]['file'],'line':str(root['role_bindings'][label]['line'])}
            roles[label]={'state':'MATCH','property':prop};props.append(prop)
        contract_roles={label:{'state':'MATCH','properties':[{'id':'contract.'+str(i),'status':'SUCCESS'}]}
                        for i,label in enumerate(root['required_contract_roles'])}
        return {'state':'COMPLETE','roles':roles,'properties':props,'contract_roles':contract_roles}
    def test_all_u8_provider_domain_and_designated_property(self):
        root=run.load_request()['roots'][0]
        self.assertEqual(root['domain_id'],'all_u8');self.assertEqual(root['q_domain'],'all_u8')
        result=run.control_match(root,{'outcome':{'verdict':'SUCCESS'}},self.good_inventory(root),0,{'state':'CLEAR'})
        self.assertEqual(result['match'],'MATCH')
    def test_fixed_zero_native_success_is_not_universal_provider_credit(self):
        root=run.load_request()['roots'][5]
        self.assertEqual(root['q_domain'],'{0}')
        control=run.control_match(root,{'outcome':{'verdict':'SUCCESS'}},self.good_inventory(root),0,{'state':'CLEAR'})
        self.assertEqual(control['native_outcome'],'SUCCESS')
        self.assertEqual(control['qualification'],'FAIL')
        self.assertEqual(control['reason'],'Q_DOMAIN_NOT_UNIVERSAL')
        self.assertEqual(control['match'],'MATCH')
        self.assertEqual(control['domain_gate']['required'],'all_u8')
    def test_contract_roles_bind_exact_sites_and_keep_repeated_call_instances(self):
        root=run.load_request()['roots'][1]
        parser=types.SimpleNamespace(records={root['selector']:[]})
        span=run.load_request()['contract_site_groups']['P-2']['target_post'][0]
        prop={'id':'contract.1','class':'assertion','status':'SUCCESS','description':'prefix_post',
              'file':'/source/'+span['file'],'line':str(span['line'])}
        parser.records[root['selector']].append(prop)
        # Contract roles are intentionally unknown without the matching requires/postcondition site.
        roles=run.contract_role_inventory(root,parser)
        self.assertEqual(roles['sort13_prefix_post']['state'],'MATCH')
        self.assertEqual(roles['sort13_len17_requires']['state'],'UNKNOWN')
        wrong=dict(prop,id='contract.2',line=str(span['line']+1))
        parser.records[root['selector']].append(wrong)
        roles=run.contract_role_inventory(root,parser)
        self.assertEqual(roles['sort13_prefix_post']['state'],'MATCH')
        self.assertEqual(roles['sort13_prefix_post']['count'],1)
    def test_regular_inventory_agrees_and_roles_fail_closed_on_ambiguity(self):
        root=run.load_request()['roots'][0];root['roles']=['P1_FRAME','P1_SWAP_TAKEN']
        properties=[{'id':'assertion.1','class':'assertion','status':'SUCCESS','description':'P1_FRAME frame',
                     'file':'/source/'+root['role_bindings']['P1_FRAME']['file'],'line':str(root['role_bindings']['P1_FRAME']['line'])},
                    {'id':'cover.1','class':'cover','status':'SATISFIED','description':'P1_SWAP_TAKEN cover',
                     'file':'/source/'+root['role_bindings']['P1_SWAP_TAKEN']['file'],'line':str(root['role_bindings']['P1_SWAP_TAKEN']['line'])}]
        parser=types.SimpleNamespace(records={root['selector']:properties})
        h={'n_properties':2,'checks':{'total':1,'success':1,'failure':[],'unreachable':[],'undetermined':[],'error':[],'unknown':[],'other':[]},
           'covers':{'total':1,'satisfied':['cover.1'],'unsatisfiable':[],'unreachable':[],'undetermined':[],'error':[],'unknown':[],'other':[]}}
        result=run.role_inventory(root,parser,h,Path('/source'),run.load_request())
        self.assertEqual(result['state'],'COMPLETE');self.assertEqual(result['roles']['P1_FRAME']['state'],'MATCH')
        root2=copy.deepcopy(root);root2['roles']=['P1_FRAME']
        parser.records[root2['selector']]=properties+[dict(properties[0],id='assertion.2')]
        self.assertEqual(run.role_inventory(root2,parser,h,Path('/source'),run.load_request())['roles']['P1_FRAME']['state'],'UNKNOWN')
        bad=copy.deepcopy(h);bad['checks']['success']=0
        self.assertEqual(run.role_inventory(root,parser,bad,Path('/source'),run.load_request())['state'],'INCOMPLETE')
        # Missing coordinates and duplicate descriptions never bind a role.
        parser.records[root2['selector']]=[dict(properties[0],file=None,line=None),dict(properties[0],id='assertion.2')]
        self.assertEqual(run.role_inventory(root2,parser,h,Path('/source'),run.load_request())['roles']['P1_FRAME']['state'],'UNKNOWN')

class ProcessBoundaryTests(unittest.TestCase):
    def test_owned_helper_process_cleans_up(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'stderr'
            result=run.s3_runtime.supervise([run.sys.executable,'-c','pass'],Path(d),{},5,12*1024*1024,path)
            self.assertEqual(result['cutoff'],None)
            self.assertTrue((result.get('containment') or {}).get('verified'))
    def test_owned_helper_timeout_has_cutoff_and_verified_reap(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'stderr'
            result=run.s3_runtime.supervise([run.sys.executable,'-c','import time; time.sleep(5)'],Path(d),{},0.2,12*1024*1024,path)
            self.assertEqual(result['cutoff'],'slot_wall')
            self.assertTrue((result.get('containment') or {}).get('verified'))
    def test_runner_exit_and_timeout_preserve_original_lifecycle(self):
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'out';out.mkdir()
            failed=run.stock_runner.execute([run.sys.executable,'-c','import sys; sys.exit(17)'],Path(d),out/'failed',5,env={**run.os.environ})
            self.assertEqual(failed['original_exit_code'],17)
            self.assertTrue(failed.get('child_shutdown_verified'))
            timed=run.stock_runner.execute([run.sys.executable,'-c','import time; time.sleep(5)'],Path(d),out/'timed',0.2,env={**run.os.environ})
            self.assertTrue(timed.get('timed_out'))
            self.assertTrue(timed.get('child_shutdown_verified'))
    def test_fallback_marks_all_roots_not_run_when_producer_never_started(self):
        req=run.load_request()
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(run.finish(Path(d)),0)
            doc=json.loads((Path(d)/run.RESULT).read_text())
            self.assertTrue(all(root['status']=='NOT_RUN' for root in doc['roots']))
            self.assertEqual(doc['artifact_state'],'PARTIAL')
    def test_native_parser_completion_and_missing_is_explicit(self):
        req=run.load_request(); root=req['roots'][0]
        self.assertEqual(run.check_config(None,root),'INCOMPLETE_OR_SCHEMA_DRIFT')
        wrong={'schema_version':'0.1.0','run_state':'COMPLETE','kani_commit':run.TOOL_SHA,'kani_commit_dirty':False,
          'harness_selection':{'requested_filters':['other'],'exact':True,'unmatched_filters':[],'matched_count':1},'harness_timeout_s':600}
        self.assertEqual(run.check_config(wrong,root),'WRONG_ROOT_SELECTION')
    def test_export_null_wrong_type_missing_and_initial_marker_are_distinct(self):
        root=run.load_request()['roots'][0]
        base=run.root_record(root,'PARTIAL')
        base['lifecycle'].update(exit_code=1,child_wall_seconds=12.5)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'export.json'
            value,info=run.read_export(path,1024);self.assertEqual(info['state'],'MISSING');self.assertIsNone(value)
            path.write_text('null');value,info=run.read_export(path,1024);self.assertEqual(info['state'],'NULL');self.assertIsNone(value)
            for raw in ('[]','17'):
                path.write_text(raw);value,info=run.read_export(path,1024)
                self.assertEqual(info['state'],'WRONG_TOP_LEVEL_TYPE');self.assertIsNone(value)
                self.assertEqual((base['lifecycle']['exit_code'],base['lifecycle']['child_wall_seconds']),(1,12.5))
            path.write_text('{"run_state":"INCOMPLETE"}')
            value,info=run.read_export(path,1024);self.assertEqual(info['state'],'PARTIAL');self.assertEqual(value['run_state'],'INCOMPLETE')
            self.assertEqual((base['lifecycle']['exit_code'],base['lifecycle']['child_wall_seconds']),(1,12.5))
    def test_compile_monitor_requires_initial_incomplete_marker(self):
        with tempfile.TemporaryDirectory() as d:
            export=Path(d)/'export.json'; monitor=run.QCompileMonitor(Path(d)/'receipt.json',export,'selector',
                {'std_sha':'a'*40,'std_tree':'b'*40,'tool_sha':run.TOOL_SHA,'tool_tree':run.TOOL_TREE})
            value={'schema_version':'0.1.0','run_state':'COMPLETE','kani_commit':run.TOOL_SHA,'kani_commit_dirty':False,
              'harness_timeout_s':600,'harness_selection':{'requested_filters':['selector'],'exact':True,'unmatched_filters':[],'matched_count':1}}
            export.write_text(json.dumps(value))
            self.assertFalse(monitor.poll(1,{}));self.assertEqual(monitor.receipt['state'],'IN_PROGRESS')
            value['run_state']='INCOMPLETE';export.write_text(json.dumps(value))
            self.assertFalse(monitor.poll(2,{}));self.assertEqual(monitor.receipt['state'],'COMPLETE')

if __name__=='__main__': unittest.main()
