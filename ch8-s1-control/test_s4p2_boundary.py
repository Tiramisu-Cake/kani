# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Exact S4P2 contract boundaries; static/service observations, no native credit."""
import copy,itertools,json,tempfile,unittest
from pathlib import Path
from unittest import mock
import runner as r
import s4p2_profile as p
import s4p2_policy as policy
import s4p2_cfg_pfc as cfg
import s4p2_lexical_bindings as lexical
import s4p2_ordinary_contracts as ordinary
import s4p2_campaign as campaign
import test_s4p2 as f
import test_s4p2_paths as paths
import collect as public
import pack_evidence

class ContractTests(unittest.TestCase):
    def test_exact_eight_original_null_design_map_and_roles(self):
        req=r.load_request();self.assertEqual([x['id'] for x in req['rows']],list(p.ORDER))
        self.assertEqual([x['required_cover_count'] for x in req['rows']],[0,0,0,0,6,6,6,3])
        self.assertEqual(sum(len(x['roles']) for x in req['rows']),42)
        self.assertEqual(sum(x['class']=='assertion' for row in req['rows'] for x in row['roles']),21)
        for row in req['rows']:
            self.assertEqual(row['mode'],'Original');self.assertIsNone(row['target'])
            self.assertIsNone(req['source_bindings'][row['id']]['target'])
        for row in req['rows'][4:]:
            self.assertEqual(len([x for x in row['roles'] if x['class']=='assertion']),4)
            self.assertEqual(row['design_id'],p.DESIGNS[row['id']])
            self.assertEqual({x['status'] for x in row['roles'] if x['class']=='assertion'},{'SUCCESS'})
            self.assertEqual({x['status'] for x in row['roles'] if x['class']=='cover'},{'SATISFIED'})
            self.assertEqual(len(row['structurally_not_applicable_roles']),4 if row==req['rows'][-1] else 0)
            for role in row['roles']:self.assertTrue(role['predicate_tokens']);self.assertTrue(role['semantic_role'])
        self.assertEqual(req['rows'][-1]['structural_na_binding']['std_sha'],req['std_sha'])
        self.assertEqual(req['rows'][-1]['structural_na_binding']['domain'],p.DOMAINS[p.ORDER[-1]])

    def test_request_mutations_fail_closed(self):
        req=r.load_request()
        changes=[lambda q:q['rows'].pop(),lambda q:q['rows'].reverse(),lambda q:q.update(schema='ch8-s4p-1-v1'),
            lambda q:q.update(std_sha='0'*40),lambda q:q.update(profile='ch8-s4p-1-fullbyte-length-blocks-v1'),
            lambda q:q['budgets'].update(projected_group_count=True),lambda q:q['flags'].update(RUSTFLAGS='--cfg=kani_smallsort_sorting'),
            lambda q:q['enabled_summary_edges'].append('provider'),lambda q:q['unreachable_admission'].update(enabled=True)]
        for i in range(8):
            changes += [lambda q,i=i:q['rows'][i].update(mode='PFC'),lambda q,i=i:q['rows'][i].update(target=False),
                        lambda q,i=i:q['rows'][i].pop('target'),lambda q,i=i:q['source_bindings'][p.ORDER[i]].update(target='forged')]
        for i in range(4,8):
            changes += [lambda q,i=i:q['rows'][i]['roles'].pop(),lambda q,i=i:q['rows'][i]['roles'].append(copy.deepcopy(q['rows'][i]['roles'][0])),
                        lambda q,i=i:q['rows'][i]['required_cover_messages'].pop(),lambda q,i=i:q['rows'][i].update(required_cover_count=0),
                        lambda q,i=i:q['rows'][i]['roles'][0].update(status='UNREACHABLE'),lambda q,i=i:q['rows'][i]['roles'][0].update(line=True),
                        lambda q,i=i:q['rows'][i]['roles'][0].update(description='EXTRA'),lambda q,i=i:q['rows'][i]['roles'][0].update(predicate_tokens='true'),
                        lambda q,i=i:q['domains'][p.ORDER[i]].update(type='Cell<u8>'),lambda q,i=i:q['domains'][p.ORDER[i]].update(base=2),
                        lambda q,i=i:q['domains'][p.ORDER[i]].update(logical_values='FEWKEYS'),lambda q,i=i:q['rows'][i].update(structurally_not_applicable_roles=['UNSORTED'])]
        for n,change in enumerate(changes):
            q=copy.deepcopy(req);change(q)
            with self.subTest(case=n),self.assertRaises((AssertionError,KeyError,TypeError)):p.validate(q)

    def test_each_declared_native_cover_must_be_sat_and_counts_typed(self):
        for row in r.load_request()['rows'][4:]:
            a,b=f.inventory(row);self.assertTrue(policy.expected_observation(row,a,b))
            for i,role in enumerate(row['roles']):
                if role['class']!='cover':continue
                for status in ('UNSATISFIABLE','UNREACHABLE','UNKNOWN','SUCCESS',None,True):
                    x,y=copy.deepcopy(a),copy.deepcopy(b);y['properties'][i]['status']=status
                    self.assertFalse(policy.expected_observation(row,x,y))
            for kind,key,value in [('checks','total',True),('checks','success',4.0),('covers','total',None)]:
                x=copy.deepcopy(a);x['harness'][kind][key]=value;self.assertFalse(policy.expected_observation(row,x,b))
            for key,value in [('n_properties',True),('n_failed',False),('n_properties',0),('n_failed',1)]:
                x=copy.deepcopy(a);x['harness'][key]=value;self.assertFalse(policy.expected_observation(row,x,b))
            for status in ('SUCCESS','FAILURE','UNREACHABLE','UNKNOWN'):
                x=copy.deepcopy(a);x['harness']['unsupported_constructs']=[{'status':status}]
                self.assertFalse(policy.expected_observation(row,x,b))

    def test_old_exact_schemas_counts_caps_and_static_witnesses(self):
        for name,count in [('s3-1-request.json',9),('s3-2-request.json',8),('s34-request.json',7),('s4p-request.json',8)]:
            req=r.load_request(r.HERE/'fixtures'/name);self.assertEqual(len(req['rows']),count)
            with self.assertRaises((AssertionError,KeyError)):p.validate(req)
        self.assertEqual(8*p.CAPS['slot_seconds']+p.CAPS['controller_seconds']+p.CAPS['cleanup_seconds'],6180)
        for model in policy.CONTRACT['rows']:
            self.assertEqual(len(model['static_assignments']),model['cover_count'])
            self.assertEqual({x['role'] for x in model['static_assignments']},set(model['cover_roles']))
            for x in model['static_assignments']:
                a,b=x['active_input'],x['candidate_output'];self.assertEqual(sorted(a),b);self.assertIn(x['n'],model['lengths'])
                if x['role']=='UNSORTED':self.assertGreater(a[0],a[-1])
                if x['role']=='DUPLICATE':self.assertLess(len(set(a)),len(a))
                if x['role']=='NONCONSTANT':self.assertLess(b[0],b[-1])
                if x['role']=='MAX_DESCENDING':self.assertTrue(all(a[i-1]>a[i] for i in range(1,len(a))))

class SourceTests(unittest.TestCase):
    def setUp(self):
        self.req=r.load_request();self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.std=Path(self.tmp.name)
        for rel,text in json.loads((r.HERE/'S4P2-SOURCE.json').read_text()).items():
            path=self.std/rel;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(text)
    def test_actual_all_four_gates_new_module_roles_domain_and_legacy_projection(self):
        report=policy.validate_source(self.std,self.req);self.assertEqual(report['status'],'STATIC_PASS')
        for gate in report['reports'].values():self.assertIn(policy.LEAF,gate['source_files_sha256'])
        self.assertEqual(len(report['reports']['contract_stacks']['cfg_projection_invariance']),64)
        for row in self.req['rows'][4:]:
            text=(self.std/policy.LEAF).read_text();self.assertIn('small_sort_network(&mut v[1..1 + n]',text)
            self.assertNotIn('kani::stub',text);self.assertNotIn('% 2',text);self.assertNotIn('assume(ordered',text)
    def test_new_module_missing_registration_and_static_call_import_alias_and_local_callable(self):
        req=copy.deepcopy(self.req)
        for key in ('cfg_pfc_source_sha256','ordinary_contract_source_sha256','lexical_source_sha256'):req.pop(key)
        path=self.std/policy.LEAF;original=path.read_text()
        for fragment in ('missing_network(&mut','unknown::small_sort_network(&mut','({small_sort_network})(&mut'):
            path.write_text(original.replace('small_sort_network(&mut',fragment,1))
            with self.subTest(fragment=fragment),self.assertRaises(ValueError):lexical.check(self.std,req)
        path.write_text(original)
        parent=self.std/policy.VERIFY;saved=parent.read_text();parent.write_text(saved.replace('mod sorting_s4_network_partition;','mod missing_s4p2;'))
        with self.assertRaises(ValueError):cfg.check(self.std,req)
        parent.write_text(saved)
        path.write_text(original.replace('#[kani::proof]','#[kani::stub_verified(small_sort_network)]\n#[kani::proof]',1))
        with self.assertRaises(ValueError):cfg.check(self.std,req)
        path.write_text(original.replace('#[kani::proof]','#[kani::stub(small_sort_network, active_u8)]\n#[kani::proof]',1))
        with self.assertRaises(ValueError):ordinary.check(self.std,req)

class ReplayModeTests(unittest.TestCase):
    def test_worker_target_missing_bool_or_pfc_globally_stops(self):
        case=paths.RealPathWriterTests()
        for mutation in ('missing','bool','pfc'):
            def fault(root,out,rid,tool,sup):
                if rid!=p.ORDER[4]:return
                path=out/rid/'receipt.json';doc=campaign.read(path)
                if mutation=='missing':doc.pop('target')
                elif mutation=='bool':doc['target']=False
                else:doc['mode']='PFC'
                campaign.atomic(path,doc)
            with self.subTest(mutation=mutation),case.fixture(fault=fault) as fix:
                code,terminal=case.run_fixture(fix);self.assertEqual(code,1)
                self.assertIn('worker row/source-stage-target' if mutation=='pfc' else 'Original/null',terminal['stop_reason'])
                self.assertEqual(terminal['s3_campaign']['completed'],list(p.ORDER[:4]))
                self.assertTrue(all(x['status']=='NOT_RUN' for x in terminal['rows'][5:]))

    def test_resealed_worker_null_mutation_rejects_local_and_upload(self):
        case=paths.RealPathWriterTests()
        with case.fixture() as fix:
            self.assertEqual(case.run_fixture(fix)[0],0)
            rid=p.ORDER[4];rowpath=fix[3]/rid/'worker-receipt.json'
            doc=campaign.read(rowpath);doc['target']=False;campaign.atomic(rowpath,doc)
            sealpath=fix[3]/'completed'/(rid+'.json');seal=campaign.read(sealpath)
            seal['files'][str(rowpath.relative_to(fix[3]))]=r.sha256(rowpath);campaign.atomic(sealpath,seal)
            pack_evidence.pack(fix[3]);upload=fix[0]/'worker-upload';upload.mkdir()
            (upload/pack_evidence.NAME).write_bytes((fix[3]/pack_evidence.NAME).read_bytes())
            for root in (fix[3],upload):
                with self.assertRaisesRegex(campaign.GlobalFailure,'worker replay Original/null'):public.collect([root],fix[4])

    def test_actual_writer_and_public_both_routes_reject_nonnull_target(self):
        case=paths.RealPathWriterTests()
        with case.fixture() as fix:
            code,terminal=case.run_fixture(fix);self.assertEqual(code,0)
            self.assertTrue(all(row['mode']=='Original' and 'target' in row and row['target'] is None for row in terminal['rows']))
            for row in terminal['rows']:
                self.assertIsNone(campaign.read(fix[3]/row['id']/'receipt.json')['target'])
                self.assertIsNone(campaign.read(fix[3]/row['id']/'worker-receipt.json')['target'])
            path=fix[3]/'receipt.json';original=path.read_bytes();upload=fix[0]/'mode-upload';upload.mkdir()
            for change in (lambda d:d['rows'][4].update(target='fake'),lambda d:d['rows'][4].pop('target'),lambda d:d['rows'][4].update(mode='PFC')):
                doc=json.loads(original);change(doc);campaign.atomic(path,doc);pack_evidence.pack(fix[3])
                (upload/pack_evidence.NAME).write_bytes((fix[3]/pack_evidence.NAME).read_bytes())
                for root in (fix[3],upload):
                    with self.assertRaises(campaign.GlobalFailure):public.collect([root],fix[4])
            path.write_bytes(original)
    def test_fallback_preserves_malformed_existing_terminal_as_error(self):
        req=r.load_request()
        with tempfile.TemporaryDirectory() as d:
            out=Path(d);terminal=campaign.finalize(out,req,'STOPPED_BEFORE_FIRST')
            terminal.pop('schema')
            for malformed in ({},terminal):
                campaign.atomic(out/'receipt.json',malformed);original=(out/'receipt.json').read_bytes()
                with self.subTest(malformed=malformed),self.assertRaisesRegex(campaign.GlobalFailure,'refusing normalization'):campaign.fallback(out,req)
                self.assertEqual((out/'receipt.json').read_bytes(),original)
