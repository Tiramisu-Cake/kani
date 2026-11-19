"""Distinguishing S4 source/model/profile gates; no native execution or proof."""
import copy,json,tempfile,unittest
from pathlib import Path
from unittest import mock
import runner as r
import s4p_profile as p
import s4p_policy as policy
import s4p_lexical_bindings as lexical
import s4p_cfg_pfc as cfg
import s4p_ordinary_contracts as ordinary
import test_s4p as f

class BoundaryTests(unittest.TestCase):
    def test_exact_eight_original_null_and_length_roles(self):
        req=r.load_request();self.assertEqual([x['id'] for x in req['rows']],list(p.ORDER))
        self.assertEqual([x['mode'] for x in req['rows']],['Original']*8)
        for i,row in enumerate(req['rows']):
            self.assertIsNone(row['target']);self.assertIsNone(req['source_bindings'][row['id']]['target'])
            if i>=4:
                prefix=('S4P_F_' if i<6 else 'S4P_N_')+('00_02' if i%2==0 else '03_04')
                lo,hi=p.DOMAINS[row['id']]['length_interval']
                self.assertEqual(row['required_success_messages'],[prefix+'_'+s for s in ('ACTIVE_CONCRETE_MODEL','SORTED_FULL_VALUE_COUNT','FULL_OUTSIDE_FRAME','ARBITRARY_OUTSIDE_CANARY')])
                self.assertEqual(row['required_cover_messages'][:hi-lo+1],[prefix+f'_N{n:02}' for n in range(lo,hi+1)])
                self.assertEqual(row['required_cover_count'],hi-lo+6)
        for i in range(8):
            for field,value in [('target','fake'),('target',False),('mode','PFC'),('unwind',35),('selector','wrong')]:
                bad=copy.deepcopy(req);bad['rows'][i][field]=value
                with self.subTest(i=i,field=field),self.assertRaises((AssertionError,KeyError)):p.validate(bad)
    def test_legacy_counts_profiles_and_runtime_caps_preserved(self):
        for file,count in [('r5-request.json',11),('s3-1-request.json',9),('s3-2-request.json',8),('s34-request.json',7)]:
            req=r.load_request(r.HERE/'fixtures'/file);self.assertEqual(len(req['rows']),count)
            with self.assertRaises((AssertionError,KeyError)):p.validate(req)
        self.assertEqual(8*p.CAPS['slot_seconds']+p.CAPS['controller_seconds']+p.CAPS['cleanup_seconds'],6180)
        self.assertEqual(p.CAPS['local_rss_kib'],6291456);self.assertEqual(p.CAPS['outer_rss_kib'],12582912)
        self.assertEqual(p.CAPS['headroom_kib'],2097152)
    def test_request_rejects_domain_provider_count_cover_and_waiver_mutations(self):
        req=r.load_request()
        for mutate in (lambda q:q['rows'].pop(),lambda q:q['rows'].reverse(),lambda q:q['budgets'].update(projected_group_count=True),
                       lambda q:q['rows'][4]['required_cover_messages'].pop(0),lambda q:q['rows'][4]['required_success_messages'].pop(),
                       lambda q:q['domains'][p.ORDER[4]].update(type='u8'),lambda q:q['domains'][p.ORDER[4]].update(base=2),
                       lambda q:q['domains'][p.ORDER[5]].update(length_interval=[3,3]),lambda q:q['enabled_summary_edges'].append('provider'),
                       lambda q:q['unreachable_admission'].update(enabled=True),lambda q:q['s3']['caps'].update(local_rss_kib=6815744),
                       lambda q:q['rows'][3]['roles'][0].update(status='FAILURE'),lambda q:q['rows'][4]['scope_classification'].update(qualification_eligible=1)):
            bad=copy.deepcopy(req);mutate(bad)
            with self.subTest(mutate=mutate),self.assertRaises((AssertionError,KeyError,TypeError)):p.validate(bad)
    def test_cell_count_requires_active_success_and_exact_failure(self):
        row=r.load_request()['rows'][3];a,b=f.inventory(row)
        self.assertTrue(policy.expected_observation(row,a,b))
        for case in ('inactive','wrong-model','order-instead','extra-failure','guard','missing','U','location'):
            x,y=copy.deepcopy(a),copy.deepcopy(b)
            if case=='inactive':y['properties'][0]['status']='FAILURE'
            elif case=='wrong-model':y['properties'][0]['description']='U8_ACTIVE'
            elif case=='order-instead':y['properties'][1]['description']='S4_NEG_CELL_ORDER'
            elif case=='extra-failure':y['properties'].append({'id':'extra','class':'assertion','status':'FAILURE'})
            elif case=='guard':x['harness']['unsupported_constructs']=[{'status':'SUCCESS'}]
            elif case=='missing':y['properties'].pop(0)
            elif case=='U':y['properties'][0]['status']='UNREACHABLE'
            else:y['properties'][1]['file']=None
            with self.subTest(case=case):self.assertFalse(policy.expected_observation(row,x,y))
    def test_cell_checker_source_count_vs_order_distinguishing_fixtures(self):
        source=json.loads((r.HERE/'S4P-SOURCE.json').read_text())
        model=lexical.functions(source[policy.c.BASE+'slice/sort/shared/smallsort/verify/sorting_model.rs'])
        text=policy.c.spelling(model['active_post']['body'])
        for fragment in ('values[i].value()<values[i-1].value()', 'let query=before.values[i];','if before.values[j]==query{old_count+=1;}','if values[j].value()==query{new_count+=1;}','if old_count!=new_count{return false;}'):
            self.assertIn(policy.c.spelling(policy.c.tokens(fragment)),text)
        self.assertIn('impl Project for Cell<u8> {\n    fn value(&self) -> u8 { self.get() }',source[policy.c.BASE+'slice/sort/shared/smallsort/verify/sorting_model.rs'])
        # A finite Python oracle discriminates the fixed fixtures. It is not Rust execution.
        def order(v):return all(v[i-1]<=v[i] for i in range(1,len(v)))
        def count(a,b):return len(a)==len(b) and all(a.count(x)==b.count(x) for x in a)
        self.assertTrue(order([0,0]));self.assertFalse(count([0,1],[0,0]))
        self.assertFalse(order([1,0]));self.assertTrue(count([0,1],[1,0]))
        self.assertTrue(order([0,1]));self.assertTrue(count([1,0],[0,1]))
        body=source[policy.LEAF]
        for fragment in ('v[2].set(1);','&v[1..3]','v[2].set(0);'):
            self.assertIn(fragment,body)
        for forbidden in ('stub_verified(', 'kani::stub(', '% 2','& 1','assume(ordered'):
            self.assertNotIn(forbidden,body)

class SourceTests(unittest.TestCase):
    def setUp(self):
        self.req=r.load_request();self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        for rel,text in json.loads((r.HERE/'S4P-SOURCE.json').read_text()).items():
            file=self.root/rel;file.parent.mkdir(parents=True,exist_ok=True);file.write_text(text)
    def test_complete_all_four_source_gates_and_exact_role_sites(self):
        report=policy.validate_source(self.root,self.req);self.assertEqual(report['status'],'STATIC_PASS')
        self.assertEqual(len(report['reports']['cfg_pfc']['rows']),8)
    def test_required_path_unknown_callable_and_cell_projection_fail_closed(self):
        req=copy.deepcopy(self.req)
        for k in ('lexical_source_sha256',):req.pop(k)
        file=self.root/policy.LEAF;original=file.read_text()
        file.write_text(original.replace('small_sort_fallback(&mut','missing_fallback(&mut',1))
        with self.assertRaisesRegex(ValueError,'unresolved static path'):lexical.check(self.root,req)
        file.write_text(original)
        cell=self.root/'library/core/src/cell.rs';cell.write_text(cell.read_text().replace('pub const fn get(&self) -> T','pub const fn missing_get(&self) -> T',1))
        with self.assertRaisesRegex(ValueError,'concrete Cell anchor drift'):lexical.check(self.root,req)
    def test_missing_new_cfg_module_and_wrong_contract_target_fail_closed(self):
        req=copy.deepcopy(self.req)
        for k in ('cfg_pfc_source_sha256','ordinary_contract_source_sha256'):req.pop(k)
        file=self.root/policy.VERIFY;original=file.read_text();file.write_text(original.replace('pub(super) mod sorting_s4_partition;','pub(super) mod missing_s4_partition;'))
        with self.assertRaises(ValueError):cfg.check(self.root,req)
        file.write_text(original);batch=self.root/policy.BATCH;batch.write_text(batch.read_text().replace('#[kani::stub(s2_swap_seam,weak_swap)]','#[kani::stub(swap_if_less,weak_swap)]',1))
        with self.assertRaisesRegex(ValueError,'active contract'):ordinary.check(self.root,req)

class ValidateLexerTests(unittest.TestCase):
    def test_full_text_cache_returns_fresh_lists_preserves_errors_and_restores(self):
        import cfg_pfc
        from validate_tokens import cached_tokens
        original=cfg_pfc.tokens
        inputs=('fn a() {}','fn b() {}','/* comment */ fn a() {}','"literal"','let x = 4;')
        expected=[original(x) for x in inputs]
        with cached_tokens(('cfg_pfc',)) as stats:
            for source,value in zip(inputs,expected):self.assertEqual(cfg_pfc.tokens(source),value)
            a=cfg_pfc.tokens(inputs[0]);a.clear();self.assertEqual(cfg_pfc.tokens(inputs[0]),expected[0])
            for _ in range(2):
                with self.assertRaises(cfg_pfc.GateError):cfg_pfc.tokens('/* unterminated')
            self.assertGreater(stats['cfg_pfc'].cache_info().hits,0)
        self.assertIs(cfg_pfc.tokens,original)
