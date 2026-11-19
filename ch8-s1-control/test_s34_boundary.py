"""Bridge domain, mixed-mode, resource and strict-admission adverse controls."""
import copy,json,unittest
from unittest import mock
import runner as r
import s34_profile as p
import s34_policy as policy
import s34_lexical_bindings as lexical
import test_s34 as f

class BoundaryTests(unittest.TestCase):
    def test_seven_mixed_modes_and_null_original_targets(self):
        req=r.load_request();self.assertEqual([x['id'] for x in req['rows']],list(p.ORDER))
        self.assertEqual([x['mode'] for x in req['rows']],['Original']*3+['PFC']+['Original']*3)
        for row in req['rows']:
            self.assertEqual(row['target'],p.TARGETS[row['id']]);self.assertEqual(req['source_bindings'][row['id']]['target'],row['target'])
        for idx in (4,5,6):
            for target in ('sort9_optimal',False,0,''):
                bad=copy.deepcopy(req);bad['rows'][idx]['target']=target
                with self.subTest(idx=idx,target=target),self.assertRaises(AssertionError):p.validate(bad)
            bad=copy.deepcopy(req);bad['rows'][idx]['mode']='PFC'
            with self.assertRaises(AssertionError):p.validate(bad)
    def test_source_domain_all_lengths_fullbytes_and_concrete_cell_routes(self):
        source=json.loads((r.HERE/'S34-SOURCE.json').read_text())[policy.LEAF]
        for prefix,count in [('B1_F_N',17),('B1_N_N',9)]:
            for n in range(count):self.assertIn(f'kani::cover(n == {n}, "{prefix}{n:02}");',source)
            row=r.load_request()['rows'][5 if count==17 else 6]
            self.assertEqual([x for x in row['required_cover_messages'] if x.startswith(prefix) and x[len(prefix):].isdigit()],[f'{prefix}{n:02}' for n in range(count)])
        for fragment in ('let bytes: [u8; 34] = kani::any();','let mut v = [const { Cell::new(0u8) }; 34];','for i in 0..34 { v[i].set(bytes[i]); }','kani::assume(n <= 16);','kani::assume(n <= 8);','sort9_optimal(&mut v[1..10]', 'small_sort_fallback(&mut v[1..1 + n]', 'small_sort_network(&mut v[1..1 + n]'):
            self.assertIn(fragment,source)
        for forbidden in ('is_initialized(', 'stub_verified(', 'kani::stub(', '% 2', '& 1', 'assume(ordered'):
            self.assertNotIn(forbidden,source)
        self.assertEqual(source.count('proof_for_contract('),1)
    def test_profile_rejects_old_schema_order_geometry_scope_promotion_and_cap(self):
        req=r.load_request()
        from s32_profile import validate as oldvalidate
        with self.assertRaises((AssertionError,KeyError)):oldvalidate(req)
        self.assertEqual(len(r.load_request(r.HERE/'fixtures/s3-2-request.json')['rows']),8)
        for mutate in (lambda q:q.update(schema='ch8-s3-2-v1'),lambda q:q['rows'].reverse(),
                       lambda q:q['execution_groups'].pop(),lambda q:q['s3']['caps'].update(local_rss_kib=6815744),
                       lambda q:q['rows'][5]['scope_classification'].update(eligible_as_init_leaf_or_provider_summary=True),
                       lambda q:q['rows'][5]['scope_classification'].update(qualification_eligible=1),
                       lambda q:q['source_bindings'][p.ORDER[3]].update(target=None),
                       lambda q:q['accounting_reference'].update(item2_used=12)):
            bad=copy.deepcopy(req);mutate(bad)
            with self.assertRaises((AssertionError,KeyError,TypeError)):p.validate(bad)
    def test_no_prior_admission_transfer_or_unknown_u_success_guard_waiver(self):
        for row in r.load_request()['rows'][3:]:
            for case in ('u','unsupported-success','null-location','missing-cover','unknown'):
                a,b=f.inventory(row)
                if case=='u':b['properties'][0]['status']='UNREACHABLE'
                elif case=='unsupported-success':a['harness']['unsupported_constructs']=[{'status':'SUCCESS','id':'historically-waived'}]
                elif case=='null-location':b['properties'][0]['file']=None
                elif case=='missing-cover':b['properties'].pop()
                else:a['outcome']='UNKNOWN'
                with self.subTest(row=row['id'],case=case):self.assertFalse(policy.expected_observation(row,a,b))
    def test_effective_low_memory_and_seven_slot_arithmetic(self):
        self.assertEqual(7*p.CAPS['slot_seconds']+p.CAPS['controller_seconds']+p.CAPS['cleanup_seconds'],5460)
        from pathlib import Path
        available=3*1024*1024
        def memory(path,*args,**kw):
            if str(path)=='/proc/meminfo':return f'MemAvailable: {available} kB\n'
            raise FileNotFoundError(str(path))
        with mock.patch.object(Path,'read_text',memory):
            budget=r.group_memory_budget();self.assertEqual(budget['group_cap_kib'],1024*1024)
            self.assertEqual(min(budget['group_cap_kib'],r.RSS_CAP_KIB),1024*1024)
        available=1024*1024
        with mock.patch.object(Path,'read_text',memory),self.assertRaises(r.RunnerError):r.group_memory_budget()

class CellGateTests(f.SourceTests):
    # Inherit setup only; explicit suite below selects just the concrete adverse gate.
    def test_cell_missing_constructor_or_method_anchor_fails_closed(self):
        for old,new in [('pub const fn new(value: T) -> Cell<T>','pub const fn renamed_new(value: T) -> Cell<T>'),('pub const fn get(&self) -> T','pub const fn renamed_get(&self) -> T')]:
            file=self.root/'library/core/src/cell.rs';original=file.read_text();self.assertIn(old,original)
            file.write_text(original.replace(old,new,1))
            try:
                with self.assertRaisesRegex(ValueError,'Cell|provider'):lexical.check(self.root,self.gate_request())
            finally:file.write_text(original)
