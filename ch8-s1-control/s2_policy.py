# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""S2 static binding and offline oracle checks; never grants proof credit."""
import hashlib
import re
import negative_oracle
import cfg_pfc
ROOTS=('swap_pfc','summary_witness','merge32_real','sort13_assumed','general32_assumed',
 'merge_order_corrupt','merge_count_corrupt','checker_count_corrupt','checker_order_corrupt','sort13_weak','general32_weak')
PREFIX='slice::sort::shared::smallsort::verify::sorting_s2_batch::'
CFG='--cfg=kani_smallsort_sorting --cfg=kani_smallsort_controls --cfg=kani_smallsort_s2_assumed'
SMALLSORT='library/core/src/slice/sort/shared/smallsort.rs'
BATCH='library/core/src/slice/sort/shared/smallsort/verify/sorting_s2_batch.rs'
BASE='99e8456d200fff1299ee5756279cddb23921dc65'
TOOL='0aac16ef62da9e9d5645782d458593e5d78143ba'
STUBS={'sort13_assumed':['#[kani::stub_verified(swap_if_less)]'],
 'general32_assumed':['#[kani::stub_verified(sort8_stable)]','#[kani::stub_verified(insert_tail)]','#[kani::stub_verified(bidirectional_merge)]'],
 'sort13_weak':['#[kani::stub(swap_if_less,weak_swap)]'],
 'general32_weak':['#[kani::stub_verified(sort8_stable)]','#[kani::stub_verified(insert_tail)]','#[kani::stub(bidirectional_merge,weak_merge)]']}
def digest(data):return hashlib.sha256(data).hexdigest()

def validate_request(r):
    assert r['schema']=='ch8-s2-batch3probes-v1'
    assert isinstance(r['cfg_pfc_source_sha256'],dict) and len(r['cfg_pfc_source_sha256'])==8
    assert [x['id'] for x in r['rows']]==list(ROOTS)
    assert r['base_std_sha']==BASE and r['tool_sha']==TOOL
    assert r['formal_expected_inventory']==['merge32_real']
    assert r['diagnostic_assumed_inventory']==['sort13_assumed','general32_assumed']
    assert r['qualification_inventory']==['swap_pfc']
    assert r['proof_credit']=='NONE' and r['future_runs']==1
    assert r['runtime_smallsort_base_sha256']=='45ae77ad0bb2a74cfab1aa53d5e1c48311f0b483c94eb52d96d97f680bd39651'
    assert r['flags']=={'unstable':['function-contracts','mem-predicates','float-lib','c-ffi','loop-contracts','quantifiers','stubbing','export-json'],'assert_contracts':False,'jobs':1,'harness_timeout':'600s','exact':True,'default_unwind':34,'cbmc_args':['--object-bits','12'],'RUSTFLAGS':CFG}
    assert r['execution_groups']==[{'id':'s2-batch3probes-u34','variant':'production','unwind':34,'row_ids':list(ROOTS)}]
    assert r['replacement_unions']==[] and r['variants']=={}
    for row in r['rows']:
        rid=row['id'];b=r['source_bindings'][rid]
        assert row['mode']==('PFC' if rid=='swap_pfc' else 'Original')
        assert b['target']==('swap_if_less' if rid=='swap_pfc' else None)
        assert row['selector']==PREFIX+rid and row['source_qualified_selector']=='core::'+PREFIX+rid
        assert row['variant']=='production' and row['unwind']==34 and row['timeout_seconds']==600
        assert row['proof_credit']=='NONE' and row['state']=='NOT_RUN'
        assert b['file']==BATCH and b['selector']==row['selector'] and b['mode']==row['mode']
        assert row['required_cover_count']==len(row['required_cover_messages'])
        assert b['sha256']==r['changed_file_sha256'][BATCH]
        if rid in ROOTS[:5]:
            assert row['expected']=='SUCCESS' and row['required_cover_count']>=3
            assert row['required_success_messages'] and 'oracle' not in row
        else:
            assert row['expected']=='DETECTED' and row['required_cover_count']==0
            o=row['oracle']
            assert o['property_id']==row['selector']+'.assertion.1'
            assert o['selector']==row['selector'] and o['file']==BATCH and o['class']=='assertion'
            assert o['source_sha256']==b['sha256'] and o['intended_message']==row['failure_description']
        if rid in ('sort13_assumed','general32_assumed'):assert row['assurance']=='DIAGNOSTIC_ASSUMED'
    assert sum(x['timeout_seconds'] for x in r['rows'])+r['budgets']['compile_seconds']==7500
    return True

def validate_source(std,r):
    validate_request(r)
    cfg_pfc.check(std,r)
    lines=(std/BATCH).read_text().splitlines()
    for row in r['rows']:
        rid=row['id'];b=r['source_bindings'][rid]
        assert digest((std/b['file']).read_bytes())==b['sha256']
        start=next(i for i,s in enumerate(lines) if s.startswith('fn '+rid+'('))
        attr=start-1
        while attr>0 and lines[attr-1].startswith('#[kani::'):attr-=1
        attrs=lines[attr:start]
        expected='#[kani::proof_for_contract(swap_if_less)]' if rid=='swap_pfc' else '#[kani::proof]'
        assert attrs[0]==expected and lines[start]=='fn '+rid+'() {'
        assert {x['line'] for x in b['locations']}=={start+1,attr+1}
        if 'oracle' in row:
            o=row['oracle'];line=lines[o['line']-1]
            assert line==o['source_line'] and '"'+row['failure_description']+'"' in line
            end=next((i for i in range(start+1,len(lines)) if lines[i]=='}'),len(lines))
            assertions=[s for s in lines[start+1:end] if re.search(r'\bassert!\(',s)]
            assert len(assertions)==1 and line in assertions
        assert [s for s in attrs if 'stub' in s]==STUBS.get(rid,[])
    added='#[cfg_attr(all(kani, kani_smallsort_sorting, kani_smallsort_s2_assumed),'
    small=(std/SMALLSORT).read_text()
    stripped='\n'.join(s for s in small.splitlines() if not s.startswith(added))+'\n'
    assert digest(stripped.encode())==r['runtime_smallsort_base_sha256']
    assert sum(s.startswith(added) for s in small.splitlines())==8
    return True

def expected_observation(row,parsed,properties):
    """Input must already be parser-bound plus same-invocation rich.validate.

    Exact source/tool/request/binary/compile identities remain caller obligations.
    True means an expected source-reported observation, never formal admission.
    """
    if parsed.get('state')!='RECORDED_OBSERVATION' or parsed.get('outcome')!='RECORDED':return False
    h=parsed.get('harness');records=properties.get('properties') if isinstance(properties,dict) else None
    if not isinstance(h,dict) or not isinstance(records,list) or properties.get('name')!=row['selector']:return False
    byid={p.get('id'):p for p in records if isinstance(p,dict)}
    if len(byid)!=len(records):return False
    if row['expected']=='DETECTED':
        o=row['oracle']
        actual=byid.get(o['property_id'],{})
        return (negative_oracle.matches(h,o) and actual.get('description')==row['failure_description']
                and all(actual.get(k)==h['failed_properties'][0].get(k) for k in ('id','class','description','file','line','status')))
    if h.get('outcome')!={'kind':'COMPLETED','verdict':'SUCCESS'}:return False
    checks,covers=h.get('checks',{}),h.get('covers',{})
    if any(checks.get(k)!=[] for k in ('failure','unreachable','undetermined','error','unknown','other')):return False
    if checks.get('success')!=checks.get('total'):return False
    if any(covers.get(k)!=[] for k in ('unsatisfiable','unreachable','undetermined','error','unknown','other')):return False
    successful={p.get('description') for p in records if p.get('class')!='cover' and p.get('status')=='SUCCESS'}
    satisfied={p.get('description') for p in records if p.get('class')=='cover' and p.get('status')=='SATISFIED'}
    return (set(row['required_success_messages']).issubset(successful) and set(row['required_cover_messages'])==satisfied and covers.get('total')==row['required_cover_count'])
