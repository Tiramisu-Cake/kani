# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""S4 literal source/role binding; native producer IDs resolved, never predicted."""
import hashlib,json,re
from pathlib import Path
import cfg_pfc as c
import s4p2r2_profile as p
import s4p2r2_cfg_pfc, s4p2r2_ordinary_contracts, s4p2r2_contract_stacks, s4p2r2_lexical_bindings
import s2_correspondence
HERE=Path(__file__).resolve().parent
SMALLSORT=c.BASE+'slice/sort/shared/smallsort.rs'
VERIFY=c.BASE+'slice/sort/shared/smallsort/verify.rs'
BATCH=s2_correspondence.BATCH
OLD_LEAF=c.BASE+'slice/sort/shared/smallsort/verify/sorting_s4_partition.rs'
LEAF=c.BASE+'slice/sort/shared/smallsort/verify/sorting_s4_network_r2.rs'
PREFIX='slice::sort::shared::smallsort::verify::'
TOOL='0aac16ef62da9e9d5645782d458593e5d78143ba'

def digest(data):return hashlib.sha256(data).hexdigest()

def normalize_labels(text):
    result,n=re.subn(r'assert!\((.*), "(S2_[A-Z0-9_]+)"\)',r'kani::assert(\1, "\2")',text)
    c.need(n==22,'all22 literal labels required')
    return result

def validate_request(r):
    raw=(HERE/'S4P2R2-INVENTORY.json').read_bytes()
    assert digest(raw)==INVENTORY_SHA256, 'exact S4P2 inventory drift'
    expected=json.loads(raw)
    assert json.dumps({k:r[k] for k in expected},sort_keys=True)==json.dumps(expected,sort_keys=True), 'exact role/domain/source inventory mismatch'
    assert r['schema']=='ch8-s4p-2r2-v1' and r['profile']==p.PROFILE
    from s4p2r2_pins import STD_SHA,STD_TREE
    assert r['std_sha']==STD_SHA and r['std_tree']==STD_TREE
    assert r['proof_credit']=='NONE' and r['native_status']=='NOT_RUN'
    assert r['tool_sha']==TOOL and r['control_parent']=='4059c900e50ba179d824a1e6f6bd7798cf343e36'
    assert r['source_parent']=='c12867b1e651a3927cbd9f169fe2c3d3728a44c3'
    assert [x['id'] for x in r['rows']]==list(p.ORDER)
    assert r['execution_groups']==p.groups(r) and r['replacement_unions']==[] and r['variants']=={}
    assert r['flags']=={'unstable':['function-contracts','mem-predicates','float-lib','c-ffi','loop-contracts','quantifiers','stubbing','export-json'],
       'assert_contracts':False,'jobs':1,'harness_timeout':'600s','exact':True,'default_unwind':50,'cbmc_args':['--object-bits','12'],'RUSTFLAGS':p.CFG}
    for key in ('cfg_pfc_source_sha256','contract_stack_source_sha256','ordinary_contract_source_sha256','lexical_source_sha256'):
        assert isinstance(r[key],dict) and r[key] and all(isinstance(k,str) and isinstance(v,str) and len(v)==64 for k,v in r[key].items())
    assert r['ci_changed_paths']==sorted(set(r['ci_changed_paths']))
    assert r['ci_deleted_paths']==sorted(set(r['ci_deleted_paths']))
    assert set(r['ci_deleted_paths'])<=set(r['ci_changed_paths'])
    assert all(path.startswith('.github/workflows/') for path in r['ci_deleted_paths'])
    assert set(r['ci_payload_sha256'])==set(r['ci_changed_paths'])-set(r['ci_deleted_paths'])-{'ch8-s1-control/CI-REQUEST.json'}
    assert all(path.startswith(('ch8-s1-control/','.github/workflows/')) for path in r['ci_changed_paths'])
    assert r['future_runs']==1 and r['qualification_inventory']==list(p.CANDIDATES)
    assert r['diagnostic_assumed_inventory']==[] and r['formal_expected_inventory']==[]
    assert r['diagnostic_only_inventory']==list(p.DIAGNOSTICS)
    assert r['unreachable_admission']=={'mode':'REJECT_ALL','proposal':'S3-U-SITE-REVIEW-v1','enabled':False,'unknown':'REJECT','role_unreachable':'REJECT'}
    for row,u in zip(r['rows'],p.BOUNDS):
        rid=row['id'];target=p.TARGETS[rid];positive=rid in p.CANDIDATES;b=r['source_bindings'][rid]
        assert p.valid_scope(rid,row['scope_classification'])
        if rid in p.DIAGNOSTICS:
            assert row['assurance']=='DIAGNOSTIC_ONLY_INITIALIZATION_OPEN'
            assert all(not any(word in role['description'] for word in ('INITIALIZED','INIT_MASK','DST_INIT','MASK_PRESERVED')) for role in row['roles'])
        file=LEAF if positive else OLD_LEAF if rid==p.ORDER[3] else BATCH;mod=Path(file).stem
        assert row['selector']==PREFIX+mod+'::'+rid and row['source_qualified_selector']=='core::'+row['selector']
        assert row['mode']==('PFC' if target else 'Original') and b['target']==target and row['target']==target
        assert row['variant']=='production' and row['unwind']==u and row['timeout_seconds']==600
        assert row['proof_credit']=='NONE' and row['state']=='NOT_RUN'
        assert b['file']==file and b['sha256']==r['changed_file_sha256'][file] and b['selector']==row['selector'] and b['mode']==row['mode']
        assert row['expected']==('SUCCESS' if positive else 'DETECTED')
        assert row['required_cover_count']==len(row['required_cover_messages'])
        assert 'oracle' not in row  # no frozen/guessed producer ordinal
        assert type(row['unwind']) is int and type(row['timeout_seconds']) is int
        assert type(row['required_cover_count']) is int
        if positive:
            model=next(x for x in CONTRACT['rows'] if x['design_id']==p.DESIGNS[rid])
            lo,hi=p.DOMAINS[rid]['length_interval']
            prefix='S4P2R2_N_'+(f'{lo:02}' if lo==hi else '00_01')
            assert row['required_success_messages']==[prefix+'_'+x for x in model['assertion_roles']]
            assert row['required_cover_messages']==[prefix+'_'+x for x in model['cover_roles']]
            assert row['required_cover_count']==model['cover_count']
        elif rid==p.ORDER[3]:
            assert row['required_success_messages']==['S4_NEG_CELL_ACTIVE'] and row['failure_description']=='S4_NEG_CELL_COUNT'
            assert row['required_cover_messages']==[]
        else:
            assert row['required_success_messages']==[] and row['required_cover_messages']==[]
            assert row['failure_description']==dict(zip(p.ORDER[:3],('S2_NEG_CHECKER_ORDER','S2_NEG_CHECKER_COUNT','S2_NEG_SORT13_WEAK')))[rid]
        roles=row['roles'];assert roles and len({x['description'] for x in roles})==len(roles)
        for role in roles:
            assert role['producer_id']=='UNKNOWN_UNTIL_SAME_INVOCATION_INVENTORY'
            assert role['file']==file and role['source_sha256']==b['sha256']
            assert type(role['line']) is int and role['line']>0 and role['class'] in ('assertion','cover')
            assert role['status']==('SATISFIED' if role['class']=='cover' else 'FAILURE' if role['description']==row.get('failure_description') else 'SUCCESS')
        assert {x['description'] for x in roles if x['class']=='cover'}==set(row['required_cover_messages'])
        assert {x['description'] for x in roles if x['class']=='assertion'}==(set(row['required_success_messages']) | ({row['failure_description']} if not positive else set()))
    assert r['accounting_reference']==p.ACCOUNTING and r['entry_g0']==p.IMPLEMENTATION_TASK
    assert r['s4p2r2_inputs']==p.INPUTS
    assert json.dumps(r['domains'],sort_keys=True)==json.dumps(p.DOMAINS,sort_keys=True)
    assert r['enabled_summary_edges']==[]
    assert r['negative_checker']=={'id':p.ORDER[3],'model':'Cell<u8>/KeyLess<Cell<u8>>','active':[1,3],'before':[0,1],'after':[0,0],'actual_callee_called':False}
    return True

def validate_source(std,r):
    validate_request(r);std=Path(std)
    baseline=(HERE/'fixtures/s3-parent-bd62-batch.rs.txt').read_text()
    assert digest(baseline.encode())=='e0f47062d71f256fed49b8ad8144c2a83c9a96ecd85646605b1c2fe9b707d0dc'
    assert (std/BATCH).read_text()==normalize_labels(baseline)
    # Existing copy/seam correspondence checked on its exact pre-normalization bytes.
    correspondence=s2_correspondence.check(baseline,(std/SMALLSORT).read_text())
    reports={name:module.check(std,r) for name,module in [
        ('ordinary',s4p2r2_ordinary_contracts),('cfg_pfc',s4p2r2_cfg_pfc),('contract_stacks',s4p2r2_contract_stacks),('lexical',s4p2r2_lexical_bindings)]}
    import s4p2r2_domain
    domain=s4p2r2_domain.check(std)
    validate_roles(std,r)
    # Source constants, bodies, expressions and initialization are additionally exact-hash sealed.
    expected=json.loads((HERE/'S4P2R2-SOURCE.json').read_text())
    for rel,text in expected.items():assert (std/rel).read_text()==text,rel
    return {'status':'STATIC_PASS','reports':reports,'domain_correspondence':domain,'legacy_copy_correspondence':correspondence,'proof_credit':'NONE'}

def validate_roles(std,r):
    std=Path(std)
    for row in r['rows']:
        b=r['source_bindings'][row['id']];data=(std/b['file']).read_bytes();lines=data.decode().splitlines()
        assert digest(data)==b['sha256']
        for loc in b['locations']:assert lines[loc['line']-1]==loc['source']
        start=lines.index('fn '+row['id']+'() {')
        end=next(i for i in range(start+1,len(lines)) if lines[i]=='}')
        attr=start-1
        while attr>0 and lines[attr-1].startswith('#[kani::'):attr-=1
        expected_attr='#[kani::proof_for_contract('+b['target']+')]' if b['target'] else '#[kani::proof]'
        assert lines[attr]==expected_attr and lines[start-1]=='#[kani::unwind('+str(row['unwind'])+')]'
        assert {x['line'] for x in b['locations']}=={attr+1,start+1}
        found=[(kind,label,i+1) for i in range(start+1,end) for kind,label in re.findall(r'kani::(assert|cover)\(.*?, "([A-Z0-9_]+)"\)',lines[i])]
        assert found==[('cover' if x['class']=='cover' else 'assert',x['description'],x['line']) for x in row['roles']]
        for role in row['roles']:
            assert lines[role['line']-1]==role['source_line']
            assert ('kani::cover(' if role['class']=='cover' else 'kani::assert(') in role['source_line']
            assert '"'+role['description']+'"' in role['source_line']
    return True


def expected_observation(row,parsed,properties):
    """Caller first checks full rich/export inventory, identity, epochs and exit."""
    try:
        if not p.valid_scope(row['id'],row.get('scope_classification')):return False
        if row['id'] in p.DIAGNOSTICS and (row.get('assurance')!='DIAGNOSTIC_ONLY_INITIALIZATION_OPEN' or any(any(w in role['description'] for w in ('INITIALIZED','INIT_MASK','DST_INIT','MASK_PRESERVED')) for role in row['roles'])):return False
        if parsed.get('state')!='RECORDED_OBSERVATION' or parsed.get('outcome')!='RECORDED':return False
        h=parsed['harness'];records=properties['properties']
        if any(type(h.get(k)) is not int for k in ('n_properties','n_failed')):return False
        if h['n_properties']!=len(records):return False
        if any(type(h.get(kind,{}).get(key)) is not int for kind,keys in [('checks',('total','success')),('covers',('total',))] for key in keys):return False
        source_root=parsed.get('source_root')
        if not isinstance(source_root,str) or not Path(source_root).is_absolute():return False
        if properties['name']!=row['selector'] or not isinstance(records,list) or not records:return False
        if any(not isinstance(x,dict) or not isinstance(x.get('id'),str) or not x['id'] for x in records):return False
        if len({x['id'] for x in records})!=len(records):return False
        # All unsupported, unknown, U, unreachable role and extra failures reject.
        if h.get('unsupported_constructs')!=[]:return False
        checks=[x for x in records if x.get('class')!='cover'];covers=[x for x in records if x.get('class')=='cover']
        if any(x.get('status') not in ('SUCCESS','FAILURE') for x in checks):return False
        if any(x.get('status')!='SATISFIED' for x in covers):return False
        failures=[x for x in checks if x['status']=='FAILURE']
        target_failure=row['expected']=='DETECTED'
        if h['n_failed']!=len(failures):return False
        if len(failures)!=(1 if target_failure else 0):return False
        if h.get('outcome')!={'kind':'COMPLETED','verdict':'FAILURE' if target_failure else 'SUCCESS'}:return False
        if set(x['description'] for x in covers)!=set(row['required_cover_messages']) or len(covers)!=row['required_cover_count']:return False
        for role in row['roles']:
            matches=[x for x in records if x.get('description')==role['description']]
            if not matches:return False
            # Loops may yield several instances, all must match and all are kept.
            if role['status']=='FAILURE' and len(matches)!=1:return False
            for x in matches:
                file=Path(x.get('file','')).as_posix()
                if file!=str(Path(source_root)/role['file']):return False
                if str(x.get('line'))!=str(role['line']) or x.get('class')!=role['class'] or x.get('status')!=role['status']:return False
        if target_failure:
            named=h.get('failed_properties')
            if not isinstance(named,list) or len(named)!=1 or any(failures[0].get(k)!=named[0].get(k) for k in ('id','class','description','file','line','status')):return False
        if h['checks']['total']!=len(checks) or h['checks']['success']!=len(checks)-len(failures):return False
        if h['checks']['failure']!=[x['id'] for x in failures]:return False
        if any(h['checks'].get(k)!=[] for k in ('unreachable','undetermined','error','unknown','other')):return False
        if h['covers']['total']!=len(covers) or set(h['covers']['satisfied'])!={x['id'] for x in covers}:return False
        if any(h['covers'].get(k)!=[] for k in ('unsatisfiable','unreachable','undetermined','error','unknown','other')):return False
        return True
    except (KeyError,TypeError,ValueError,AttributeError):return False

INVENTORY_SHA256='7c57e37b2f0ad563e0710f0876f128bec52904bad639c5b757c4d80eada325d7'
CONTRACT_BYTES=(HERE/"S4P2R2-ROLE-CONTRACT.json").read_bytes()
assert digest(CONTRACT_BYTES)=='c90950843f17903b0271a0cf349e4afd5e9189924119aacb252904f0a0b7ef1d'
CONTRACT=json.loads(CONTRACT_BYTES)
