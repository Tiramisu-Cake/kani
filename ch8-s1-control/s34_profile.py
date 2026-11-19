"""One combined seven-root discriminator; fixed caps, no implicit proof admission."""
import copy
from r5_profile import CAPS
PROFILE='ch8-s3s4-bridge1-fullbyte-v1'
ORDER=('checker_order_corrupt','checker_count_corrupt','sort13_weak','i_p01_b01_fullu8',
       'sort9_v34_b01_len09_real','fallback_cell_b01_n00_16','network_u8_b01_n00_08')
CANDIDATES=ORDER[3:]
DIAGNOSTICS=()
DEFERRED=('insert_full_rel16_allbases','insert_rel16_p15_active16','insert_rel16_p16_active17',
          'merge8_universal_init_provider','sort8_init_caller_34contexts','positive_sort13',
          'network_N09_32','generic_trait_dispatch','mutating_comparator','fullN16N32_mission')
BOUNDS=(34,34,34,36,36,36,36)
CFG='--cfg=kani_smallsort_sorting --cfg=kani_smallsort_controls --cfg=kani_smallsort_s2_assumed --cfg=kani_smallsort_s3_leaf'
PLAN='7749b8517ba42b400c41f0b4f7a7212a4fdcab8a'
INTAKE='5d9439a7641c929838bf075c6aa6533a353ee92d'
BOUNDARY='ff193cc35690a5daabaa849d412c58d9f286d893'
IMPLEMENTATION_TASK='e060dab687785f64560a5a563b0689c04d68a215'
INPUTS={'plan':PLAN,'intake':INTAKE,'intake_review':'028531727fc48ef9f26f16dfb95c2b2666c96dd7',
        'exact_admission':BOUNDARY,'S4_inventory':'9e013a2683afbf64de762e570a052c11917e52f7',
        'source_reference':'1b4a904f8144172f0a3682f84f1bd4afd80eaf5d','control_reference':'775574eb2f361ef90eade30330ff0d608530287f'}
ACCOUNTING={'ledger_g0':'df305d47173284dfd54ad55d6b7567c892790c87','item1_used':31,'item1_cap':31,
            'item2_used':13,'item2_cap':17,'total_used':44,'total_cap':48,
            'future_accounting':'COORDINATOR_ONLY; hypothetical counted attempt14/17,total45/48; no reservation or grant',
            'latest_admission_only':BOUNDARY,'reservation':False,'changed':False}
TARGETS={rid:'insert_tail' if rid==ORDER[3] else None for rid in ORDER}
CALLEES=dict(zip(ORDER[3:],('insert_tail','sort9_optimal','small_sort_fallback','small_sort_network')))

def enabled(request):return request.get('profile')==PROFILE
def groups(request):return [{'id':'s3-'+rid,'variant':'production','unwind':u,'row_ids':[rid]} for rid,u in zip(ORDER,BOUNDS)]
def classification(rid):
    assert rid in ORDER
    return {'category':('FIXED_NEGATIVE_CONTROL' if rid in ORDER[:3] else
            'BOUNDED_S3_ACTUAL_BODY_PFC_CANDIDATE' if rid==ORDER[3] else
            'BOUNDED_S3_ACTUAL_BODY_ORIGINAL_CANDIDATE' if rid==ORDER[4] else
            'S4_SYMBOLIC_LENGTH_DIRECT_HELPER_CANDIDATE' if rid==ORDER[5] else
            'S4_SYMBOLIC_LENGTH_DIRECT_HELPER_PREFIX_CANDIDATE'),
            'qualification_eligible':rid in CANDIDATES,'eligible_as_init_leaf_or_provider_summary':False,
            'actual_initialization_mask_and_dstinit':'NO_INDEPENDENT_INIT_THEOREM','proof_credit':'NONE'}
def valid_scope(rid,value):
    expected=classification(rid)
    return isinstance(value,dict) and value==expected and all(type(value[k]) is type(v) for k,v in expected.items())
def validate(request):
    import s34_policy
    assert request['profile']==PROFILE and request['schema']=='ch8-s3s4-bridge1-v1'
    assert request['s3']=={'selected':list(ORDER),'deferred':list(DEFERRED),'caps':CAPS,'plan_commit':PLAN,'intake_commit':INTAKE,
        'boundary_commit':BOUNDARY,'u_policy':'ZERO_U_FAIL_CLOSED; site-specific proposal PENDING_REVIEW_NOT_ENABLED',
        'unselected_full_obligations':'EXPLICIT_NOT_SELECTED_NO_PROMOTION'}
    assert request['budgets']['projected_group_count']==7
    assert 7*CAPS['slot_seconds']+CAPS['controller_seconds']+CAPS['cleanup_seconds']==5460<=CAPS['campaign_seconds']
    s34_policy.validate_request(request)
    return True
def view(request):validate(request);return copy.deepcopy(request)
