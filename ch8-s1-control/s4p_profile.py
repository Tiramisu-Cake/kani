"""Eight full-byte length blocks; every summary/provider edge remains disabled."""
import copy
from r5_profile import CAPS
PROFILE='ch8-s4p-1-fullbyte-length-blocks-v1'
SCHEMA='ch8-s4p-1-v1'
ORDER=('checker_order_corrupt','checker_count_corrupt','sort13_weak','s4p_cell_count_corrupt',
       's4p_fallback_b01_n00_02_fullbyte','s4p_fallback_b01_n03_04_fullbyte',
       's4p_network_b01_n00_02_fullbyte','s4p_network_b01_n03_04_fullbyte')
CANDIDATES=ORDER[4:]
DIAGNOSTICS=()
DEFERRED=('fallback_N05_16','network_N05_32','general_N00_32','Cell_semantic_provider',
          'generic_trait_dispatch','mutating_comparator','initialization_and_ownership','compiler_MIR_B1_B2')
BOUNDS=(34,34,34,36,36,36,36,36)
CFG='--cfg=kani_smallsort_sorting --cfg=kani_smallsort_controls --cfg=kani_smallsort_s2_assumed --cfg=kani_smallsort_s3_leaf --cfg=kani_smallsort_s4_partition'
PLAN='a931835b4af8dc8b2ad60e9a115bc0a4903b0b5e'
INTAKE='97eaff96cd28267e36af69fe98077dd08737eea6'
BOUNDARY='39606c431ba266a5dbab2163d0e5175428d38aec'
IMPLEMENTATION_TASK='c049f3c7f44d111db45baf36a5de24dc19209ee5'
INPUTS={'plan':PLAN,'intake':INTAKE,'intake_review':'135c04791a779e949079db723bdbc0e636873b37',
        'exact_admission':BOUNDARY,'source_reference':'f1bdf11902252ad1178f42403c253ae710fecbaf',
        'control_reference':'d675ef70dc1ada13330efc0990c2e1d6b0d21a5a',
        'prior_s3_1_actual_admission':'b4879b203e42e265f38ce1b44fe767aa78bb43fc'}
ACCOUNTING={'mode':'TRACKING_ONLY','reservation':False,'changed':False,
            'future_accounting':'USERCOORDINATOR_ONLY_AFTER_EXACT_REVIEW_AND_GO',
            'latest_admission_only':BOUNDARY}
TARGETS={rid:None for rid in ORDER}
CALLEES=dict(zip(CANDIDATES,('small_sort_fallback','small_sort_fallback','small_sort_network','small_sort_network')))
DOMAINS={rid:{'length_interval':([0,2] if i%2==0 else [3,4]),'allocation':34,'base':1,
              'logical_values':'ALL_34_INDEPENDENT_U8_0_255','initialized':True,
              'type':('Cell<u8>' if i<2 else 'u8'),'comparator':('KeyLess<Cell<u8>>' if i<2 else 'KeyLess<u8>'),
              'summary_edges':[]} for i,rid in enumerate(CANDIDATES)}
def enabled(request):return request.get('profile')==PROFILE
def groups(request):return [{'id':'s3-'+rid,'variant':'production','unwind':u,'row_ids':[rid]} for rid,u in zip(ORDER,BOUNDS)]
def classification(rid):
    assert rid in ORDER
    return {'category':('FIXED_NEGATIVE_CONTROL' if rid in ORDER[:3] else 'CELL_CHECKER_ONLY_NEGATIVE' if rid==ORDER[3] else 'S4_FULLBYTE_LENGTH_BLOCK_ACTUAL_BODY_CANDIDATE'),
            'qualification_eligible':rid in CANDIDATES,'eligible_as_init_leaf_or_provider_summary':False,
            'actual_initialization_mask_and_dstinit':'NO_INDEPENDENT_INIT_THEOREM','proof_credit':'NONE'}
def valid_scope(rid,value):
    expected=classification(rid)
    return isinstance(value,dict) and value==expected and all(type(value[k]) is type(v) for k,v in expected.items())
def validate(request):
    import s4p_policy
    assert request['profile']==PROFILE and request['schema']==SCHEMA
    assert request['s3']=={'selected':list(ORDER),'deferred':list(DEFERRED),'caps':CAPS,'plan_commit':PLAN,'intake_commit':INTAKE,
        'boundary_commit':BOUNDARY,'u_policy':'ZERO_U_FAIL_CLOSED; site-specific proposal PENDING_REVIEW_NOT_ENABLED',
        'unselected_full_obligations':'EXPLICIT_NOT_SELECTED_NO_PROMOTION'}
    assert type(request['budgets']['projected_group_count']) is int and request['budgets']['projected_group_count']==8
    assert 8*CAPS['slot_seconds']+CAPS['controller_seconds']+CAPS['cleanup_seconds']==6180<=CAPS['campaign_seconds']
    s4p_policy.validate_request(request)
    return True
def view(request):validate(request);return copy.deepcopy(request)
