"""Explicit S3-2 eight-row scope; diagnostics can never become init/provider leaves."""
import copy
from r5_profile import CAPS
PROFILE='ch8-s3-2-capped-fullbyte-v1'
ORDER=('checker_order_corrupt','checker_count_corrupt','sort13_weak','i_p01_b1_16',
       'm8_s32_d00_allinit','i_p16_b1_16','m8_s32_d00_partial_diag','m8_s40_d16_partial_diag')
DIAGNOSTICS=ORDER[6:]
CANDIDATES=ORDER[3:6]
DEFERRED=('s3_insert_tail_u8_rel16','s3_merge8_u8_same_alloc','sort8_registration_only',
          'merge32_real','sort13_assumed','general32_assumed','positive_sort8','positive_sort9','positive_sort13','fullN16','fullN32')
BOUNDS=(34,34,34,36,50,36,50,50)
CFG='--cfg=kani_smallsort_sorting --cfg=kani_smallsort_controls --cfg=kani_smallsort_s2_assumed --cfg=kani_smallsort_s3_leaf'
PLAN='86f5bcc11acd0dbc512e9576514dc52c733b46b6'
INTAKE='31c1dbfc7ca2df34b28bb5eb7ee81bc207ee5642'
BOUNDARY='20eb52b5efe45a89491dced2aab34d40dbe371f7'
TARGETS=dict(zip(ORDER,(None,None,None,'insert_tail','bidirectional_merge','insert_tail','bidirectional_merge','bidirectional_merge')))
def enabled(request):return request.get('profile')==PROFILE
def groups(request):return [{'id':'s3-'+rid,'variant':'production','unwind':u,'row_ids':[rid]} for rid,u in zip(ORDER,BOUNDS)]
def classification(rid):
    assert rid in ORDER
    return {'category':'DIAGNOSTIC_ONLY_INITIALIZATION_OPEN' if rid in DIAGNOSTICS else 'BOUNDED_ACTUAL_BODY_PFC_CANDIDATE' if rid in CANDIDATES else 'FIXED_NEGATIVE_CONTROL',
            'qualification_eligible':rid in CANDIDATES,'eligible_as_init_leaf_or_provider_summary':False,
            'actual_initialization_mask_and_dstinit':'OPEN_UNPROVED' if rid in DIAGNOSTICS else 'NO_INDEPENDENT_INIT_THEOREM',
            'proof_credit':'NONE'}
def valid_scope(rid,value):
    expected=classification(rid)
    return isinstance(value,dict) and value==expected and all(type(value[k]) is type(v) for k,v in expected.items())
def validate(request):
    import s32_policy
    assert request['profile']==PROFILE and request['schema']=='ch8-s3-2-v1'
    assert request['s3']=={'selected':list(ORDER),'deferred':list(DEFERRED),'caps':CAPS,'plan_commit':PLAN,'intake_commit':INTAKE,
        'boundary_commit':BOUNDARY,'u_policy':'ZERO_U_FAIL_CLOSED; site-specific proposal PENDING_REVIEW_NOT_ENABLED',
        'unselected_full_obligations':'EXPLICIT_NOT_SELECTED_NO_PROMOTION'}
    assert 8*CAPS['slot_seconds']+CAPS['controller_seconds']+CAPS['cleanup_seconds']==6180<=CAPS['campaign_seconds']
    s32_policy.validate_request(request)
    return True
def view(request):validate(request);return copy.deepcopy(request)
