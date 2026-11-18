"""Explicit S3-1 selection and unchanged shared envelopes. No dispatch authority."""
import copy
from r5_profile import CAPS
PROFILE='ch8-s3-1-actual-fullbyte-v1'
ORDER=('checker_order_corrupt','checker_count_corrupt','s3_swap_u8_geometry',
       's3_sort4_u8_separate','s3_sort4_u8_same_alloc','s3_insert_tail_u8_rel16',
       's3_merge8_u8_separate','s3_merge8_u8_same_alloc','sort13_weak')
DEFERRED=('swap_pfc','summary_witness','merge32_real','sort13_assumed','general32_assumed',
          'merge_order_corrupt','merge_count_corrupt','general32_weak')
BOUNDS=(34,34,36,8,50,36,12,50,34)
CFG='--cfg=kani_smallsort_sorting --cfg=kani_smallsort_controls --cfg=kani_smallsort_s2_assumed --cfg=kani_smallsort_s3_leaf'
PLAN='da89127150a550ccb3861a7bfc5b6205c6409e61'
INTAKE='ebd77a955b2b8d1b4e8079cfbf569386bcf0b130'
TARGETS=dict(zip(ORDER,(None,None,'swap_if_less','sort4_stable','sort4_stable','insert_tail','bidirectional_merge','bidirectional_merge',None)))

def enabled(request):return request.get('profile')==PROFILE

def groups(request):
    return [{'id':'s3-'+rid,'variant':'production','unwind':u,'row_ids':[rid]} for rid,u in zip(ORDER,BOUNDS)]

def validate(request):
    import s3_policy
    assert request['profile']==PROFILE and request['schema']=='ch8-s3-1-v1'
    assert request['s3']=={'selected':list(ORDER),'deferred':list(DEFERRED),'caps':CAPS,'plan_commit':PLAN,'intake_commit':INTAKE,
        'u_policy':'ZERO_U_FAIL_CLOSED; site-specific proposal PENDING_REVIEW_NOT_ENABLED',
        'unselected_full_obligations':'EXPLICIT_NOT_SELECTED_NO_PROMOTION'}
    assert 9*CAPS['slot_seconds']+CAPS['controller_seconds']+CAPS['cleanup_seconds']==6900
    s3_policy.validate_request(request)
    return True

def view(request):validate(request);return copy.deepcopy(request)
