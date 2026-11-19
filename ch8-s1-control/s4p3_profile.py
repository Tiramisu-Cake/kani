# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Eight full-byte length blocks; every summary/provider edge remains disabled."""
import copy
from r5_profile import CAPS
PROFILE='ch8-s4p-3-network-fullbyte-concrete-calls-v1'
SCHEMA='ch8-s4p-3-v1'
ORDER=('checker_order_corrupt', 'checker_count_corrupt', 'sort13_weak', 's4p_cell_count_corrupt', 's4p3_network_b01_n08_fullbyte', 's4p3_network_b01_n09_fullbyte', 's4p3_network_b01_n13_fullbyte', 's4p3_network_b01_n17_fullbyte')
CANDIDATES=ORDER[4:]
DIAGNOSTICS=()
DEFERRED=('fallback_N05_16','network_N05_32','general_N00_32','Cell_semantic_provider',
          'generic_trait_dispatch','mutating_comparator','initialization_and_ownership','compiler_MIR_B1_B2')
BOUNDS=(34,34,34,36,36,36,36,36)
CFG='--cfg=kani_smallsort_sorting --cfg=kani_smallsort_controls --cfg=kani_smallsort_s2_assumed --cfg=kani_smallsort_s3_leaf --cfg=kani_smallsort_s4_partition'
PLAN='c0de8471801ac22b38e3290c7a6b75742135af6b'
INTAKE='c0de8471801ac22b38e3290c7a6b75742135af6b'
BOUNDARY='8896f60ae9e0ea1c706c6b8693d00e2500190676'
IMPLEMENTATION_TASK='778418b5a6c59e9b649435fd4bbc7a61ae0cd2ec'
INPUTS={'plan': 'c0de8471801ac22b38e3290c7a6b75742135af6b', 'plan_review': '762a2a678eb624d1ddd18f0764a365e7787392c0', 'source_reference': '8faf8e62af8f82b5c46af020086f8df591b6757e', 'control_reference': '3d3fb715271e3b195c6e0eee3557d5b0a6aad00d', 'authority': '778418b5a6c59e9b649435fd4bbc7a61ae0cd2ec', 'intake': 'c0de8471801ac22b38e3290c7a6b75742135af6b', 'network_admission_reference': '8896f60ae9e0ea1c706c6b8693d00e2500190676', 'role_contract_sha256': '371d6e557189dba0e0647753dd0222db20f6b975ad59968248b6f1179022d59b'}
ACCOUNTING={'mode':'TRACKING_ONLY','reservation':False,'changed':False,
            'future_accounting':'USERCOORDINATOR_ONLY_AFTER_EXACT_REVIEW_AND_GO',
            'latest_admission_only':BOUNDARY}
TARGETS={rid:None for rid in ORDER}
CALLEES={rid:"small_sort_network" for rid in CANDIDATES}
DOMAINS={'s4p3_network_b01_n08_fullbyte': {'length_interval': [8, 8], 'allocation': 34, 'base': 1, 'logical_values': 'ALL_34_INDEPENDENT_U8_0_255', 'initialized': True, 'type': 'u8', 'comparator': 'KeyLess<u8>', 'summary_edges': []}, 's4p3_network_b01_n09_fullbyte': {'length_interval': [9, 9], 'allocation': 34, 'base': 1, 'logical_values': 'ALL_34_INDEPENDENT_U8_0_255', 'initialized': True, 'type': 'u8', 'comparator': 'KeyLess<u8>', 'summary_edges': []}, 's4p3_network_b01_n13_fullbyte': {'length_interval': [13, 13], 'allocation': 34, 'base': 1, 'logical_values': 'ALL_34_INDEPENDENT_U8_0_255', 'initialized': True, 'type': 'u8', 'comparator': 'KeyLess<u8>', 'summary_edges': []}, 's4p3_network_b01_n17_fullbyte': {'length_interval': [17, 17], 'allocation': 34, 'base': 1, 'logical_values': 'ALL_34_INDEPENDENT_U8_0_255', 'initialized': True, 'type': 'u8', 'comparator': 'KeyLess<u8>', 'summary_edges': []}}
DESIGNS={'s4p3_network_b01_n08_fullbyte': 'PLAN_N08_V34_B01_FULLU8', 's4p3_network_b01_n09_fullbyte': 'PLAN_N09_V34_B01_FULLU8', 's4p3_network_b01_n13_fullbyte': 'PLAN_N13_V34_B01_FULLU8', 's4p3_network_b01_n17_fullbyte': 'PLAN_N17_V34_B01_FULLU8'}
TERMINAL_SCHEMA="ch8-s4p-3-campaign-v1"
SEAL_SCHEMA="ch8-s4p-3-portable-seal-v1"
def enabled(request):return request.get('profile')==PROFILE
def groups(request):return [{'id':'s3-'+rid,'variant':'production','unwind':u,'row_ids':[rid]} for rid,u in zip(ORDER,BOUNDS)]
def classification(rid):
    assert rid in ORDER
    return {'category':('FIXED_NEGATIVE_CONTROL' if rid in ORDER[:3] else 'CELL_CHECKER_ONLY_NEGATIVE' if rid==ORDER[3] else 'S4P3_FULLBYTE_NETWORK_BOUNDARY_ACTUAL_BODY_CANDIDATE'),
            'qualification_eligible':rid in CANDIDATES,'eligible_as_init_leaf_or_provider_summary':False,
            'actual_initialization_mask_and_dstinit':'NO_INDEPENDENT_INIT_THEOREM','proof_credit':'NONE'}
def valid_scope(rid,value):
    expected=classification(rid)
    return isinstance(value,dict) and value==expected and all(type(value[k]) is type(v) for k,v in expected.items())
def validate(request):
    import s4p3_policy
    assert request['profile']==PROFILE and request['schema']==SCHEMA
    assert request['s3']=={'selected':list(ORDER),'deferred':list(DEFERRED),'caps':CAPS,'plan_commit':PLAN,'intake_commit':INTAKE,
        'boundary_commit':BOUNDARY,'u_policy':'ZERO_U_FAIL_CLOSED; site-specific proposal PENDING_REVIEW_NOT_ENABLED',
        'unselected_full_obligations':'EXPLICIT_NOT_SELECTED_NO_PROMOTION'}
    assert type(request['budgets']['projected_group_count']) is int and request['budgets']['projected_group_count']==8
    assert 8*CAPS['slot_seconds']+CAPS['controller_seconds']+CAPS['cleanup_seconds']==6180<=CAPS['campaign_seconds']
    s4p3_policy.validate_request(request)
    return True
def view(request):validate(request);return copy.deepcopy(request)
