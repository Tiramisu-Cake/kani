# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Eight full-byte length blocks; every summary/provider edge remains disabled."""
import copy
from r5_profile import CAPS
PROFILE='ch8-s4p-2-network-fullbyte-singletons-v1'
SCHEMA='ch8-s4p-2-v1'
ORDER=('checker_order_corrupt', 'checker_count_corrupt', 'sort13_weak', 's4p_cell_count_corrupt', 's4p2_network_b01_n02_fullbyte', 's4p2_network_b01_n03_fullbyte', 's4p2_network_b01_n04_fullbyte', 's4p2_network_b01_n00_01_fullbyte')
CANDIDATES=ORDER[4:]
DIAGNOSTICS=()
DEFERRED=('fallback_N05_16','network_N05_32','general_N00_32','Cell_semantic_provider',
          'generic_trait_dispatch','mutating_comparator','initialization_and_ownership','compiler_MIR_B1_B2')
BOUNDS=(34,34,34,36,36,36,36,36)
CFG='--cfg=kani_smallsort_sorting --cfg=kani_smallsort_controls --cfg=kani_smallsort_s2_assumed --cfg=kani_smallsort_s3_leaf --cfg=kani_smallsort_s4_partition'
PLAN='7253272c427eb9b564c79350ef73b231fa124298'
INTAKE='842984040e87b8b8594653634b72df7d800ca198'
BOUNDARY='9bb6e2b7a18e338f532ec817f8acfd7515fc2fc9'
IMPLEMENTATION_TASK='bf3aba53618b759a11d3ff277e88ba66530ec708'
INPUTS={'plan': '7253272c427eb9b564c79350ef73b231fa124298', 'plan_review': 'e287943e116a102d5950295b2629d80a62d1f922', 'intake': '842984040e87b8b8594653634b72df7d800ca198', 'intake_review': '3c7bd65cf0bb758cb82dc56ef71a8b8e23efd5c0', 'exact_admission': '9bb6e2b7a18e338f532ec817f8acfd7515fc2fc9', 'source_reference': '985062ebad90cee1e2846b1648cd6a8624d146f6', 'control_reference': '2db5d2c08804036d283cb36450647cd584ee9e10', 'role_contract_sha256': 'c90950843f17903b0271a0cf349e4afd5e9189924119aacb252904f0a0b7ef1d', 'implementation_gates_sha256': 'b9d81c6dcff93f42828e604e147073317c882390af9fd4f18f2f66da747455af'}
ACCOUNTING={'mode':'TRACKING_ONLY','reservation':False,'changed':False,
            'future_accounting':'USERCOORDINATOR_ONLY_AFTER_EXACT_REVIEW_AND_GO',
            'latest_admission_only':BOUNDARY}
TARGETS={rid:None for rid in ORDER}
CALLEES={rid:"small_sort_network" for rid in CANDIDATES}
DOMAINS={'s4p2_network_b01_n02_fullbyte': {'length_interval': [2, 2], 'allocation': 34, 'base': 1, 'logical_values': 'ALL_34_INDEPENDENT_U8_0_255', 'initialized': True, 'type': 'u8', 'comparator': 'KeyLess<u8>', 'summary_edges': []}, 's4p2_network_b01_n03_fullbyte': {'length_interval': [3, 3], 'allocation': 34, 'base': 1, 'logical_values': 'ALL_34_INDEPENDENT_U8_0_255', 'initialized': True, 'type': 'u8', 'comparator': 'KeyLess<u8>', 'summary_edges': []}, 's4p2_network_b01_n04_fullbyte': {'length_interval': [4, 4], 'allocation': 34, 'base': 1, 'logical_values': 'ALL_34_INDEPENDENT_U8_0_255', 'initialized': True, 'type': 'u8', 'comparator': 'KeyLess<u8>', 'summary_edges': []}, 's4p2_network_b01_n00_01_fullbyte': {'length_interval': [0, 1], 'allocation': 34, 'base': 1, 'logical_values': 'ALL_34_INDEPENDENT_U8_0_255', 'initialized': True, 'type': 'u8', 'comparator': 'KeyLess<u8>', 'summary_edges': []}}
DESIGNS={'s4p2_network_b01_n02_fullbyte': 'PLAN_N02_V34_B01_FULLU8', 's4p2_network_b01_n03_fullbyte': 'PLAN_N03_V34_B01_FULLU8', 's4p2_network_b01_n04_fullbyte': 'PLAN_N04_V34_B01_FULLU8', 's4p2_network_b01_n00_01_fullbyte': 'PLAN_N01_V34_B01_FULLU8'}
TERMINAL_SCHEMA="ch8-s4p-2-campaign-v1"
SEAL_SCHEMA="ch8-s4p-2-portable-seal-v1"
def enabled(request):return request.get('profile')==PROFILE
def groups(request):return [{'id':'s3-'+rid,'variant':'production','unwind':u,'row_ids':[rid]} for rid,u in zip(ORDER,BOUNDS)]
def classification(rid):
    assert rid in ORDER
    return {'category':('FIXED_NEGATIVE_CONTROL' if rid in ORDER[:3] else 'CELL_CHECKER_ONLY_NEGATIVE' if rid==ORDER[3] else 'S4P2_FULLBYTE_NETWORK_EXACT_PARTITION_ACTUAL_BODY_CANDIDATE'),
            'qualification_eligible':rid in CANDIDATES,'eligible_as_init_leaf_or_provider_summary':False,
            'actual_initialization_mask_and_dstinit':'NO_INDEPENDENT_INIT_THEOREM','proof_credit':'NONE'}
def valid_scope(rid,value):
    expected=classification(rid)
    return isinstance(value,dict) and value==expected and all(type(value[k]) is type(v) for k,v in expected.items())
def validate(request):
    import s4p2_policy
    assert request['profile']==PROFILE and request['schema']==SCHEMA
    assert request['s3']=={'selected':list(ORDER),'deferred':list(DEFERRED),'caps':CAPS,'plan_commit':PLAN,'intake_commit':INTAKE,
        'boundary_commit':BOUNDARY,'u_policy':'ZERO_U_FAIL_CLOSED; site-specific proposal PENDING_REVIEW_NOT_ENABLED',
        'unselected_full_obligations':'EXPLICIT_NOT_SELECTED_NO_PROMOTION'}
    assert type(request['budgets']['projected_group_count']) is int and request['budgets']['projected_group_count']==8
    assert 8*CAPS['slot_seconds']+CAPS['controller_seconds']+CAPS['cleanup_seconds']==6180<=CAPS['campaign_seconds']
    s4p2_policy.validate_request(request)
    return True
def view(request):validate(request);return copy.deepcopy(request)
