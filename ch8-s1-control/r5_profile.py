"""Exact control-only isolation profile; canonical legacy obligations stay intact."""
import copy
PROFILE='ch8-s2-r5-isolated-v1'
ORDER=('checker_order_corrupt','checker_count_corrupt','swap_pfc','sort13_weak',
       'merge32_real','sort13_assumed','merge_count_corrupt','merge_order_corrupt','summary_witness')
DEFERRED=('general32_assumed','general32_weak')
CAPS={'child_seconds':600,'compile_seconds':180,'slot_seconds':720,
      'controller_seconds':180,'cleanup_seconds':240,'campaign_seconds':6900,
      'outer_seconds':7500,'phase_seconds':8100,'step_seconds':7560,
      'local_rss_kib':6*1024*1024,'outer_rss_kib':12*1024*1024,'headroom_kib':2*1024*1024,
      'stdout_bytes':16*1024*1024,'stderr_bytes':1024*1024,'export_bytes':8*1024*1024,
      'artifact_bytes':256*1024*1024}
def enabled(request):return request.get('profile')==PROFILE

def validate(request):
    assert request.get('profile')==PROFILE
    assert request.get('r5')=={'selected':list(ORDER),'deferred':list(DEFERRED),'caps':CAPS,
        'plan_commit':'07d891b23ba65405920090de87ed7eec9730fec4',
        'intake_commit':'5ca0641af6c5b588ae2a4257ccc0fe52df6a827a',
        'full_inventory':{'roots':11,'covers':20,'negatives':6},
        'selected_inventory':{'roots':9,'covers':16,'negatives':5},
        'deferred_reason':'DEFERRED_TO_S3_PROVED_LEAVES; NOT_SELECTED; UNKNOWN'}
    assert 9*CAPS['slot_seconds']+CAPS['controller_seconds']+CAPS['cleanup_seconds']==CAPS['campaign_seconds']
    import s2_policy
    s2_policy.validate_legacy_request(request)
    return True

def groups(request):
    return [{'id':'r5-'+rid,'variant':'production','unwind':34,'row_ids':[rid]}
            for rid in (*ORDER,*DEFERRED)]

def view(request):
    validate(request);result=copy.deepcopy(request);result['execution_groups']=groups(request);return result

def validate_yaml(doc):
    job=doc['jobs']['s2_batch'];assert job['env']=={'S2_PROFILE':PROFILE}
    steps={s['name']:s for s in job['steps']}
    cmd='python3 control/ch8-s1-control/r5_campaign.py run --std export --tool tool --out "$RECEIPT_ROOT"\n'
    assert steps['Run S2 batch3probes with bounded observations']['run']==cmd
    assert steps['Materialize bounded fallback']['run']=='python3 control/ch8-s1-control/r5_campaign.py finish --out "$RECEIPT_ROOT"\n'
    assert steps['Validate control and synthetic wrapper']['timeout-minutes']==12
    actual=steps['Validate control and synthetic wrapper']['run'].splitlines()
    legacy='python3 -m unittest -v test_runner.py test_s107.FinalizationTests test_s2.py test_cfg_pfc.py test_rustc_diagnostics.py test_contract_stacks.py test_r1403_lexical.py'
    assert actual==['python3 check_package.py control --repo ..',legacy+' test_r5.py']
    normalized=copy.deepcopy(doc);normalized['jobs']['s2_batch'].pop('env')
    for step in normalized['jobs']['s2_batch']['steps']:
        if step['name']=='Run S2 batch3probes with bounded observations':
            step['run']='python3 control/ch8-s1-control/runner.py run --std export --tool tool --out "$RECEIPT_ROOT" --groups "$S1_GROUP"\n'
        if step['name']=='Materialize bounded fallback':
            step['run']='python3 control/ch8-s1-control/check_package.py fallback --out "$RECEIPT_ROOT" --groups "$S1_GROUP"\npython3 control/ch8-s1-control/pack_evidence.py --root "$RECEIPT_ROOT"\n'
        if step['name']=='Validate control and synthetic wrapper':
            # Normalize only the explicitly checked R5 cap for strict legacy validation.
            step['timeout-minutes']=10
            step['run']='python3 check_package.py control --repo ..\n'+legacy+'\n'
    return normalized
