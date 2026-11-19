"""S3 request-derived provenance and observed protected-evidence rejection.

Pure readers are shared by local finalization and structured portable replay.
Controller recovery can fill an interrupted capture's absence, never erase an
observed error, mismatch, unreadability or contradictory identity.
"""
import re
IDENTITIES=('std_sha','std_tree','tool_sha','tool_tree')

class EvidenceError(ValueError):pass

def need(ok,reason):
    if not ok:raise EvidenceError(reason)

def identity(request):
    values={k:request[k] for k in IDENTITIES}
    need(all(isinstance(v,str) and re.fullmatch('[0-9a-f]{40}',v) for v in values.values()),'invalid requested source/tool identity')
    return values

def protected(doc,request,baseline,supervision,request_hash):
    import runner as r
    need(isinstance(doc,dict) and doc,'missing worker protected receipt')
    # These fields only exist when capture raised. Even null/empty/malformed
    # error records cannot be interpreted as a successful measurement.
    for key in ('source_before_error','source_after_error','tool_fingerprints_before_error','tool_fingerprints_after_error'):
        need(key not in doc,'recorded worker protected error: '+key)
    errors=doc.get('snapshot_errors')
    need(isinstance(errors,list) and not errors,'recorded/malformed worker snapshot_errors')
    need(doc.get('request_sha256')==request_hash,'worker request snapshot mismatch/unavailable')
    expected={**identity(request),'changed_file_sha256':request['changed_file_sha256']}
    need(doc.get('source_before')==expected,'worker source_before mismatch/unavailable')
    if 'source_after' in doc:need(doc['source_after']==expected,'worker source_after mismatch/malformed')
    need(doc.get('state') in ('COMPLETE','FAILED','IN_PROGRESS','INTERRUPTED'),'unknown/malformed worker state')
    complete=doc['state']=='COMPLETE'
    exit_code=supervision.get('worker_exit')
    interrupted=(type(exit_code) is int and exit_code<0) or supervision.get('cutoff') in ('slot_wall','slot_wall_during_cleanup')
    recovery=(not complete and interrupted and isinstance(supervision.get('containment'),dict)
              and supervision['containment'].get('verified') is True)
    before=doc.get('tool_fingerprints_before')
    need(r.fingerprints_match(before,before),'worker binary before incomplete/malformed')
    for stage in ('before','after'):
        key='tool_fingerprints_'+stage
        if key not in doc:
            need(stage=='after' and recovery,'worker binary capture absent without verified interruption')
            continue
        snap=doc[key]
        need(r.fingerprints_match(snap,snap),'recorded worker binary capture unreadable/malformed: '+stage)
        need(r.fingerprints_match(baseline['binaries'],snap),'recorded worker binary drift: '+stage)
        if 'state' in snap:need(snap['state']=='COMPLETE','recorded incomplete worker binary capture')
        if 'snapshot_completed' in snap:need(snap['snapshot_completed'] is True,'recorded unfinished worker binary capture')
        need(not snap.get('missing_binaries') and not snap.get('error'),'recorded worker binary capture error')
    if 'binary_identity' in doc:
        need(doc['binary_identity']=='MATCH','recorded unknown/mismatched worker binary identity')
        need('tool_fingerprints_after' in doc,'contradictory MATCH without inner binary AFTER')
    else:need(recovery,'missing worker binary identity without verified interruption')
    missing=[k for k in ('source_after','tool_fingerprints_after') if k not in doc]
    need(not missing or recovery,'worker post-state absent without verified interruption')
    return {'inner_after_absent':missing,'controller_recovery_used':bool(missing),'observed_errors_ignored':False}

def provenance(doc,compile_receipt,request,rid,request_hash):
    need(isinstance(doc,dict),'worker provenance receipt wrong type')
    wanted=identity(request)
    for key,value in wanted.items():need(doc.get(key)==value,'worker identity missing/malformed/stale: '+key)
    under=doc.get('source_under_test')
    need(isinstance(under,dict),'source_under_test missing/null/wrong type')
    for key,value in wanted.items():need(under.get(key)==value,'source_under_test identity missing/malformed/stale: '+key)
    need(under.get('base_std_sha')==request['std_sha'],'source_under_test current pre-overlay base_std_sha mismatch')
    need(under.get('historical_patch_base_std_sha')==request['base_std_sha'],'historical patch ancestry mismatch')
    need(under.get('variant')=='production' and under.get('patch_sha256') is None
         and under.get('file_sha256')==request['changed_file_sha256'],'source_under_test variant/file/patch mismatch')
    need(isinstance(compile_receipt,dict),'compile identity receipt missing/null/wrong type')
    for key,value in wanted.items():need(compile_receipt.get(key)==value,'compile identity missing/malformed/stale: '+key)
    row=next(x for x in request['rows'] if x['id']==rid)
    need(compile_receipt.get('request_sha256')==request_hash and compile_receipt.get('selectors')==[row['selector']]
         and compile_receipt.get('limit_seconds')==180 and compile_receipt.get('state') in ('COMPLETE','FAILED','IN_PROGRESS'),
         'compile request/selector/limit/state mismatch')
    if doc.get('state')=='COMPLETE':need(compile_receipt['state']=='COMPLETE','completed group without completed compilation')
    return True
