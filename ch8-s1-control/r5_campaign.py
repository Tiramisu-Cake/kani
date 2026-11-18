#!/usr/bin/env python3
"""One bounded serial r5 campaign; legacy decoder and full obligations retained."""
import argparse,hashlib,json,os,signal,subprocess,sys,time
from pathlib import Path
import runner as r
import r5_profile as p
import r5_runtime as rt

class GlobalFailure(RuntimeError):pass
class CampaignSignal(BaseException):pass

def atomic(path,value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    data=json.dumps(value,indent=2,sort_keys=True).encode()+b'\n'
    temp=path.with_name(path.name+'.tmp')
    with temp.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
    os.replace(temp,path)
    fd=os.open(path.parent,os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)

def read(path):
    if path.is_symlink() or path.stat().st_size>r.ARTIFACT_CAP_BYTES:raise GlobalFailure('receipt storage boundary')
    value=json.loads(path.read_text())
    if not isinstance(value,dict):raise GlobalFailure('receipt wrong type')
    return value

def digest(data):return hashlib.sha256(data).hexdigest()
def group(request,rid):return next(g for g in r.group_rows(request['rows'],p.groups(request)) if g['rows'][0]['id']==rid)
def identity(request):return {k:request[k] for k in ('std_sha','std_tree','tool_sha','tool_tree')}

def sealed(out,reader=None,ids=None):
    def raw(path):
        if reader:return reader(path)
        if path.is_symlink():raise GlobalFailure('sealed symlink')
        return path.read_bytes()
    records={}
    if ids is None:ids=[rid for rid in p.ORDER if (out/'completed'/(rid+'.json')).exists()]
    if len(ids)!=len(set(ids)) or not set(ids)<=set(p.ORDER):raise GlobalFailure('completed inventory mismatch')
    for rid in ids:
        seal=json.loads(raw(out/'completed'/(rid+'.json')))
        if (not isinstance(seal,dict) or seal.get('schema')!='ch8-s2-r5-portable-seal-v1'
                or seal.get('id')!=rid or not isinstance(seal.get('files'),dict)):
            raise GlobalFailure('invalid portable completion seal')
        required={str(Path(rid)/name) for name in ('receipt.json','worker-receipt.json')}
        required.update({f'groups/r5-{rid}/receipt.json',f'workers/{rid}-supervision.json'})
        if not required<=set(seal['files']):raise GlobalFailure('required structured seal member missing')
        for name,h in seal['files'].items():
            rel=Path(name)
            allowed=(len(rel.parts)>=3 and rel.parts[:2]==('groups','r5-'+rid)) or name in required
            if (not isinstance(name,str) or rel.is_absolute() or '..' in rel.parts or '\\' in name
                    or rel.as_posix()!=name or rel.suffix!='.json' or not allowed):
                raise GlobalFailure('portable sealed path/schema boundary')
            if not isinstance(h,str) or len(h)!=64 or any(ch not in '0123456789abcdef' for ch in h):
                raise GlobalFailure('portable seal digest type/format')
            if digest(raw(out/rel))!=h:raise GlobalFailure('completed evidence storage drift')
        if str(Path(rid)/'receipt.json') not in seal['files']:raise GlobalFailure('row not sealed')
        records[rid]=seal
    return records

def usage(out):
    totals={'stdout_bytes':0,'stderr_bytes':0,'export_bytes':0,'artifact_bytes':0}
    for f in out.rglob('*'):
        if f.is_symlink():raise GlobalFailure('artifact symlink')
        if not f.is_file():continue
        try:size=f.stat().st_size
        except FileNotFoundError:continue # atomic temporary renamed during census
        totals['artifact_bytes']+=size
        if f.name=='export.json':totals['export_bytes']+=size
    for path in (out/'groups').glob('*/receipt.json'):
        doc=read(path);execution=doc.get('execution',{})
        for key in ('stdout_bytes','stderr_bytes'):
            value=execution.get(key,0)
            if type(value) is not int or value<0:raise GlobalFailure('aggregate output statistics unknown')
            totals[key]+=value
    for f in (out/'workers').glob('*.stderr'):totals['stderr_bytes']+=f.stat().st_size
    return totals

def check_usage(out):
    used=usage(out)
    if any(used[key]>=p.CAPS[key] for key in used):raise GlobalFailure('aggregate_output_export_artifact_cap')
    return {key:p.CAPS[key]-used[key] for key in ('stdout_bytes','stderr_bytes','export_bytes')}

def finalize(out,request,stop_reason=None,elapsed=None):
    """Only missing/unsealed rows may change. Completed prefix bytes never rewritten."""
    p.validate(request);out.mkdir(parents=True,exist_ok=True);done=sealed(out)
    start_doc=read(out/'campaign-start.json') if (out/'campaign-start.json').exists() else {}
    rows=[]
    for row in request['rows']:
        rid=row['id']
        if rid in done:result=read(out/rid/'receipt.json')
        else:
            supervision_path=out/'workers'/(rid+'-supervision.json')
            supervision=read(supervision_path) if supervision_path.exists() else None
            prior_path=out/rid/'receipt.json'
            prior=read(prior_path) if prior_path.exists() else {}
            interrupted=(supervision is not None and supervision.get('worker_pid') is not None) or prior.get('status') in ('IN_PROGRESS','OBSERVED','UNKNOWN','INTERRUPTED')
            intent_only=(out/'workers'/(rid+'-launch.json')).exists() and not interrupted
            status='DEFERRED_NOT_SELECTED' if rid in p.DEFERRED else 'INTERRUPTED' if interrupted else 'UNSEALED_INVOCATION_UNKNOWN' if intent_only else 'NOT_RUN'
            result={**r._row_base(row,status),'group':'r5-'+rid,'proof_credit':'NONE',
                    'reason':'DEFERRED_TO_S3_PROVED_LEAVES' if rid in p.DEFERRED else stop_reason or 'NO_DURABLE_COMPLETION',
                    'cost_status':'UNKNOWN_NOT_ZERO','assurance':row['assurance'],
                    'invocation_supervision':supervision,
                    'native_root_start':'UNKNOWN_UNLESS_NATIVE_EVENT_RETAINED' if interrupted or intent_only else 'NOT_SELECTED_OR_NO_WORKER_LAUNCH'}
            # Save unfinished worker evidence before replacing canonical row.
            old=out/rid/'receipt.json';saved=out/rid/'unfinished-worker-receipt.json'
            if old.exists() and not saved.exists():
                previous=read(old)
                if previous.get('status') not in ('NOT_RUN','DEFERRED_NOT_SELECTED'):atomic(saved,previous)
            atomic(old,result)
        rows.append(result)
    for rid in p.ORDER:
        gp=out/'groups'/('r5-'+rid)/'receipt.json'
        if not gp.exists():atomic(gp,{'state':'NOT_RUN','group':'r5-'+rid,'reason':stop_reason or 'NO_INVOCATION',
                                   'selectors':[group(request,rid)['rows'][0]['selector']],'proof_credit':'NONE'})
    failed=any(x.get('outcome')!='RECORDED' or x.get('r5_expected_match') is not True for x in rows if x['id'] in p.ORDER)
    doc={'schema':'ch8-s2-r5-campaign-v1','state':'STOPPED' if stop_reason else 'SELECTED_PARTIAL' if failed else 'SELECTED_RECORDED_FULL_INVENTORY_INCOMPLETE',
         **start_doc.get('identity',identity(request)),'request_sha256':(start_doc['request_sha256'] if 'request_sha256' in start_doc else r.sha256(r.REQUEST_PATH)),'selected_groups':['r5-'+rid for rid in p.ORDER],
         'rows':rows,'stop_reason':stop_reason,'phase_elapsed_seconds':elapsed,'proof_credit':'NONE',
         'r5_campaign':{'profile':p.PROFILE,'launch_order':list(p.ORDER),'deferred':list(p.DEFERRED),
                        'completed':list(done),'full_inventory_complete':False,'selected_roots':9,'covers_required':16,'exact_negatives_required':5,
                        'global_caps':p.CAPS,'scope':'STATIC/SOURCE_REPORTED_OBSERVATIONS; independent proof credit NONE'}}
    atomic(out/'receipt.json',doc);return doc

def fallback(out,request):
    terminal=read(out/'receipt.json') if (out/'receipt.json').exists() else {}
    done=sealed(out)
    if (out/'campaign-start.json').exists():request=read(out/'campaign-start.json')['request_data']
    if (terminal.get('schema')!='ch8-s2-r5-campaign-v1'
        or set(terminal.get('r5_campaign',{}).get('completed',[]))!=set(done)):
        finalize(out,request,terminal.get('stop_reason') or 'ALWAYS_FALLBACK_PRESERVED_PREFIX',terminal.get('phase_elapsed_seconds'))
    atomic(out/'job-status.json',{'job_status':os.environ.get('JOB_STATUS','UNKNOWN'),
        'request_sha256':(terminal['request_sha256'] if 'request_sha256' in terminal else r.sha256(r.REQUEST_PATH)),
        'acceptance':'PENDING_INDEPENDENT_REVIEW','credit':'NONE'})
    return {'fallback':'R5_PREFIX_PRESERVED','proof_credit':'NONE'}

def record_supervision(out,rid,supervision):
    path=out/'workers'/(rid+'-supervision.json')
    if path.exists():
        if read(path)!=supervision:raise GlobalFailure('supervision storage drift')
    else:atomic(path,supervision)


def validate_owned_groups(doc,supervision):
    observed=supervision.get('containment',{}).get('observed',[])
    worker=supervision.get('worker_pid')
    driver=doc.get('execution',{}).get('process_identity',{})
    initial=supervision.get('worker_initial_identity')
    if (not isinstance(initial,dict) or initial.get('pid')!=worker or initial.get('pgid')!=worker
        or type(initial.get('start_ticks')) is not int or initial['start_ticks']<=0
        or not any(rec.get('pid')==worker and rec.get('pgid')==worker and rec.get('start_ticks')==initial['start_ticks'] for rec in observed)):
        raise GlobalFailure('missing_owned_worker_pid_pgid_starttime')
    if doc.get('state')=='COMPLETE' and (type(driver.get('start_ticks')) is not int
        or not any(rec.get('pid')==driver.get('pid') and rec.get('pgid')==driver.get('pgid') and rec.get('start_ticks')==driver['start_ticks'] for rec in observed)):
        raise GlobalFailure('missing_observed_stock_driver_identity')
    allowed={worker}
    if driver.get('pid') is not None:
        if driver.get('pgid')!=driver['pid']:raise GlobalFailure('stock child was not its declared session leader')
        allowed.add(driver['pgid'])
    # Exited/zombie detached children count too: worker's PG-only AFTER snapshot
    # cannot certify quiescence of an escaped group, even if outer cleanup reaps it.
    if any(rec.get('pgid') not in allowed for rec in observed):
        raise GlobalFailure('unexpected_process_group_containment_gap')


def root_outcome(out,request,rid,supervision):
    record_supervision(out,rid,supervision)
    gp=out/'groups'/('r5-'+rid)/'receipt.json'
    doc=read(gp) if gp.exists() else {}
    expected={**identity(request),'changed_file_sha256':request['changed_file_sha256']}
    if (doc.get('request_sha256')!=r.sha256(r.REQUEST_PATH) or doc.get('source_before')!=expected or doc.get('source_after')!=expected
            or doc.get('binary_identity')!='MATCH' or doc.get('snapshot_errors')):
        raise GlobalFailure('source_tool_request_binary_snapshot_drift_or_unavailable')
    events=doc.get('native_start_events',[]);selector=group(request,rid)['rows'][0]['selector']
    if any(x.get('selector')!=selector for x in events) or len(events)>1:
        raise GlobalFailure('native_selector_start_mismatch')
    if not supervision.get('containment',{}).get('verified'):raise GlobalFailure('unreaped_or_orphan_child')
    validate_owned_groups(doc,supervision)
    if supervision.get('orphan_survivors_at_worker_exit') or supervision.get('supervisor_error') or supervision.get('cutoff') in ('outer_sampled_rss','aggregate_artifact_cap'):
        raise GlobalFailure('global_supervisor_failure')
    expected_row=group(request,rid)['rows'][0]
    result=read(out/rid/'receipt.json') if (out/rid/'receipt.json').exists() else r._row_base(expected_row)
    if any(result.get(k)!=expected_row[k] for k in ('id','selector','mode','variant')) or result.get('group')!='r5-'+rid:
        raise GlobalFailure('worker row/source-stage-target binding mismatch')
    if result.get('outcome')=='RECORDED' and doc.get('state')!='COMPLETE':
        result.update(outcome='UNKNOWN',reason='incomplete_group_not_accepted')
    atomic(out/rid/'worker-receipt.json',result)
    if supervision.get('cutoff') or supervision.get('worker_exit')!=0:
        result.update(status='UNKNOWN',outcome='UNKNOWN',reason=supervision.get('cutoff') or 'worker_exit',r5_expected_match=False)
    elif result.get('outcome')=='RECORDED':
        if not doc.get('native_start_verified'):raise GlobalFailure('completed root lacks exact native start')
        rich=read(out/'groups'/('r5-'+rid)/'properties.json')
        props=next((x for x in rich.get('harnesses',[]) if x.get('name')==selector),{})
        result['r5_expected_match']=r.s2_policy.expected_observation(group(request,rid)['rows'][0],result.get('export',{}),props)
    else:result['r5_expected_match']=False
    result['assurance']=expected_row['assurance']
    result['invocation_original_exit']=doc.get('execution',{}).get('original_exit_code')
    result['invocation_signal']=doc.get('execution',{}).get('signal')
    result['r5_timeout_scopes']={'compile_subcap_inside_child_seconds':180,'whole_child_seconds':600,
        'inner_CBMC_ceiling_seconds':600,'complete_slot_seconds':720,'supervised_worker_wall_seconds':710,'durable_publication_reserve_seconds':10,
        'termination_reason':doc.get('execution',{}).get('termination_reason'),
        'external_child_cutoff_is_backend_TIMEOUT600':False}
    result.update(r5_supervision=supervision,resource_scope='LOCAL6GiB_SAMPLED_PGID_VmRSS; not strict tree/kernel/cgroup',proof_credit='NONE')
    atomic(out/rid/'receipt.json',result)
    directory=out/'groups'/('r5-'+rid)
    files={};local_only={}
    for f in sorted(directory.rglob('*')):
        if f.is_symlink():raise GlobalFailure('completion evidence symlink')
        if f.is_file():
            with f.open('rb') as stream:os.fsync(stream.fileno())
            name=str(f.relative_to(out));h=r.sha256(f)
            if f.suffix=='.json':files[name]=h
            else:local_only[name]={'sha256':h,'bytes':f.stat().st_size,
                'scope':'LOCAL_CAPTURE_BYTES_ONLY_NOT_UPLOADED_NOT_REQUIRED_FOR_PORTABLE_REPLAY'}
    for d in sorted([directory]+[d for d in directory.rglob('*') if d.is_dir()],key=lambda x:len(x.parts),reverse=True):
        fd=os.open(d,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    if supervision.get('monotonic_start') is not None and time.monotonic()>=supervision['monotonic_start']+p.CAPS['slot_seconds']:
        supervision['cutoff']=supervision.get('cutoff') or 'durable_slot_cutoff'
        supervision['limit_initiated']=True
        result.update(outcome='UNKNOWN',r5_expected_match=False,reason='durable_slot_cutoff',r5_supervision=supervision)
        atomic(out/rid/'receipt.json',result)
    for name in ('receipt.json','worker-receipt.json'):files[str(Path(rid)/name)]=r.sha256(out/rid/name)
    supervision_path=out/'workers'/(rid+'-supervision.json')
    files[str(supervision_path.relative_to(out))]=r.sha256(supervision_path)
    seal={'schema':'ch8-s2-r5-portable-seal-v1','id':rid,'files':files,'local_only_file_digests':local_only,
          'supervision':supervision,'expected_match':result['r5_expected_match'],
          'sealed_monotonic':time.monotonic(),'proof_credit':'NONE'}
    atomic(out/'completed'/(rid+'.json'),seal)
    return result

def invoke(std,tool,out,request,rid,limits,slot):
    lp=out/'workers'/(rid+'-limits.json');atomic(lp,limits)
    argv=[sys.executable,str(Path(__file__).resolve()),'worker','--std',str(std.resolve()),'--tool',str(tool.resolve()),
          '--out',str(out.resolve()),'--root',rid,'--limits',str(lp.resolve())]
    return rt.supervise(argv,Path.cwd(),dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),slot,p.CAPS['outer_rss_kib'],
                        out/'workers'/(rid+'.stderr'),lambda:usage(out)['artifact_bytes']>=p.CAPS['artifact_bytes'])

def run_campaign(std,tool,out,request,invoker=None,clock=time.monotonic):
    p.validate(request);out=out.resolve();out.mkdir(parents=True,exist_ok=True)
    if (out/'campaign-start.json').exists() or (out/'completed').exists():raise GlobalFailure('campaign retry/resume forbidden')
    start=clock();request_hash=r.sha256(r.REQUEST_PATH);stop=None
    atomic(out/'campaign-start.json',{'request_sha256':request_hash,'start_monotonic':start,'caps':p.CAPS,'selected':list(p.ORDER),
                                    'pid':os.getpid(),'profile':p.PROFILE,'identity':identity(request),'request_data':request,'proof_credit':'NONE'})
    try:
        for index,rid in enumerate(p.ORDER):
            if r.sha256(r.REQUEST_PATH)!=request_hash:raise GlobalFailure('request drift')
            sealed(out)
            if p.CAPS['campaign_seconds']-(clock()-start) < (len(p.ORDER)-index)*p.CAPS['slot_seconds']+p.CAPS['cleanup_seconds']:
                raise GlobalFailure('global_budget_reserved_slots_no_reset')
            limits=check_usage(out)
            atomic(out/'workers'/(rid+'-launch.json'),{'id':rid,'rank':index+1,'selector':group(request,rid)['rows'][0]['selector'],
                'monotonic':clock(),'request_sha256':request_hash,'limits':limits,'slot_seconds':p.CAPS['slot_seconds']})
            supervision=(invoker or invoke)(std,tool,out,request,rid,limits,p.CAPS['slot_seconds']-10)
            record_supervision(out,rid,supervision)
            if clock()-start>=p.CAPS['campaign_seconds']-p.CAPS['cleanup_seconds']:raise GlobalFailure('hard_global_deadline')
            if r.sha256(r.REQUEST_PATH)!=request_hash:raise GlobalFailure('request drift')
            root_outcome(out,request,rid,supervision)
            finalize(out,request,elapsed=clock()-start)
            check_usage(out)
    except BaseException as exc:
        stop=f'{type(exc).__name__}: {exc}'
    terminal=finalize(out,request,stop,clock()-start)
    return 0 if terminal['state']=='SELECTED_RECORDED_FULL_INVENTORY_INCOMPLETE' else 1

def worker(std,tool,out,request,rid,limits):
    p.validate(request)
    assert rid in p.ORDER and set(limits)=={'stdout_bytes','stderr_bytes','export_bytes'}
    assert all(type(v) is int and 0<v<=p.CAPS[k] for k,v in limits.items())
    # No tool build/reuse/alternative solver. Legacy protected path, exactly one selector.
    r._run_group(std,tool,out,request,group(request,rid),time.monotonic()+p.CAPS['slot_seconds']-10,isolated_limits=limits)
    return 0

def collect(roots,request):
    import collect as c
    result=c.legacy_collect(roots,p.view(request))
    for root in roots:
        terminal=c.read(root/'receipt.json');meta=terminal.get('r5_campaign',{})
        if meta.get('profile')!=p.PROFILE or meta.get('launch_order')!=list(p.ORDER) or meta.get('deferred')!=list(p.DEFERRED):
            raise GlobalFailure('r5 terminal selection mismatch')
        done=sealed(root,c.read_bytes,meta.get('completed',[]))
        invocation_ids=set()
        for rid,seal in done.items():
            sup=seal.get('supervision',{})
            if not sup.get('containment',{}).get('verified'):raise GlobalFailure('unverified root containment')
            row=c.read(root/rid/'receipt.json');gp=c.read(root/'groups'/('r5-'+rid)/'receipt.json')
            validate_owned_groups(gp,sup)
            if row.get('r5_supervision')!=sup:raise GlobalFailure('row/seal supervision mismatch')
            if row.get('outcome')=='RECORDED':
                selector=group(request,rid)['rows'][0]['selector'];argv=gp.get('argv',[])
                try:
                    std=Path(argv[argv.index('--output-format=regular')+1]).parent
                    tool=Path(argv[0]).parent.parent;export=Path(argv[argv.index('--export-json')+1])
                    assert argv==r.build_argv(std,tool,[selector],34,export)
                except (ValueError,IndexError,AssertionError):raise GlobalFailure('singleton argv binding mismatch')
                iid=gp.get('invocation_id');target=Path(gp.get('cargo_target_dir','/'))
                if not iid or iid in invocation_ids or target!=std/'target/ch8-s1-cargo'/iid:
                    raise GlobalFailure('fresh invocation namespace mismatch')
                invocation_ids.add(iid)
                if (sup.get('cutoff') or sup.get('supervisor_error') or sup.get('worker_exit')!=0 or sup.get('orphan_survivors_at_worker_exit')
                    or gp.get('compile_limit_seconds')!=180 or not 0<gp.get('timeout_seconds',0)<=600
                    or not 0<gp.get('memory',{}).get('group_cap_kib',0)<=p.CAPS['local_rss_kib']
                    or gp.get('effective_cfg')!=request['flags']['RUSTFLAGS']
                    or [x.get('selector') for x in gp.get('native_start_events',[])]!=[selector]
                    or not gp.get('native_start_verified')):
                    raise GlobalFailure('r5 recorded result has cutoff/resource/start/config mismatch')
                compile_receipt=c.read(root/'groups'/('r5-'+rid)/'compile/receipt.json')
                if (compile_receipt.get('state')!='COMPLETE' or compile_receipt.get('limit_seconds')!=180
                    or compile_receipt.get('selectors')!=[selector]
                    or compile_receipt.get('request_sha256')!=terminal['request_sha256']):
                    raise GlobalFailure('r5 fresh compile binding mismatch')
    result.update(state='SELECTED_OBSERVATIONS_PENDING_REVIEW_FULL_INVENTORY_INCOMPLETE',
                  selected_missing_groups=[x for x in result['missing_groups'] if x not in ['r5-'+rid for rid in p.DEFERRED]],
                  deferred=list(p.DEFERRED),full_inventory_complete=False)
    for row in result['rows']:
        if row['id'] in p.DEFERRED:row.update(status='DEFERRED_NOT_SELECTED',outcome='UNKNOWN',reason='DEFERRED_TO_S3_PROVED_LEAVES')
    return result

def main():
    a=argparse.ArgumentParser();a.add_argument('command',choices=['run','worker','finish']);a.add_argument('--std',type=Path);a.add_argument('--tool',type=Path);a.add_argument('--out',type=Path,required=True);a.add_argument('--root');a.add_argument('--limits',type=Path)
    args=a.parse_args()
    if args.command=='finish':
        import pack_evidence
        failed=False
        try:fallback(args.out,r.load_request())
        except Exception as exc:
            failed=True;print('r5 fallback incomplete: '+type(exc).__name__+': '+str(exc),file=sys.stderr)
        finally:pack_evidence.pack(args.out)
        return 1 if failed else 0
    if args.std is None or args.tool is None:a.error('run/worker requires --std and --tool')
    request=r.load_request();p.validate(request)
    if os.environ.get('S2_PROFILE')!=p.PROFILE:raise GlobalFailure('workflow profile environment mismatch')
    if args.command=='worker':return worker(args.std,args.tool,args.out,request,args.root,read(args.limits))
    def interrupted(signum,frame):raise CampaignSignal(str(signum))
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,interrupted)
    alarm_start=time.monotonic()
    def campaign_alarm(signum,frame):
        remaining=p.CAPS['campaign_seconds']-(time.monotonic()-alarm_start)
        if remaining>0:
            signal.setitimer(signal.ITIMER_REAL,remaining)
            raise CampaignSignal('campaign cleanup reserve reached')
        raise CampaignSignal('hard global6900 deadline')
    signal.signal(signal.SIGALRM,campaign_alarm)
    signal.setitimer(signal.ITIMER_REAL,p.CAPS['campaign_seconds']-p.CAPS['cleanup_seconds'])
    try:return run_campaign(args.std,args.tool,args.out,request)
    finally:signal.setitimer(signal.ITIMER_REAL,0)
if __name__=='__main__':raise SystemExit(main())
