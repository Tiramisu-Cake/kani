#!/usr/bin/env python3
"""Offline YAML/identity preflight and bounded NOT_RUN fallback; never dispatches."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import time

HERE = Path(__file__).resolve().parent
# Actual control: r1 sibling -> 9e14 -> 7c413 -> 9208 -> b25 -> 40b -> stock0aac (depth7).
# Actual source: r1 -> S2-active -> S2-witness -> S2-attrs -> accepted99e (depth5).
CHECKOUT_DEPTHS = {'control': 7, 'export': 5, 'tool': 2}


def load_yaml(text):
    import yaml

    # Preserve scalar types, but do not treat YAML 1.1 words such as `on` as bools.
    BaseLoader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    class WorkflowLoader(BaseLoader):
        yaml_implicit_resolvers = {
            key: [(tag, pattern) for tag, pattern in entries
                  if tag != 'tag:yaml.org,2002:bool']
            for key, entries in BaseLoader.yaml_implicit_resolvers.items()
        }

    WorkflowLoader.add_implicit_resolver('tag:yaml.org,2002:bool',
                                       re.compile(r'^(?:true|false)$', re.I), list('tTfF'))
    return yaml.load(text, Loader=WorkflowLoader)


def check_scalar_types(doc):
    """Typed GitHub workflow fields; action inputs below are a stricter local policy.

    Expressions in typed fields are deliberately rejected: this frozen package
    has literal caps/flags and must not defer their validation until dispatch.
    env, matrix values and arbitrary action `with` inputs are not schema booleans.
    """
    def fields(value, path, booleans=(), integers=(), minimum=1):
        assert isinstance(value, dict), path
        for key in booleans:
            if key in value:
                assert type(value[key]) is bool, f'{path}.{key}: expected native boolean'
        for key in integers:
            if key in value:
                assert type(value[key]) is int and value[key] >= minimum, (
                    f'{path}.{key}: expected native integer >= {minimum}')

    def concurrency(value, path):
        if isinstance(value, dict):
            fields(value, path, booleans=('cancel-in-progress',))

    concurrency(doc.get('concurrency'), 'concurrency')
    for name, job in doc['jobs'].items():
        path=f'jobs.{name}'
        fields(job, path, booleans=('continue-on-error',), integers=('timeout-minutes',))
        concurrency(job.get('concurrency'), path+'.concurrency')
        fields(job.get('strategy', {}), path+'.strategy',
               booleans=('fail-fast',), integers=('max-parallel',))
        for index, step in enumerate(job.get('steps', [])):
            spath=f'{path}.steps[{index}]'
            fields(step, spath, booleans=('continue-on-error',), integers=('timeout-minutes',))
            inputs=step.get('with', {})
            if step.get('uses', '').startswith('actions/checkout@'):
                fields(inputs, spath+'.with', booleans=('persist-credentials', 'submodules'),
                       integers=('fetch-depth',), minimum=0)
            if step.get('uses', '').startswith('actions/upload-artifact@'):
                fields(inputs, spath+'.with', integers=('retention-days',), minimum=0)


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def check_yaml(path):
    doc=load_yaml(path.read_text()); check_scalar_types(doc)
    if 'S3_PROFILE' in doc.get('jobs',{}).get('s3_leaf',{}).get('env',{}):
        import s3_package
        if doc["jobs"]["s3_leaf"]["env"]["S3_PROFILE"]=="ch8-s3-2-capped-fullbyte-v1":import s32_package as s3_package
        if doc["jobs"]["s3_leaf"]["env"]["S3_PROFILE"]=="ch8-s3s4-bridge1-fullbyte-v1":import s34_package as s3_package
        if doc["jobs"]["s3_leaf"]["env"]["S3_PROFILE"]=="ch8-s4p-3-network-fullbyte-concrete-calls-v1":import s4p3_package as s3_package
        if doc["jobs"]["s3_leaf"]["env"]["S3_PROFILE"]=="ch8-s4p-2r2-network-fullbyte-concrete-calls-v1":import s4p2r2_package as s3_package
        if doc["jobs"]["s3_leaf"]["env"]["S3_PROFILE"]=="ch8-s4p-2-network-fullbyte-singletons-v1":import s4p2_package as s3_package
        if doc["jobs"]["s3_leaf"]["env"]["S3_PROFILE"]=="ch8-s4p-1-fullbyte-length-blocks-v1":import s4p_package as s3_package
        return s3_package.check_yaml(doc)
    import r5_profile
    if 'S2_PROFILE' in doc.get('jobs',{}).get('s2_batch',{}).get('env',{}):
        doc=r5_profile.validate_yaml(doc)
        result=check_legacy_yaml(doc)
        return {**result,'step_timeout_sum_minutes':188}
    return check_legacy_yaml(doc)


def check_legacy_yaml(doc):
    assert doc['on']=={'push':{'branches':['uninit-ci/ch8-s2-batch3probes-*']}}
    assert doc['permissions']=={'contents':'read'}
    assert doc['concurrency']=={'group':'ch8-s2-fork','cancel-in-progress':False}
    assert set(doc['jobs'])=={'s2_batch'}
    job=doc['jobs']['s2_batch']
    assert job['runs-on']=='ubuntu-24.04' and job['timeout-minutes']==180
    assert 'strategy' not in job and 'needs' not in job
    assert job['if']=="${{ github.repository == 'Tiramisu-Cake/kani' && github.event_name == 'push' }}"
    steps=job['steps']
    assert sum(s['timeout-minutes'] for s in steps)==186
    checkouts={s['with']['path']:s['with'] for s in steps if s.get('uses','').startswith('actions/checkout@')}
    assert {k:v['fetch-depth'] for k,v in checkouts.items()}==CHECKOUT_DEPTHS
    assert all(v['persist-credentials'] is False for v in checkouts.values())
    assert checkouts['control']['ref']=='${{ github.sha }}'
    assert checkouts['export']['ref']=='${{ steps.pins.outputs.std }}'
    assert checkouts['tool']['ref']=='${{ steps.pins.outputs.tool }}'
    runs=[s for s in steps if s.get('name','').startswith('Run S2')]
    assert len(runs)==1 and runs[0]['timeout-minutes']==126
    assert runs[0]['env']['S1_GROUP']=='s2-batch3probes-u34'
    assert '--groups' in runs[0]['run'] and 'runner.py run --std export --tool tool' in runs[0]['run']
    assert steps[-1]['uses']=='actions/upload-artifact@v4' and steps[-1]['if']=='always()'
    assert steps[-1]['timeout-minutes']==6 and steps[-2]['timeout-minutes']==2
    assert steps[-1]['with']['if-no-files-found']=='error'
    assert steps[-1]['with']['path']=='${{ env.RECEIPT_ROOT }}/group-evidence.json.gz'
    byname={s['name']:s for s in steps}
    # Exact approved setup caps; aggregate setup clock remains independent.
    assert [(s['name'],s['timeout-minutes']) for s in steps] == [
        ('Begin setup budget',1),('Checkout CI control',2),
        ('Validate control and synthetic wrapper',10),('Read immutable export pins',1),
        ('Checkout production model export',5),('Checkout immutable upstream tool',2),
        ('Check all source identities',1),('Setup exact stock tool',15),
        ('Build exact stock tool once',15),('Run S2 batch3probes with bounded observations',126),
        ('Materialize bounded fallback',2),('Upload bounded evidence',6)]
    assert byname['Checkout immutable upstream tool']['with']['repository']=='model-checking/kani'
    assert byname['Checkout production model export']['with']['repository']=='Tiramisu-Cake/verify-rust-std'
    assert byname['Setup exact stock tool']['uses']=='./tool/.github/actions/setup'
    assert byname['Build exact stock tool once']['timeout-minutes']==15
    assert byname['Setup exact stock tool']['timeout-minutes']==15
    assert byname['Check all source identities']['run']=='python3 control/ch8-s1-control/runner.py check-source --std export --tool tool'
    names=[s['name'] for s in steps]
    assert names.index('Checkout production model export') < names.index('Check all source identities') < names.index('Setup exact stock tool') < names.index('Build exact stock tool once') < names.index('Run S2 batch3probes with bounded observations')
    assert not any(byname['Check all source identities'].get(k) for k in ('if','continue-on-error'))
    assert 'test_runner.py test_s107.FinalizationTests test_s2.py test_cfg_pfc.py' in byname['Validate control and synthetic wrapper']['run']
    assert byname['Validate control and synthetic wrapper']['run'].splitlines() == [
        'python3 check_package.py control --repo ..',
        'python3 -m unittest -v test_runner.py test_s107.FinalizationTests test_s2.py test_cfg_pfc.py test_rustc_diagnostics.py test_contract_stacks.py test_r1403_lexical.py']
    assert steps[-2]['if']=='always()' and 'fallback' in steps[-2]['run'] and 'pack_evidence.py' in steps[-2]['run']
    return {'jobs':1,'serial':True,'max_runner_minutes':180,'step_timeout_sum_minutes':186,'checkout_depths':CHECKOUT_DEPTHS}


def control(repo):
    from runner import load_request
    r=load_request()
    assert os.environ['GITHUB_REPOSITORY']=='Tiramisu-Cake/kani'
    assert os.environ['GITHUB_EVENT_NAME']=='push'
    assert os.environ['GITHUB_REF'].startswith('refs/heads/'+('uninit-ci/ch8-s4p-' if r.get('schema') in ('ch8-s4p-1-v1','ch8-s4p-2-v1','ch8-s4p-2r2-v1','ch8-s4p-3-v1') else 'uninit-ci/ch8-s3s4-' if r.get('schema')=='ch8-s3s4-bridge1-v1' else 'uninit-ci/ch8-s3-2-' if r.get('schema')=='ch8-s3-2-v1' else 'uninit-ci/ch8-s3-1-' if r.get('schema')=='ch8-s3-1-v1' else 'uninit-ci/ch8-s2-batch3probes-'))
    assert os.environ['GITHUB_RUN_ATTEMPT']=='1', 'Rerun requires separate coordinator GO'
    assert git(repo,'rev-parse','HEAD')==os.environ['GITHUB_SHA']
    assert git(repo,'rev-list','--parents','-n','1','HEAD').split()==[os.environ['GITHUB_SHA'],r['control_parent']]
    assert not git(repo,'status','--porcelain','--untracked-files=no')
    assert git(repo,'ls-tree','-r','--name-only','HEAD','.github/workflows').splitlines()==['.github/workflows/ch8-s2.yml']
    changed=git(repo,'diff','--name-only',r['tool_sha'],'HEAD').splitlines()
    assert sorted(changed)==r['ci_changed_paths']
    assert all(p.startswith(('ch8-s1-control/','.github/workflows/')) for p in changed)
    if r.get('schema') in ('ch8-s3-2-v1','ch8-s3s4-bridge1-v1','ch8-s4p-1-v1','ch8-s4p-2-v1','ch8-s4p-2r2-v1','ch8-s4p-3-v1'):
        assert git(repo,'diff','--diff-filter=D','--name-only',r['tool_sha'],'HEAD').splitlines()==r['ci_deleted_paths']
        assert set(r['ci_payload_sha256'])==set(changed)-set(r['ci_deleted_paths'])-{'ch8-s1-control/CI-REQUEST.json'}
    for rel,digest in r['ci_payload_sha256'].items():
        assert hashlib.sha256((repo/rel).read_bytes()).hexdigest()==digest,rel
    check_yaml(repo/'.github/workflows/ch8-s2.yml')
    assert not (repo.parent/'Cargo.toml').exists()
    return {'control_sha':git(repo,'rev-parse','HEAD'),'status':'STATIC_PASS','proof_credit':'NONE'}


def build(tool, epoch, out):
    # Executed on the GitHub runner only. Local preparation never invokes this.
    from runner import execute
    elapsed=time.time()-float(epoch.read_text())
    remaining=min(900, int(1800-elapsed))
    assert 0 < remaining <= 900, 'setup30min budget exhausted before tool build'
    out.mkdir(parents=True,exist_ok=True)
    result=execute(['cargo','build-dev','--','--release'],tool.resolve(),out.resolve(),
                   remaining,stdout_cap=1048576,stderr_cap=1048576,env=os.environ.copy())
    result['setup_total_seconds']=time.time()-float(epoch.read_text())
    (out/'receipt.json').write_text(json.dumps(result,indent=2)+'\n')
    assert (result.get('original_exit_code')==0 and not result.get('timed_out')
            and not result.get('termination_reason') and not result.get('stdout_truncated')
            and not result.get('stderr_truncated') and result['setup_total_seconds']<=1800), 'setup/build incomplete or capped'
    return {'setup':'COMPLETE','total_seconds':result['setup_total_seconds'],'proof_status':'NOT_RUN'}


def fallback(out, group_ids=None):
    import r5_profile
    request=json.loads((HERE/'CI-REQUEST.json').read_text())
    if request.get('schema')=='ch8-s4p-3-v1':
        import s4p3_campaign
        return s4p3_campaign.fallback(out,request)
    if request.get('schema')=='ch8-s4p-2r2-v1':
        import s4p2r2_campaign
        return s4p2r2_campaign.fallback(out,request)
    if request.get('schema')=='ch8-s4p-2-v1':
        import s4p2_campaign
        return s4p2_campaign.fallback(out,request)
    if request.get('schema')=='ch8-s4p-1-v1':
        import s4p_campaign
        return s4p_campaign.fallback(out,request)
    if request.get('schema')=='ch8-s3s4-bridge1-v1':
        import s34_campaign
        return s34_campaign.fallback(out,request)
    if request.get('schema')=='ch8-s3-2-v1':
        import s32_campaign
        return s32_campaign.fallback(out,request)
    if request.get('schema')=='ch8-s3-1-v1':
        import s3_campaign
        return s3_campaign.fallback(out,request)
    if r5_profile.enabled(request):
        active=(out/'campaign-start.json').exists() or (out/'completed').exists()
        terminal=out/'receipt.json'
        if terminal.exists():
            try:active=active or json.loads(terminal.read_text()).get('schema')=='ch8-s2-r5-campaign-v1'
            except (ValueError,AttributeError):active=True # ambiguous storage must not overwrite a prefix
        if group_ids is None or active:
            import r5_campaign
            return r5_campaign.fallback(out,request)
        # Explicit legacy group API remains strict before any r5 campaign state.
    return legacy_fallback(out,group_ids)


def legacy_fallback(out, group_ids=None):
    out.mkdir(parents=True,exist_ok=True)
    r=json.loads((HERE/'CI-REQUEST.json').read_text())
    # SIGKILL cannot run finally: retain observations and mark incomplete work UNKNOWN.
    from runner import _write_json, _bounded_log
    from runner import group_rows
    import rustc_diagnostics
    groups=group_rows(r['rows'],r.get('execution_groups'))
    if group_ids is not None:
        selected=set(group_ids)
        assert selected and selected.issubset({g['id'] for g in groups})
        groups=[g for g in groups if g['id'] in selected]
    selected_rows={row['id'] for g in groups for row in g['rows']}
    for group in groups:
        dest=out/'groups'/group['id'];dest.mkdir(parents=True,exist_ok=True)
        for path in (dest/'receipt.json',dest/'compile/receipt.json'):
            if path.is_file():
                value=json.loads(path.read_text())
                if value.get('state')=='IN_PROGRESS':
                    value.update(state='INTERRUPTED',outcome='UNKNOWN')
                    for stream in ('stdout','stderr'):
                        value[stream]=_bounded_log(dest/(stream+'.log'),None)
                    value['rustc_diagnostics']=rustc_diagnostics.summary(dest)
                    value['rustc_diagnostics'].update(complete=False,
                        incomplete_reasons=['FALLBACK_INTERRUPTED_EXECUTION']+value['rustc_diagnostics']['incomplete_reasons'])
                    _write_json(path,value)
            else:
                _write_json(path,{'state':'NOT_RUN_OR_INTERRUPTED','outcome':'UNKNOWN','proof_credit':'NONE',
                                  'rustc_diagnostics':rustc_diagnostics.summary(dest)})
    # Materialize every absent row, preserving any execution receipt already captured.
    for row in r['rows']:
        if row['id'] not in selected_rows: continue
        dest=out/row['id']; dest.mkdir(exist_ok=True)
        receipt=dest/'receipt.json'
        if not receipt.exists():
            receipt.write_text(json.dumps({'id':row['id'],'selector':row['selector'],
                'mode':row['mode'],'variant':row['variant'],'status':'NOT_RUN',
                'outcome':'UNKNOWN','original_exit':None,'signal':None,
                'reason':'No complete row receipt (setup/preflight/build/phase interruption)'},indent=2)+'\n')
        else:
            value=json.loads(receipt.read_text())
            if value.get('status')=='IN_PROGRESS':
                value.update(status='INTERRUPTED',outcome='UNKNOWN',
                             reason='No completed row receipt; original execution outcome UNKNOWN')
                for stream in ('stdout','stderr'):
                    # Row diagnostics belong to the group, never claim per-root output.
                    group_dir=out/'groups'/value.get('group','unknown')
                    value[stream]=_bounded_log(group_dir/(stream+'.log'),None)
                _write_json(receipt,value)
    # Setup failures and SIGKILL may leave no terminal identity envelope. Keep
    # the original snapshot and synthesize a collectable UNKNOWN partition.
    terminal_path=out/'receipt.json'
    original=None
    if terminal_path.is_file():
        captured=terminal_path.read_text()
        try:
            original=json.loads(captured)
        except json.JSONDecodeError:
            original={'state':'INVALID_JSON','captured_text':captured}
    identity={key:r.get(key) for key in ('std_sha','std_tree','tool_sha','tool_tree')}
    request_digest=hashlib.sha256((HERE/'CI-REQUEST.json').read_bytes()).hexdigest()
    complete_envelope=(isinstance(original,dict) and all(original.get(k)==v for k,v in identity.items())
                       and original.get('request_sha256')==request_digest
                       and original.get('selected_groups')==[g['id'] for g in groups]
                       and isinstance(original.get('rows'),list))
    if not complete_envelope:
        if terminal_path.is_file():
            _write_json(out/'interrupted-terminal.json',original)
        observations=[]
        for group in groups:
            for row in group['rows']:
                path=out/row['id']/'receipt.json'
                observed=json.loads(path.read_text())
                base={'id':row['id'],'selector':row['selector'],'mode':row['mode'],
                      'variant':row['variant'],'group':group['id'],'status':'NOT_RUN',
                      'outcome':'UNKNOWN','proof_credit':'NONE'}
                observations.append({**base,**observed} if isinstance(observed,dict) else base)
        _write_json(terminal_path,{**identity,'request_sha256':request_digest,
                    'selected_groups':[g['id'] for g in groups],
                    'state':'FALLBACK_INCOMPLETE','rows':observations,'proof_credit':'NONE',
                    'reason':'No completed terminal envelope; original row/group receipts retained'})
    (out/'job-status.json').write_text(json.dumps({'job_status':os.environ.get('JOB_STATUS','UNKNOWN'),
        'request_sha256':hashlib.sha256((HERE/'CI-REQUEST.json').read_bytes()).hexdigest(),
        'acceptance':'PENDING_INDEPENDENT_REVIEW','credit':'NONE'})+'\n')
    # Bound upload payload even on interrupted output production. Oversize means UNKNOWN,
    # preserve exact size/hash before removing unbounded content from the upload directory.
    cap=r['budgets']['artifact_bytes']
    files=[p for p in out.rglob('*') if p.is_file()]
    size=sum(p.stat().st_size for p in files)
    if size>cap:
        dropped=[]
        for p in sorted(files,key=lambda p:p.stat().st_size,reverse=True):
            if size<=cap: break
            if p.suffix=='.json' and p.stat().st_size<=65536: continue
            n=p.stat().st_size
            dropped.append({'path':str(p.relative_to(out)),'bytes':n,
                            'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})
            p.unlink();size-=n
        (out/'TRUNCATED.json').write_text(json.dumps({'outcome':'UNKNOWN','reason':'artifact cap',
            'dropped':dropped,'original_bytes':sum(p.get('bytes',0) for p in dropped)+size},indent=2)+'\n')
    return {'fallback':'MATERIALIZED','proof_credit':'NONE'}


if __name__=='__main__':
    p=argparse.ArgumentParser();s=p.add_subparsers(dest='command',required=True)
    a=s.add_parser('yaml');a.add_argument('path',type=Path)
    a=s.add_parser('control');a.add_argument('--repo',type=Path,required=True)
    a=s.add_parser('fallback');a.add_argument('--out',type=Path,required=True);a.add_argument('--groups')
    a=s.add_parser('build');a.add_argument('--tool',type=Path,required=True);a.add_argument('--epoch',type=Path,required=True);a.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    result=check_yaml(a.path) if a.command=='yaml' else control(a.repo.resolve()) if a.command=='control' else build(a.tool,a.epoch,a.out) if a.command=='build' else fallback(a.out,a.groups.split(',') if a.groups else None)
    print(json.dumps(result,sort_keys=True))
