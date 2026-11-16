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


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def check_yaml(path):
    import yaml
    doc = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    assert set(doc['on']) == {'push'}
    assert doc['on']['push']['branches'] == ['uninit-ci/ch8-s1k-*']
    assert doc['permissions'] == {'contents': 'read'}
    assert len(doc['jobs']) == 1
    job = doc['jobs']['s1']
    assert job['runs-on'] == 'ubuntu-24.04' and int(job['timeout-minutes']) == 120
    assert "github.repository == 'Tiramisu-Cake/kani'" in job['if']
    assert "github.event_name == 'push'" in job['if']
    assert int(job['strategy']['max-parallel']) == 1
    assert job['strategy']['matrix'] == {'lane': ['s1']}
    assert not re.search(r'\$\{\{\s*runner\.', json.dumps({k:v for k,v in job.items() if k!='steps'}))
    steps=job['steps']
    for step in steps:
        assert not re.search(r'\$\{\{\s*runner\.', json.dumps({k:v for k,v in step.items() if k!='env'}))
    checkouts=[s for s in steps if s.get('uses','').startswith('actions/checkout@')]
    assert len(checkouts) == 3
    assert {s['with']['path'] for s in checkouts} == {'control','export','tool'}
    by_path={s['with']['path']:s['with'] for s in checkouts}
    assert by_path['control']['ref'] == '${{ github.sha }}'
    assert by_path['control'].get('repository', 'Tiramisu-Cake/kani') == 'Tiramisu-Cake/kani'
    assert by_path['export']['repository'] == 'Tiramisu-Cake/verify-rust-std'
    assert by_path['export']['ref'] == '${{ steps.pins.outputs.std }}'
    assert by_path['export']['submodules'] == 'true'
    assert by_path['tool']['repository'] == 'model-checking/kani'
    assert by_path['tool']['ref'] == '${{ steps.pins.outputs.tool }}'
    assert all(int(s['with']['fetch-depth']) >= 2 for s in checkouts)
    assert all(s['with']['persist-credentials']=='false' for s in checkouts)
    assert all(s.get('if') == 'always()' for s in steps[-2:])
    assert all('timeout-minutes' in s for s in steps)
    build_index=next(i for i,s in enumerate(steps) if s['name']=='Build exact stock tool once')
    assert sum(int(s['timeout-minutes']) for s in steps[:build_index]) <= 30
    # Build wrapper uses the remaining absolute30min setup budget; step caps overlap it.
    assert int(steps[build_index]['timeout-minutes'])==15
    assert int(steps[build_index+1]['timeout-minutes'])==75
    recipe=steps[build_index+1]['run']
    assert 'runner.py warmup' not in recipe
    assert recipe.count('runner.py run') == 1
    assert 'runner.py run --std export --tool tool' in recipe
    assert 'runner.py list' not in recipe
    assert sum(int(s['timeout-minutes']) for s in steps[-2:])==15
    assert steps[-1]['with']['retention-days']=='7'
    return {'yaml':'PASS','runner_context':'STEP_ENV_ONLY','checkout_depth':'AT_LEAST_2',
            'layout':['control','export','tool'],'dispatch':'NOT_RUN'}


def control(repo):
    r=json.loads((HERE/'CI-REQUEST.json').read_text())
    assert r['status']=='READY'
    assert os.environ['GITHUB_REPOSITORY']=='Tiramisu-Cake/kani'
    assert os.environ['GITHUB_EVENT_NAME']=='push'
    assert os.environ['GITHUB_REF'].startswith('refs/heads/uninit-ci/ch8-s1k-')
    assert os.environ['GITHUB_RUN_ATTEMPT']=='1', 'Every rerun needs another coordinator reservation'
    assert git(repo,'rev-parse','HEAD')==os.environ['GITHUB_SHA']
    assert git(repo,'rev-parse','HEAD^')==r['tool_sha'], 'control parent must be exact upstream tool'
    assert git(repo,'rev-list','--parents','-n','1','HEAD').split()==[os.environ['GITHUB_SHA'],r['tool_sha']], 'single-parent control required'
    assert not git(repo,'status','--porcelain','--untracked-files=no')
    changed=git(repo,'diff','--name-only','HEAD^','HEAD').splitlines()
    assert changed and all(p.startswith(('ch8-s1-control/','.github/workflows/')) for p in changed)
    assert sorted(changed)==r['ci_changed_paths'], 'control changed path inventory drift'
    workflows=git(repo,'ls-tree','-r','--name-only','HEAD','.github/workflows').splitlines()
    assert workflows == ['.github/workflows/ch8-s1.yml']
    for rel,digest in r['ci_payload_sha256'].items():
        assert hashlib.sha256((repo/rel).read_bytes()).hexdigest()==digest, rel
    # Export and tool are sibling workspaces. Never checkout/build a child of control.
    assert not (repo.parent/'Cargo.toml').exists(), 'outer Cargo workspace forbidden'
    return {'control_sha':git(repo,'rev-parse','HEAD'),'parent_tool_sha':r['tool_sha'],'status':'PASS'}


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


def fallback(out):
    out.mkdir(parents=True,exist_ok=True)
    r=json.loads((HERE/'CI-REQUEST.json').read_text())
    # SIGKILL cannot run finally: retain observations and mark incomplete work UNKNOWN.
    from runner import _write_json, _bounded_log
    from runner import group_rows
    for group in group_rows(r['rows']):
        dest=out/'groups'/group['id'];dest.mkdir(parents=True,exist_ok=True)
        for path in (dest/'receipt.json',dest/'compile/receipt.json'):
            if path.is_file():
                value=json.loads(path.read_text())
                if value.get('state')=='IN_PROGRESS':
                    value.update(state='INTERRUPTED',outcome='UNKNOWN')
                    for stream in ('stdout','stderr'):
                        value[stream]=_bounded_log(dest/(stream+'.log'),None)
                    _write_json(path,value)
            else:
                _write_json(path,{'state':'NOT_RUN_OR_INTERRUPTED','outcome':'UNKNOWN','proof_credit':'NONE'})
    # Materialize every absent row, preserving any execution receipt already captured.
    for row in r['rows']:
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
    a=s.add_parser('fallback');a.add_argument('--out',type=Path,required=True)
    a=s.add_parser('build');a.add_argument('--tool',type=Path,required=True);a.add_argument('--epoch',type=Path,required=True);a.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    result=check_yaml(a.path) if a.command=='yaml' else control(a.repo.resolve()) if a.command=='control' else build(a.tool,a.epoch,a.out) if a.command=='build' else fallback(a.out)
    print(json.dumps(result,sort_keys=True))
