# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
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
    from workflow_repo import check_control_repo_paths
    doc = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    repo_paths = check_control_repo_paths(doc)
    assert set(doc['on']) == {'push'}
    assert doc['on']['push']['branches'] == ['uninit-ci/ch8-prof02-*']
    assert doc['permissions'] == {'contents': 'read'}
    assert doc['concurrency'] == {'group': 'ch8-prof02-control', 'cancel-in-progress': 'false'}
    assert list(doc['jobs']) == ['profiles-on', 'profiles-off']
    on, off = doc['jobs']['profiles-on'], doc['jobs']['profiles-off']
    assert off.get('needs') == 'profiles-on'
    assert 'always()' in off['if']
    assert 'always()' in off['if'], 'OFF lane must still run after ON failure'
    for lane, job in (('on', on), ('off', off)):
        assert job['runs-on'] == 'ubuntu-24.04' and int(job['timeout-minutes']) == 180
        assert "github.repository == 'Tiramisu-Cake/kani'" in job['if']
        assert "github.event_name == 'push'" in job['if']
        assert int(job['strategy']['max-parallel']) == 1
        assert job['strategy']['matrix'] == {'lane': [lane]}
        assert not re.search(r'\$\{\{\s*runner\.', json.dumps({k:v for k,v in job.items() if k!='steps'}))
        steps=job['steps']
        for step in steps:
            assert not re.search(r'\$\{\{\s*runner\.', json.dumps({k:v for k,v in step.items() if k!='env'}))
        checkouts=[s for s in steps if s.get('uses','').startswith('actions/checkout@')]
        assert {s['with']['path'] for s in checkouts} == {'control','export','tool'}
        assert all(int(s['with']['fetch-depth']) >= 2 for s in checkouts)
        assert next(s for s in checkouts if s['with']['path']=='control')['with']['fetch-depth']=='32'
        assert all(s['with']['persist-credentials']=='false' for s in checkouts)
        assert all(s.get('if') == 'always()' for s in steps[-2:])
        fallback_step=next(s for s in steps if s['name'].startswith('Materialize bounded'))
        assert ('--lane off' in fallback_step['run']) == (lane=='off')
        assert all('timeout-minutes' in s for s in steps)
        build_index=next(i for i,s in enumerate(steps) if s['name']==f'Build exact {"SEL1" if lane=="on" else "stock"} tool once')
        assert sum(int(s['timeout-minutes']) for s in steps[:build_index]) <= 30
        assert int(steps[build_index]['timeout-minutes'])==15
        assert int(steps[build_index+1]['timeout-minutes'])==140
        assert steps[build_index+1]['run'].count('runner.py run ') == 1
        validation=next(s['run'] for s in steps if s.get('name')=='Validate control and synthetic wrappers')
        for name in ('test_batch.py','test_profiles.py','test_runner.py'):
            assert name in validation
        assert sum(int(s['timeout-minutes']) for s in steps[-2:])==10
        assert steps[-1]['with']['retention-days']=='7'
        assert "github.run_attempt == 1" in job['if']
        assert next(s for s in checkouts if s['with']['path']=='export')['with']['repository']=='Tiramisu-Cake/verify-rust-std'
        assert next(s for s in checkouts if s['with']['path']=='tool')['with']['repository']=='Tiramisu-Cake/kani'
        assert next(s for s in checkouts if s['with']['path']=='tool')['with']['ref']=='${{ steps.pins.outputs.tool }}'
    assert any(s.get('uses') == './tool/.github/actions/setup' for s in on['steps'])
    assert any(s.get('uses') == './tool/.github/actions/setup' for s in off['steps'])
    return {'yaml':'PASS','runner_context':'STEP_ENV_ONLY','checkout_depth':'AT_LEAST_2',
            'layout':['control','export','tool'],'dispatch':'NOT_RUN','control_repo_paths':repo_paths}


def control(repo):
    check_yaml(repo/'.github/workflows/ch8-prof-on.yml')
    r=json.loads((HERE/'CI-REQUEST.json').read_text())
    off=json.loads((HERE/'off'/'CI-REQUEST.json').read_text())
    assert r['status']==off['status']=='READY'
    assert r['std_sha']==off['std_sha'] and r['std_tree']==off['std_tree']
    assert r['rows']==off['rows'], 'ON/OFF row inventory drift'
    assert r['execution']['dispatches_per_push']==1
    assert r['execution']['max_active_jobs']==1 and r['execution']['aggregate_wall_minutes_cap']==360
    for request in (r, off):
        assert request['dispatch_cap']==1 and request['dispatches']==0
        assert request['caps']['jobs']==2 and request['caps']['max_parallel']==1
        assert request['caps']['concurrent_runs']==1 and request['caps']['workflow_minutes']==180
        assert request['caps']['total_wall_minutes_cap']==360
        assert request['caps']['setup_seconds']==1800 and request['caps']['proof_phase_seconds']==8400
        assert request['caps']['closeout_seconds']==600 and request['caps']['row_seconds']==600
        assert request['caps']['rss_gib']==6 and request['caps']['stdout_bytes_per_row']==1048576
        assert request['caps']['export_bytes_per_row']==8388608 and request['caps']['artifact_bytes']==268435456
        assert request['execution']==r['execution'] and request['execution']['off_runs_after_on_failure'] is True
    assert r['tool_sha']=='14bc57fdb99960240c4944845a3d985c8af4dcf7'
    assert off['tool_sha']=='0aac16ef62da9e9d5645782d458593e5d78143ba'
    assert os.environ['GITHUB_REPOSITORY']=='Tiramisu-Cake/kani'
    assert os.environ['GITHUB_EVENT_NAME']=='push'
    assert os.environ['GITHUB_REF'].startswith('refs/heads/uninit-ci/ch8-prof02-')
    assert os.environ['GITHUB_RUN_ATTEMPT']=='1', 'Every rerun needs another coordinator reservation'
    assert git(repo,'rev-parse','HEAD')==os.environ['GITHUB_SHA']
    assert git(repo,'merge-base','HEAD',r['tool_sha'])==r['tool_sha'], 'control history must descend from exact SEL1'
    assert not git(repo,'status','--porcelain','--untracked-files=no')
    changed=git(repo,'diff','--name-only',r['tool_sha'],'HEAD').splitlines()
    assert changed and all(p.startswith(('ch8-prof-on-control/','.github/workflows/')) for p in changed)
    assert sorted(changed)==r['ci_changed_paths'], 'control changed path inventory drift from SEL1'
    workflows=git(repo,'ls-tree','-r','--name-only','HEAD','.github/workflows').splitlines()
    assert workflows == ['.github/workflows/ch8-prof-on.yml']
    for rel,digest in r['ci_payload_sha256'].items():
        assert hashlib.sha256((repo/rel).read_bytes()).hexdigest()==digest, rel
    for req,base in ((r,HERE),(off,HERE/'off')):
        assert hashlib.sha256((base/'manifest.json').read_bytes()).hexdigest()==req['manifest_sha256']
    assert not (repo.parent/'Cargo.toml').exists(), 'outer Cargo workspace forbidden'
    return {'control_sha':git(repo,'rev-parse','HEAD'),'baseline_tool_sha':r['tool_sha'],
            'off_tool_sha':off['tool_sha'],'status':'PASS'}

def build(tool, epoch, out):
    tool, epoch, out = tool.resolve(), epoch.resolve(), out.resolve()
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


def fallback(out, lane='on'):
    out = out.resolve()
    out.mkdir(parents=True,exist_ok=True)
    if lane not in ('on','off'):
        raise ValueError('lane must be on or off')
    request_path=HERE/'CI-REQUEST.json' if lane=='on' else HERE/'off'/'CI-REQUEST.json'
    r=json.loads(request_path.read_text())
    import shutil
    for target in out.rglob('target'):
        if target.is_dir(): shutil.rmtree(target)
    # Materialize every absent row, preserving any execution receipt already captured.
    for row in r['rows']:
        dest=out/row['id']; dest.mkdir(exist_ok=True)
        receipt=dest/'receipt.json'
        if not receipt.exists():
            receipt.write_text(json.dumps({'id':row['id'],'selector':row['selector'],
                'mode':row['mode'],'variant':'production','status':'NOT_RUN',
                'outcome':'UNKNOWN','original_exit':None,'signal':None,
                'reason':'No complete row receipt (setup/preflight/build/phase interruption)'},indent=2)+'\n')
    (out/'job-status.json').write_text(json.dumps({'lane':lane,'job_status':os.environ.get('JOB_STATUS','UNKNOWN'),
        'request_sha256':hashlib.sha256(request_path.read_bytes()).hexdigest(),
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
    a=s.add_parser('fallback');a.add_argument('--out',type=Path,required=True);a.add_argument('--lane',choices=('on','off'),default='on')
    a=s.add_parser('build');a.add_argument('--tool',type=Path,required=True);a.add_argument('--epoch',type=Path,required=True);a.add_argument('--out',type=Path,required=True)
    a=p.parse_args()
    result=check_yaml(a.path) if a.command=='yaml' else control(a.repo.resolve()) if a.command=='control' else build(a.tool,a.epoch,a.out) if a.command=='build' else fallback(a.out,a.lane)
    print(json.dumps(result,sort_keys=True))
