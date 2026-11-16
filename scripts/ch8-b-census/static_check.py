# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Offline YAML/identity checks; PyYAML and actionlint are static tooling only."""
import ast
import hashlib
import json
from pathlib import Path
import re
import yaml
import census

ROOT=Path(__file__).resolve().parents[2]
WORKFLOW=ROOT/'.github/workflows/ch8-b-census.yml'
req,roots=census.load()
w=yaml.safe_load(WORKFLOW.read_text())
assert w['on']=={'push':{'branches':['uninit-ci/ch8-b-census-*']}}
assert w['permissions']=={'contents':'read'}
class Loader(yaml.SafeLoader):
    pass
Loader.yaml_implicit_resolvers = {k:[(tag,pattern) for tag,pattern in values if tag!='tag:yaml.org,2002:bool'] for k,values in Loader.yaml_implicit_resolvers.items()}
import fnmatch
matched=[]
for p in (ROOT/'.github/workflows').glob('*.yml'):
    events=yaml.load(p.read_text(),Loader=Loader).get('on',{})
    push=events.get('push') if isinstance(events,dict) else None
    if push is None: continue
    branches=push.get('branches',['**'])
    active=False
    for pattern in branches:
        if fnmatch.fnmatchcase('uninit-ci/ch8-b-census-example',pattern.lstrip('!')):
            active=not pattern.startswith('!')
    if active: matched.append(p.name)
assert sorted(p.name for p in (ROOT/'.github/workflows').glob('*')) == ['ch8-b-census.yml']
assert matched==['ch8-b-census.yml'], 'extra workflow push triggers: '+repr(matched)
job=w['jobs']['census']
assert job['timeout-minutes']==req['job_minutes']==210
assert job['runs-on']==req['os']
assert 'strategy' not in job
steps=job['steps']
for step in steps:
    if step.get('uses','').startswith('actions/checkout@'):
        assert step['with']['fetch-depth']>=2
        assert step['with']['persist-credentials'] is False
    for key,value in step.items():
        if key!='env':
            assert 'runner.' not in json.dumps(value), 'runner.* outside step env'
    if 'run' in step:
        # Parse every embedded Python heredoc as Python, independent of indentation.
        match=re.search(r"python3 - <<'PYCODE'\n(.*?)\nPYCODE",step['run'],re.S)
        if match: ast.parse(match.group(1))
assert [s['with']['path'] for s in steps if s.get('uses','').startswith('actions/checkout@')]==['control','export','std']
assert next(s for s in steps if s.get('uses')=='./export/.github/actions/setup')['with']['kani_dir']=='export'
assert not any(p.exists() for p in (ROOT/'control',ROOT/'export',ROOT/'std')), 'nested workspace'
for p in census.HERE.glob('*.py'): ast.parse(p.read_text())
# Group harness data appears once across rows; group selection identity is repeated per row.
assert 2*req['export_cap_bytes']+235*(32768+sum(len(r['selector'])+4 for r in roots))+1024**2 < req['artifact_cap_bytes']
result = ({'status':'PASS','roots':235,'shards':req['inventory']['shards'],
    'checks':['YAML parse','runner context','checkout depth','trigger','cwd prefixes','no nested workspace','Python AST','artifact envelope'],
    'workflow_sha256':hashlib.sha256(WORKFLOW.read_bytes()).hexdigest()})

by_path={s['with']['path']:s['with'] for s in steps if s.get('uses','').startswith('actions/checkout@')}
assert by_path['std']['ref']==req['std']['sha']
assert by_path['export']['ref']==req['kani']['sha']
assert by_path['export']['repository']==req['kani']['repository']=='model-checking/kani'
assert req['jobs']==req['per_root_jobs']==1 and req['group_count']==1
assert req['stage_seconds']['verify']==req['compile_seconds']+235*req['root_seconds']
assert req['root_seconds']==600 and req['root_rss_bytes']==6*1024**3
# Only direct selected verification and bounded build are invocation entry points.
tree=ast.parse((census.HERE/'census.py').read_text())
assert not any(isinstance(n,ast.Constant) and n.value in ('list','metrics','run-kani.sh') for n in ast.walk(tree))
assert census.argv_for(req,roots,Path('/tool/scripts/kani'),Path('/target'),Path('/export.json'))[1]=='verify-std'

print(json.dumps(result))
