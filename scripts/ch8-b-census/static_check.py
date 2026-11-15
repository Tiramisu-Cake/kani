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
job=w['jobs']['census']
assert job['timeout-minutes']==req['job_minutes']==210
assert job['runs-on']==req['os']
assert job['strategy']=={'fail-fast':False,'max-parallel':1,'matrix':{'shard':[2,4]}}
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
# Protocol upper bound; two writers cannot exceed it even at the per-root export cap.
assert 235*(req['export_cap_bytes']+32768)+1024**2 < req['artifact_cap_bytes']
print(json.dumps({'status':'PASS','roots':235,'shards':req['inventory']['shards'],
    'checks':['YAML parse','runner context','checkout depth','trigger','cwd prefixes','no nested workspace','Python AST','artifact envelope'],
    'workflow_sha256':hashlib.sha256(WORKFLOW.read_bytes()).hexdigest()}))
