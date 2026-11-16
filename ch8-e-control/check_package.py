#!/usr/bin/env python3
"""Static frozen-package checks. No compiler, CI submission or publication."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from workflow_repo import check_control_repo_paths

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
PINS = {
    'upstream': {'repository': 'model-checking/kani', 'sha': '0aac16ef62da9e9d5645782d458593e5d78143ba',
                 'tree': '9d8bc9312bf955ef126d32b819b3cd0ed105ed2b'},
    'sel1': {'repository': 'Tiramisu-Cake/kani', 'sha': '14bc57fdb99960240c4944845a3d985c8af4dcf7',
             'tree': '1efb6e4dfa69d346df8e23741d11839b1932403d'},
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(*args):
    return subprocess.check_output(['git', '-C', str(ROOT), *args], text=True).strip()


def yaml_check(path):
    import yaml
    doc = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    assert set(doc['on']) == {'push'}
    assert doc['on']['push']['branches'] == ['uninit-ci/ch8-e-ctl-*']
    assert doc['permissions'] == {'contents': 'read'}
    assert doc['concurrency']['cancel-in-progress'] == 'false'
    assert set(doc['jobs']) == {'controls'}
    job = doc['jobs']['controls']
    assert job['runs-on'] == 'ubuntu-24.04'
    assert int(job['timeout-minutes']) == 120
    assert "github.repository == 'Tiramisu-Cake/kani'" in job['if']
    assert "github.event_name == 'push'" in job['if']
    assert job['strategy']['fail-fast'] == 'false'
    assert job['strategy']['max-parallel'] == '1'
    assert job['strategy']['matrix']['include'] == [
        {'pin': p, 'repository': v['repository'], 'sha': v['sha']} for p, v in PINS.items()]
    # runner context is unavailable in several job-level expression locations.
    assert not re.search(r'\$\{\{\s*runner\.', json.dumps({k:v for k,v in job.items() if k != 'steps'}))
    steps = job['steps']
    for s in steps:
        assert not re.search(r'\$\{\{\s*runner\.', json.dumps({k:v for k,v in s.items() if k != 'env'}))
        assert 0 < int(s['timeout-minutes']) <= 76
    checkouts = [s['with'] for s in steps if s.get('uses', '').startswith('actions/checkout@')]
    assert len(checkouts) == 2
    assert [s['path'] for s in checkouts] == ['control', 'tool']
    assert checkouts[0]['ref'] == '${{ github.sha }}'
    assert checkouts[1]['ref'] == '${{ matrix.sha }}'
    assert checkouts[1]['repository'] == '${{ matrix.repository }}'
    assert all(int(s['fetch-depth']) >= 2 and s['persist-credentials'] == 'false' for s in checkouts)
    assert [s.get('if') for s in steps[-2:]] == ['always()', 'always()']
    assert steps[-1]['with']['path'].splitlines() == [
        '${{ env.RECEIPT_ROOT }}/', '!${{ env.RECEIPT_ROOT }}/**/target/**']
    assert steps[-1]['with']['if-no-files-found'] == 'error'
    commands = '\n'.join(s.get('run', '') for s in steps)
    assert 'verify-std' not in commands
    assert 'runner.py build --tool tool --out "$RECEIPT_ROOT" --pin ${{ matrix.pin }}' in commands
    assert 'runner.py run --tool tool --out "$RECEIPT_ROOT" --pin ${{ matrix.pin }}' in commands
    paths = check_control_repo_paths(doc)
    return {'control_repo_paths': paths, 'yaml': 'PASS', 'runner_context': 'STEP_ENV_ONLY', 'matrix_pins': list(PINS)}


def static_check():
    req = json.loads((HERE/'CI-REQUEST.json').read_text())
    assert req['status'] == 'READY' and req['pins'] == PINS
    assert req['attempt'] == 1 and req['bucket'] == 'E' and req['item'] == 1
    assert req['dispatch_authorized'] is False and req['proof_credit'] == 'NONE'
    assert req['rows_sha256'] == digest(HERE/'rows.json')
    rows = json.loads((HERE/'rows.json').read_text())
    assert isinstance(rows, list) and rows
    ids = set()
    for row in rows:
        assert isinstance(row, dict) and re.fullmatch('[a-z][a-z0-9_]*', row['id'])
        assert row['id'] not in ids
        ids.add(row['id'])
        path = HERE / row['file']
        assert path.resolve().is_relative_to((HERE/'fixtures').resolve())
        assert path.suffix == '.rs' and path.is_file()
        assert re.fullmatch('[a-z][a-z0-9_]*', row['harness'])
        assert row['checks'] and set(row['checks']) <= {'ON', 'OFF'}
        assert set(row['expected_by_check']) == set(row['checks'])
        assert all(v in {'SUCCESS', 'FRONTEND_REJECTION', 'UNINIT_FAILURE', 'ASSERTION_FAILURE', 'ASSIGNS_FAILURE', 'OBSERVE'}
                   for v in row['expected_by_check'].values())
        if 'expected_by_pin' in row:
            assert set(row['expected_by_pin']) == set(PINS)
            for expectations in row['expected_by_pin'].values():
                assert set(expectations) == set(row['checks'])
                assert set(expectations.values()) <= {'SUCCESS', 'ASSIGNS_FAILURE'}
        assert isinstance(row['required_covers'], list)
        text = path.read_text()
        assert text.count('#[kani::proof]') == 1
        assert 'fn '+row['harness']+'(' in text
        assert all(label in text for label in row['required_covers'])
        assert 'kani::unwind' not in text
    mapping = req['payload_sha256']
    expected = {str(p.relative_to(ROOT)) for p in HERE.rglob('*') if p.is_file()
                and p.name not in {'CI-REQUEST.json', 'MANIFEST.sha256'} and '__pycache__' not in p.parts}
    expected.add('.github/workflows/ch8-e.yml')
    assert set(mapping) == expected, (set(mapping) ^ expected)
    for rel, sha in mapping.items():
        assert digest(ROOT/rel) == sha, rel
    manifest = ''.join(f'{sha}  {rel}\n' for rel, sha in sorted(mapping.items()))
    assert (HERE/'MANIFEST.sha256').read_text() == manifest
    assert req['payload_manifest_sha256'] == digest(HERE/'MANIFEST.sha256')
    yaml_check(ROOT/'.github/workflows/ch8-e.yml')
    assert sorted(p.name for p in (ROOT/'.github/workflows').iterdir() if p.is_file()) == ['ch8-e.yml']
    return {'static': 'PASS', 'source_files': len(rows), 'invocations_per_pin': sum(len(r['checks']) for r in rows),
            'proof_status': 'ALL_NOT_RUN', 'credit': 'NONE'}


def control_check():
    result = static_check()
    for key, value in {'GITHUB_REPOSITORY': 'Tiramisu-Cake/kani', 'GITHUB_EVENT_NAME': 'push',
                       'GITHUB_RUN_ATTEMPT': '1'}.items():
        assert os.environ.get(key) == value, key
    assert os.environ.get('GITHUB_REF', '').startswith('refs/heads/uninit-ci/ch8-e-ctl-')
    sha = os.environ['GITHUB_SHA']
    assert git('rev-parse', 'HEAD') == sha
    assert git('rev-list', '--parents', '-n', '1', 'HEAD').split() == [sha, PINS['upstream']['sha']]
    assert not git('status', '--porcelain=v1', '--untracked-files=no')
    changed = git('diff', '--name-only', 'HEAD^', 'HEAD').splitlines()
    assert changed and all(p.startswith(('ch8-e-control/', '.github/workflows/')) for p in changed)
    assert git('ls-tree', '-r', '--name-only', 'HEAD', '.github/workflows').splitlines() == ['.github/workflows/ch8-e.yml']
    assert not (ROOT.parent/'Cargo.toml').exists()
    result['control_sha'] = sha
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['static', 'yaml', 'control'])
    parser.add_argument('--repo', type=Path)
    args = parser.parse_args()
    if args.command == 'control':
        assert args.repo is not None and args.repo.resolve() == ROOT, '--repo must resolve to control checkout'
    elif args.repo is not None:
        assert args.repo.resolve() == ROOT
    result = yaml_check(ROOT/'.github/workflows/ch8-e.yml') if args.command == 'yaml' else control_check() if args.command == 'control' else static_check()
    print(json.dumps(result, sort_keys=True))
