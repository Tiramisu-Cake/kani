#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Static-only package and upstream-parent checks; never invokes compilers."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from workflow_repo import check_control_repo_paths

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
UPSTREAM = '0aac16ef62da9e9d5645782d458593e5d78143ba'
PINS = {'upstream': {'repository': 'model-checking/kani', 'sha': UPSTREAM,
                     'tree': '9d8bc9312bf955ef126d32b819b3cd0ed105ed2b'}}


def digest(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def yaml_check(path):
    import yaml
    doc = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
    assert doc['on'] == {'push': {'branches': ['uninit-ci/ch8-issue-mre-*']}}
    assert doc['permissions'] == {'contents': 'read'}
    assert doc['concurrency']['cancel-in-progress'] == 'false'
    assert set(doc['jobs']) == {'controls'}
    job = doc['jobs']['controls']
    assert job['runs-on'] == 'ubuntu-24.04' and job['timeout-minutes'] == '30'
    assert 'strategy' not in job
    for guard in ["github.repository == 'Tiramisu-Cake/kani'", "github.event_name == 'push'", 'github.run_attempt == 1']:
        assert guard in job['if']
    steps = job['steps']
    assert sum(int(s['timeout-minutes']) for s in steps) <= 28
    checkouts = [s['with'] for s in steps if s.get('uses', '').startswith('actions/checkout@')]
    assert checkouts == [dict(ref='${{ github.sha }}', path='control', **{'fetch-depth': '2', 'persist-credentials': 'false'}),
                         dict(repository='model-checking/kani', ref=UPSTREAM, path='tool', **{'fetch-depth': '2', 'persist-credentials': 'false'})]
    assert [s.get('if') for s in steps[-2:]] == ['always()', 'always()']
    assert steps[-1]['with']['if-no-files-found'] == 'error'
    assert steps[-1]['with']['path'].splitlines() == ['${{ env.RECEIPT_ROOT }}/', '!${{ env.RECEIPT_ROOT }}/**/target/**']
    assert len([s for s in steps if s.get('uses') == './tool/.github/actions/setup']) == 1
    commands = '\n'.join(s.get('run', '') for s in steps)
    for phase in ['build', 'run']:
        assert f'runner.py {phase} --tool tool --out "$RECEIPT_ROOT"' in commands
    assert 'verify-std' not in commands and 'sel1' not in path.read_text().lower()
    return {'control_repo_paths': check_control_repo_paths(doc)}


def static_check():
    req = json.loads((HERE/'CI-REQUEST.json').read_text())
    assert req['status'] == 'READY' and req['pins'] == PINS
    assert req['attempt'] == 1 and req['dispatch_authorized'] is False
    assert req['proof_credit'] == 'NONE' and req['proof_status'] == 'ALL_NOT_RUN'
    assert req['rows_sha256'] == digest(HERE/'rows.json')
    rows = json.loads((HERE/'rows.json').read_text())
    assert len(rows) == 10 and len({r['id'] for r in rows}) == 10
    assert len({r['file'] for r in rows}) == 7
    expected_ids = {'copy_integer', 'raw_bool_overwrite', 'raw_bool_read', 'actual_uninit_read'} | {
        f'{v}_{h}' for v in ['slice_uninit', 'slice_initialized', 'thin_uninit'] for h in ['check_body', 'check_slice_havoc']}
    assert {r['id'] for r in rows} == expected_ids
    for r in rows:
        source = HERE/r['file']
        assert source.resolve().is_relative_to((HERE/'fixtures').resolve()) and source.suffix == '.rs'
        text = source.read_text()
        assert 'fn '+r['harness']+'(' in text and 'kani::unwind' not in text
        assert r['expected'] in {'SUCCESS', 'COPY_UNSUPPORTED', 'UNINIT_FAILURE'}
        assert (r['failure_description'] is None) == (r['expected'] == 'SUCCESS')
        assert r['flags'] == (['-Z', 'valid-value-checks'] if r['expected'] == 'COPY_UNSUPPORTED' else ['-Z','function-contracts','-Z','uninit-checks'])
        assert r['kind'] == ('ProofForContract' if r['harness'] == 'check_body' else 'Proof')
        assert r['verified_stubs'] == (['initialize'] if r['harness'] == 'check_slice_havoc' else [])
    # Variant scope is literal and mechanically constrained.
    original = (HERE/'fixtures/slice_uninit.rs').read_text()
    assert (HERE/'fixtures/slice_initialized.rs').read_text() == original.replace('[MaybeUninit::uninit(); 2]', '[MaybeUninit::new(0u8); 2]')
    assert (HERE/'fixtures/thin_uninit.rs').read_text() == original.replace(
        '#[kani::modifies(std::ptr::slice_from_raw_parts_mut(out.as_mut_ptr().cast::<u8>(), 2))]',
        '#[kani::modifies(out.as_mut_ptr().cast::<u8>(), out.as_mut_ptr().cast::<u8>().wrapping_add(1))]')
    mapping = req['payload_sha256']
    expected = {str(p.relative_to(ROOT)) for p in HERE.rglob('*') if p.is_file()
                and p.name not in {'CI-REQUEST.json', 'MANIFEST.sha256'} and '__pycache__' not in p.parts}
    expected.add('.github/workflows/ch8-issue-mre.yml')
    assert set(mapping) == expected
    for rel, sha in mapping.items():
        assert digest(ROOT/rel) == sha, rel
    assert (HERE/'MANIFEST.sha256').read_text() == ''.join(f'{sha}  {rel}\n' for rel, sha in sorted(mapping.items()))
    assert req['payload_manifest_sha256'] == digest(HERE/'MANIFEST.sha256')
    assert [p.name for p in (ROOT/'.github/workflows').iterdir()] == ['ch8-issue-mre.yml']
    return {'static': 'PASS', 'rows': len(rows), 'source_files': 7,
            'workflow_paths': yaml_check(ROOT/'.github/workflows/ch8-issue-mre.yml')}


def control_check(repo):
    assert repo.resolve() == ROOT.resolve(), '--repo must select this control checkout'
    assert git(repo, 'show', '-s', '--format=%P', 'HEAD') == UPSTREAM
    assert not git(repo, 'status', '--porcelain=v1', '--untracked-files=no')
    changed = git(repo, 'diff', '--name-only', UPSTREAM, 'HEAD').splitlines()
    assert all(p.startswith(('.github/workflows/', 'ch8-issue-mre-control/')) for p in changed)
    assert git(repo, 'rev-parse', UPSTREAM+'^{tree}') == PINS['upstream']['tree']
    return {'control': 'PASS', 'sha': git(repo, 'rev-parse', 'HEAD'), 'tree': git(repo, 'rev-parse', 'HEAD^{tree}')}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['static','control'])
    parser.add_argument('--repo', type=Path, default=ROOT)
    args = parser.parse_args()
    result = static_check()
    if args.mode == 'control': result.update(control_check(args.repo))
    print(json.dumps(result, indent=2))
