#!/usr/bin/env python3
"""Offline package checks and bounded NOT_RUN fallback. Never dispatches a build."""
import argparse
import hashlib
import json
import os
import re
import shutil
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
    assert doc['on']['push']['branches'] == ['uninit-ci/ch8-c-ctl-*']
    assert doc['permissions'] == {'contents': 'read'}
    assert len(doc['jobs']) == 1
    job = doc['jobs']['c-controls']
    assert job['runs-on'] == 'ubuntu-24.04' and int(job['timeout-minutes']) == 150
    assert "github.repository == 'Tiramisu-Cake/kani'" in job['if']
    assert "github.event_name == 'push'" in job['if']
    assert int(job['strategy']['max-parallel']) == 1
    assert job['strategy']['matrix'] == {'lane': ['c-controls']}
    assert not re.search(r'\$\{\{\s*runner\.', json.dumps({k:v for k,v in job.items() if k!='steps'}))
    steps = job['steps']
    for step in steps:
        assert not re.search(r'\$\{\{\s*runner\.', json.dumps({k:v for k,v in step.items() if k!='env'}))
        assert int(step['timeout-minutes']) > 0
    checkouts = [s for s in steps if s.get('uses', '').startswith('actions/checkout@')]
    assert len(checkouts) == 3
    by_path = {s['with']['path']: s['with'] for s in checkouts}
    assert set(by_path) == {'control', 'export', 'tool'}
    assert by_path['control']['ref'] == '${{ github.sha }}'
    assert by_path['control'].get('repository', 'Tiramisu-Cake/kani') == 'Tiramisu-Cake/kani'
    assert by_path['export']['repository'] == 'Tiramisu-Cake/verify-rust-std'
    assert by_path['export']['ref'] == '${{ steps.pins.outputs.std }}'
    assert by_path['export']['submodules'] == 'true'
    assert by_path['tool']['repository'] == 'model-checking/kani'
    assert by_path['tool']['ref'] == '${{ steps.pins.outputs.tool }}'
    assert all(int(s['with']['fetch-depth']) >= 2 for s in checkouts)
    assert all(s['with']['persist-credentials'] == 'false' for s in checkouts)
    assert all(s.get('if') == 'always()' for s in steps[-2:])
    assert steps[-1]['with']['retention-days'] == '7'
    assert steps[-1]['with']['path'].splitlines() == [
        '${{ env.RECEIPT_ROOT }}/', '!${{ env.RECEIPT_ROOT }}/**/target/**']
    run_batch = next(s for s in steps if s.get('name') == 'Seed frozen inventory and run fixed C batches')
    assert int(run_batch['timeout-minutes']) == 112
    assert 'runner.py inventory ' in run_batch['run'] and 'runner.py list ' not in run_batch['run']
    return {'yaml': 'PASS', 'runner_context': 'STEP_ENV_ONLY',
            'checkout_depth': 'AT_LEAST_2', 'layout': ['control', 'export', 'tool'],
            'job_timeout_minutes': 150, 'dispatch': 'NOT_RUN'}


def control(repo):
    r = json.loads((HERE / 'CI-REQUEST.json').read_text())
    assert r['status'] == 'READY'
    assert r['flags']['attempt'] == 1 and r['flags']['max_root_seconds'] == 600
    assert r['flags']['uninit_checks'] is False and r['flags']['valid_value_checks'] is False
    assert r['flags']['assert_contracts'] is False and r['flags']['sorting_cfg'] is False
    budgets = r['budgets']
    grouped = {}
    for row in r['rows']:
        grouped.setdefault((row['unwind'], row['timeout_seconds']), []).append(row)
    expected_group_seconds = sum(sum(row['timeout_seconds'] for row in group) + 900
                                 for group in grouped.values())
    assert budgets['group_seconds'] == expected_group_seconds
    assert budgets['phase_seconds'] == budgets['run_step_seconds'] == 6720
    assert budgets['group_seconds'] == 6600
    assert budgets['setup_seconds'] + budgets['phase_seconds'] + budgets['reserve_seconds'] == 8820
    assert budgets['job_seconds'] == 9000 and 8820 <= budgets['job_seconds']
    assert budgets['job_seconds'] == 150 * 60 and budgets['run_step_seconds'] == 112 * 60
    assert [row['id'] for row in r['rows']] == [
        'c_merge_source_write_restore', 'c_merge_source_read_only',
        'c_callback_live_shared_in_outer_frame', 'c_callback_read_only_in_outer_frame',
        'c_external_mut_state', 'c_external_cell_state',
        'c_insert_tail_local_lifetime', 'c_local_storage_reuse']
    manifest_path = repo / 'ch8-c-control' / r['payload_manifest']
    assert hashlib.sha256(manifest_path.read_bytes()).hexdigest() == r['payload_manifest_sha256']
    manifest_entries = {}
    for line in manifest_path.read_text().splitlines():
        digest, rel = line.split('  ', 1)
        manifest_entries[rel] = digest
    assert manifest_entries == r['ci_payload_sha256']
    assert os.environ['GITHUB_REPOSITORY'] == 'Tiramisu-Cake/kani'
    assert os.environ['GITHUB_EVENT_NAME'] == 'push'
    assert os.environ['GITHUB_REF'].startswith('refs/heads/uninit-ci/ch8-c-ctl-')
    assert os.environ['GITHUB_RUN_ATTEMPT'] == '1', 'Each rerun needs another coordinator reservation'
    assert git(repo, 'rev-parse', 'HEAD') == os.environ['GITHUB_SHA']
    assert git(repo, 'rev-parse', 'HEAD^') == r['tool_sha']
    assert git(repo, 'rev-list', '--parents', '-n', '1', 'HEAD').split() == [os.environ['GITHUB_SHA'], r['tool_sha']]
    assert not git(repo, 'status', '--porcelain=v1')
    changed = git(repo, 'diff', '--name-only', 'HEAD^', 'HEAD').splitlines()
    assert changed and all(p.startswith(('ch8-c-control/', '.github/workflows/')) for p in changed)
    assert sorted(changed) == r['ci_changed_paths']
    workflows = git(repo, 'ls-tree', '-r', '--name-only', 'HEAD', '.github/workflows').splitlines()
    assert workflows == ['.github/workflows/ch8-c.yml']
    for rel, digest in r['ci_payload_sha256'].items():
        assert hashlib.sha256((repo / rel).read_bytes()).hexdigest() == digest, rel
    assert not (repo.parent / 'Cargo.toml').exists(), 'outer Cargo workspace forbidden'
    return {'control_sha': git(repo, 'rev-parse', 'HEAD'), 'parent_tool_sha': r['tool_sha'], 'status': 'PASS'}


def build(tool, epoch, out):
    # This command is reachable only from the explicitly scheduled GitHub workflow step.
    from runner import execute
    elapsed = time.time() - float(epoch.read_text())
    remaining = min(900, int(1800 - elapsed))
    assert 0 < remaining <= 900, '30 minute setup budget expired before tool build'
    out.mkdir(parents=True, exist_ok=True)
    result = execute(['cargo', 'build-dev', '--', '--release'], tool.resolve(), out.resolve(),
                     remaining, stdout_cap=1048576, stderr_cap=1048576, env=os.environ.copy())
    result['setup_total_seconds'] = time.time() - float(epoch.read_text())
    (out / 'receipt.json').write_text(json.dumps(result, indent=2) + '\n')
    assert (result.get('original_exit_code') == 0 and not result.get('timed_out')
            and not result.get('termination_reason') and not result.get('stdout_truncated')
            and not result.get('stderr_truncated') and result['setup_total_seconds'] <= 1800), 'setup/build incomplete or capped'
    return {'setup': 'COMPLETE', 'total_seconds': result['setup_total_seconds'], 'proof_status': 'NOT_RUN'}


def fallback(out):
    out.mkdir(parents=True, exist_ok=True)
    r = json.loads((HERE / 'CI-REQUEST.json').read_text())
    for row in r['rows']:
        dest = out / row['id']; dest.mkdir(exist_ok=True)
        receipt = dest / 'receipt.json'
        if not receipt.exists():
            receipt.write_text(json.dumps({'id': row['id'], 'selector': row['selector'],
                'mode': row['mode'], 'variant': row['variant'], 'status': 'NOT_RUN',
                'outcome': 'UNKNOWN', 'original_exit': None, 'signal': None,
                'reason': 'No complete row receipt (setup/preflight/build/phase interruption)'}, indent=2) + '\n')
    # Build directories are not evidence and must not consume the artifact budget
    # or enter the upload. Preserve sibling inventory and receipts.
    excluded_targets = []
    for path in sorted(out.rglob('target'), key=lambda p: len(p.parts), reverse=True):
        if path.is_symlink():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        else:
            continue
        excluded_targets.append(str(path.relative_to(out)))
    (out / 'job-status.json').write_text(json.dumps({'job_status': os.environ.get('JOB_STATUS', 'UNKNOWN'),
        'request_sha256': hashlib.sha256((HERE / 'CI-REQUEST.json').read_bytes()).hexdigest(),
        'excluded_build_directories': excluded_targets,
        'acceptance': 'PENDING_INDEPENDENT_REVIEW', 'credit': 'NONE'}) + '\n')
    cap = r['budgets']['artifact_bytes']
    files = [p for p in out.rglob('*') if p.is_file()]
    size = sum(p.stat().st_size for p in files)
    if size > cap:
        dropped = []
        for p in sorted(files, key=lambda p: p.stat().st_size, reverse=True):
            if size <= cap: break
            if p.suffix == '.json' and p.stat().st_size <= 65536: continue
            n = p.stat().st_size
            dropped.append({'path': str(p.relative_to(out)), 'bytes': n,
                            'sha256': hashlib.sha256(p.read_bytes()).hexdigest()})
            p.unlink(); size -= n
        (out / 'TRUNCATED.json').write_text(json.dumps({'outcome': 'UNKNOWN', 'reason': 'artifact cap',
            'dropped': dropped, 'original_bytes': sum(x['bytes'] for x in dropped) + size}, indent=2) + '\n')
    return {'fallback': 'MATERIALIZED', 'proof_credit': 'NONE'}


if __name__ == '__main__':
    p = argparse.ArgumentParser(); s = p.add_subparsers(dest='command', required=True)
    a = s.add_parser('yaml'); a.add_argument('path', type=Path)
    a = s.add_parser('control'); a.add_argument('--repo', type=Path, required=True)
    a = s.add_parser('fallback'); a.add_argument('--out', type=Path, required=True)
    a = s.add_parser('build'); a.add_argument('--tool', type=Path, required=True); a.add_argument('--epoch', type=Path, required=True); a.add_argument('--out', type=Path, required=True)
    a = p.parse_args()
    result = check_yaml(a.path) if a.command == 'yaml' else control(a.repo.resolve()) if a.command == 'control' else build(a.tool, a.epoch, a.out) if a.command == 'build' else fallback(a.out)
    print(json.dumps(result, sort_keys=True))
