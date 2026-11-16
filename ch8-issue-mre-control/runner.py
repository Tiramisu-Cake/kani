#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Bounded, prep-only runner for pinned upstream Challenge 8 issue MREs."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import threading
import time
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
REQUEST = HERE / "CI-REQUEST.json"
ROWS = HERE / "rows.json"
PIN = {"sha": "0aac16ef62da9e9d5645782d458593e5d78143ba",
       "tree": "9d8bc9312bf955ef126d32b819b3cd0ed105ed2b",
       "repository": "model-checking/kani"}
RSS_CAP_KIB = 6 * 1024 * 1024
LOG_CAP = 1024 * 1024
LOG_TAIL = 4096
EXPORT_CAP = 8 * 1024 * 1024
BUILD_SECONDS = 720
ROW_SECONDS = 30
PHASE_SECONDS = 330
EXPECTED_FLAGS = (('-Z', 'valid-value-checks'),
                  ('-Z', 'function-contracts', '-Z', 'uninit-checks'))


class RunnerError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.run(['git', '-C', str(repo), *args], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def _guard_env() -> dict[str, str]:
    env = os.environ.copy()
    checks = {'GITHUB_REPOSITORY': 'Tiramisu-Cake/kani', 'GITHUB_EVENT_NAME': 'push',
              'GITHUB_REF': None, 'GITHUB_RUN_ATTEMPT': '1'}
    for key, expected in checks.items():
        if expected is not None and env.get(key) != expected:
            raise RunnerError(f'{key} must be {expected}')
    if not env.get('GITHUB_REF', '').startswith('refs/heads/uninit-ci/ch8-issue-mre-'):
        raise RunnerError('GITHUB_REF is outside the issue MRE branch family')
    for key in ('KANI_ATTEMPT', 'SMALLSORT_ATTEMPT'):
        if key in env and env[key] != '1':
            raise RunnerError(f'refusing {key} other than attempt 1')
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'KANI_FLAGS', 'KANI_OPTS'):
        if env.get(key, '').strip():
            raise RunnerError(f'refusing inherited {key}')
    env['KANI_ATTEMPT'] = '1'
    return env


def load_request() -> tuple[dict[str, Any], str]:
    try:
        raw = REQUEST.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f'cannot read CI request: {exc}') from exc
    if not isinstance(value, dict) or value.get('status') != 'READY':
        raise RunnerError('CI request is not READY')
    if value.get('attempt') != 1:
        raise RunnerError('request is not attempt 1')
    pins = value.get('pins')
    if not isinstance(pins, dict) or not isinstance(pins.get('upstream'), dict):
        raise RunnerError('request is missing upstream pin')
    if any(pins['upstream'].get(k) != v for k, v in PIN.items()):
        raise RunnerError('request upstream SHA/tree/repository mismatch')
    payload = value.get('payload_sha256')
    if not isinstance(payload, dict) or any(not isinstance(k, str) or not isinstance(v, str) or
                                             not re.fullmatch(r'[0-9a-f]{64}', v)
                                             for k, v in payload.items()):
        raise RunnerError('request payload_sha256 must map paths to SHA256 values')
    rows_hash = value.get('rows_sha256')
    if not isinstance(rows_hash, str) or not re.fullmatch(r'[0-9a-f]{64}', rows_hash):
        raise RunnerError('request rows_sha256 is missing or malformed')
    caps = value.get('caps')
    expected_caps = {'row_envelope_seconds': ROW_SECONDS,
                     'run_phase_seconds_per_pin': PHASE_SECONDS,
                     'tool_build_seconds': BUILD_SECONDS,
                     'process_group_rss_bytes': RSS_CAP_KIB * 1024,
                     'stdout_head_bytes': LOG_CAP, 'stderr_head_bytes': LOG_CAP,
                     'tail_bytes_per_stream': LOG_TAIL, 'export_bytes': EXPORT_CAP}
    if not isinstance(caps, dict) or any(caps.get(k) != v for k, v in expected_caps.items()):
        raise RunnerError('request caps do not match runner limits')
    manifest = value.get('payload_manifest_sha256')
    if not isinstance(manifest, str) or not re.fullmatch(r'[0-9a-f]{64}', manifest):
        raise RunnerError('request payload_manifest_sha256 is missing or malformed')
    entries = []
    for rel, digest in sorted(payload.items()):
        p = (REPO / rel).resolve()
        if REPO.resolve() not in p.parents or not p.is_file() or sha256(p) != digest:
            raise RunnerError(f'payload hash mismatch: {rel}')
        entries.append(f'{digest}  {rel}\n')
    manifest_bytes = ''.join(entries).encode()
    manifest_path = HERE / 'MANIFEST.sha256'
    if hashlib.sha256(manifest_bytes).hexdigest() != manifest or not manifest_path.is_file() or manifest_path.read_bytes() != manifest_bytes:
        raise RunnerError('payload manifest mismatch')
    return value, hashlib.sha256(raw).hexdigest()


def verify_tool(tool: Path) -> dict[str, str]:
    tool = tool.resolve()
    if tool.name != 'tool' or tool.parent != HERE.parent.parent.resolve():
        raise RunnerError("tool must be the sibling 'tool' directory beside control")
    try:
        sha, tree, kind = (git(tool, 'rev-parse', 'HEAD'), git(tool, 'rev-parse', 'HEAD^{tree}'),
                           git(tool, 'cat-file', '-t', PIN['sha']))
        dirty = git(tool, 'status', '--porcelain=v1', '--untracked-files=no')
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RunnerError(f'cannot inspect pinned tool checkout: {exc}') from exc
    if (sha, tree, kind) != (PIN['sha'], PIN['tree'], 'commit'):
        raise RunnerError('tool upstream SHA/tree drift or pinned commit unavailable')
    if dirty:
        raise RunnerError('tool tracked state is not clean')
    return {'pin': 'upstream', 'sha': sha, 'tree': tree}


def load_rows(request: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    try:
        raw = ROWS.read_bytes()
        rows = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f'cannot read rows.json: {exc}') from exc
    digest = hashlib.sha256(raw).hexdigest()
    if digest != request['rows_sha256']:
        raise RunnerError('rows.json SHA does not match CI request')
    if not isinstance(rows, list) or not rows:
        raise RunnerError('rows.json must be a non-empty array')
    seen = set()
    for row in rows:
        if not isinstance(row, dict):
            raise RunnerError('row must be an object')
        rid, rel, harness = row.get('id'), row.get('file'), row.get('harness')
        if not isinstance(rid, str) or not rid or rid in seen:
            raise RunnerError('missing or duplicate row id')
        seen.add(rid)
        if (not isinstance(rel, str) or Path(rel).is_absolute() or '..' in Path(rel).parts or
                not isinstance(harness, str) or not harness or '\x00' in harness):
            raise RunnerError(f'invalid source or harness for {rid}')
        src = (HERE / rel).resolve()
        if HERE.resolve() not in src.parents or not src.is_file():
            raise RunnerError(f'source file missing or outside control tree for {rid}')
        expected_sha = _row_payload_hash(request, rel)
        if expected_sha != sha256(src):
            raise RunnerError(f'payload SHA mismatch for {rid}')
        flags = row.get('flags')
        if not isinstance(flags, list) or tuple(flags) not in EXPECTED_FLAGS:
            raise RunnerError(f'unapproved semantic flags for {rid}')
        if row.get('expected') not in ('SUCCESS', 'COPY_UNSUPPORTED', 'UNINIT_FAILURE'):
            raise RunnerError(f'invalid expected outcome for {rid}')
        if row.get('desired') not in ('SUCCESS', 'INVALID_VALUE_FAILURE', 'UNINIT_FAILURE'):
            raise RunnerError(f'invalid desired outcome for {rid}')
        if row.get('kind') not in ('Proof', 'ProofForContract'):
            raise RunnerError(f'invalid kind for {rid}')
        contract, stubs, desc = row.get('contract'), row.get('verified_stubs'), row.get('failure_description')
        if (contract is not None and (not isinstance(contract, str) or not contract) or
                not isinstance(stubs, list) or any(not isinstance(x, str) or not x for x in stubs) or
                (row['kind'] == 'ProofForContract') != (contract is not None) or
                (row['expected'] == 'SUCCESS' and desc is not None) or
                (row['expected'] != 'SUCCESS' and (not isinstance(desc, str) or not desc))):
            raise RunnerError(f'invalid metadata/oracle for {rid}')
    return rows, digest


def _row_payload_hash(request: dict[str, Any], rel: str) -> str | None:
    return request['payload_sha256'].get(rel) or request['payload_sha256'].get(f'{HERE.name}/{rel}')


def _read_pipe(pipe, head: Path, tail_path: Path, state: dict[str, Any], lock: threading.Lock, key: str) -> None:
    tail = bytearray()
    with head.open('wb') as output:
        while True:
            data = pipe.read(65536)
            if not data: break
            with lock:
                tail.extend(data)
                if len(tail) > LOG_TAIL: del tail[:-LOG_TAIL]
                room = max(0, LOG_CAP - state[key + '_kept'])
                if len(data) > room: state[key + '_cap'] = True
                state[key + '_kept'] += min(room, len(data))
                state[key + '_bytes'] += len(data)
            if room: output.write(data[:room])
    pipe.close()
    tail_path.write_bytes(tail)


def _group_rss_kib(pgid: int) -> int:
    total = 0
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit(): continue
        try:
            fields = (entry / 'stat').read_text().split(')')[-1].split()
            if int(fields[2]) == pgid:
                for line in (entry / 'status').read_text().splitlines():
                    if line.startswith('VmRSS:'):
                        total += int(line.split()[1]); break
        except (OSError, ValueError, IndexError): pass
    return total


def _kill_group(pgid: int, grace: float = 3.0) -> None:
    try: os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError: return
    until = time.monotonic() + grace
    while time.monotonic() < until:
        try: os.killpg(pgid, 0)
        except ProcessLookupError: return
        time.sleep(.05)
    try: os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError: pass


def execute(argv: list[str], cwd: Path, out: Path, timeout: int,
            env: dict[str, str] | None = None, export_path: Path | None = None) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    info = {'argv': argv, 'cwd': str(cwd.resolve()), 'original_exit_code': None, 'signal': None,
            'timed_out': False, 'rss_peak_kib': 0, 'output_truncated': False, 'output_bytes': 0}
    state = {k: 0 for k in ('stdout_kept', 'stderr_kept', 'stdout_bytes', 'stderr_bytes')}
    state.update(stdout_cap=False, stderr_cap=False)
    lock, start = threading.Lock(), time.monotonic()
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, bufsize=0)
    except OSError as exc:
        info.update(runner_error=f'exec failed: {exc}', elapsed_seconds=round(time.monotonic()-start, 3))
        return info
    readers = [threading.Thread(target=_read_pipe, args=(proc.stdout, out/'stdout.log', out/'stdout.tail.log', state, lock, 'stdout'), daemon=True),
               threading.Thread(target=_read_pipe, args=(proc.stderr, out/'stderr.log', out/'stderr.tail.log', state, lock, 'stderr'), daemon=True)]
    for thread in readers: thread.start()
    deadline, reason = start + timeout, None
    interrupted = []
    previous = {}
    def handle(sig, _frame):
        interrupted.append(sig); _kill_group(proc.pid)
    for sig in (signal.SIGTERM, signal.SIGINT):
        previous[sig] = signal.getsignal(sig); signal.signal(sig, handle)
    while proc.poll() is None or any(t.is_alive() for t in readers):
        info['rss_peak_kib'] = max(info['rss_peak_kib'], _group_rss_kib(proc.pid))
        with lock:
            if state['stdout_cap']: reason = 'stdout_cap'
            elif state['stderr_cap']: reason = 'stderr_cap'
        if export_path is not None:
            try:
                if export_path.exists() and export_path.stat().st_size > EXPORT_CAP: reason = 'export_cap'
            except OSError: pass
        if info['rss_peak_kib'] > RSS_CAP_KIB: reason = 'rss_cap'
        if time.monotonic() >= deadline:
            info['timed_out'] = True; reason = reason or 'timeout'
        if reason:
            info['termination_reason'] = reason; _kill_group(proc.pid); break
        time.sleep(.05)
    for sig, handler in previous.items(): signal.signal(sig, handler)
    if proc.poll() is None: _kill_group(proc.pid, 0)
    code = proc.wait()
    for thread in readers: thread.join(timeout=2)
    info.update(original_exit_code=code, signal=(-code if code < 0 else None),
                stdout_truncated=state['stdout_cap'], stderr_truncated=state['stderr_cap'],
                output_truncated=state['stdout_cap'] or state['stderr_cap'],
                output_bytes=state['stdout_bytes']+state['stderr_bytes'],
                elapsed_seconds=round(time.monotonic()-start, 3), rss_cap_kib=RSS_CAP_KIB)
    if interrupted:
        info['interrupted_by_signal'] = interrupted[-1]; info['termination_reason'] = 'external_signal'
    return info


def cap_export_snapshot(path: Path) -> dict[str, Any]:
    try:
        size = path.stat().st_size
        if size <= EXPORT_CAP: return {'size_bytes': size, 'truncated': False}
        snapshot = path.with_name(path.name + '.oversize-head')
        with path.open('rb') as src, snapshot.open('wb') as dst:
            dst.write(src.read(EXPORT_CAP))
        path.unlink()
        return {'size_bytes': size, 'truncated': True, 'snapshot_path': str(snapshot)}
    except OSError as exc:
        return {'snapshot_error': f'{type(exc).__name__}: {exc}'}


def _schema_validate(value: Any) -> list[str]:
    script = REPO / 'scripts/validate_json_export.py'
    schema_path = REPO / 'tests/json-handler/schema-validation/kani_json_schema.json'
    try:
        spec = importlib.util.spec_from_file_location('kani_json_export_validator', script)
        if spec is None or spec.loader is None: return ['validator unavailable']
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        return module.validate_document(value, json.loads(schema_path.read_text(encoding='utf-8')))
    except Exception as exc: return [f'schema validation unavailable: {exc}']


def _contract_matches(actual: Any, wanted: str | None) -> bool:
    if wanted is None: return actual is None
    if not isinstance(actual, dict): return False
    value = actual.get('contracted_function_name')
    return isinstance(value, str) and (value == wanted or value.endswith('::' + wanted))


def _names_match(actual: Any, wanted: list[str]) -> bool:
    if not isinstance(actual, list): return False
    def tail(name: Any) -> Any:
        return name.rsplit('::', 1)[-1] if isinstance(name, str) else name
    return sorted(map(tail, actual)) == sorted(map(tail, wanted))


def parse_export(path: Path, row: dict[str, Any], source: Path, run: dict[str, Any]) -> dict[str, Any]:
    base = {'outcome': 'UNKNOWN', 'state': 'UNKNOWN', 'proof_credit': 'NONE'}
    if (run.get('timed_out') or run.get('output_truncated') or run.get('termination_reason') or
            run.get('runner_error') or run.get('original_exit_code') is None):
        return {**base, 'state': 'EXECUTION_INCOMPLETE', 'reason': run.get('termination_reason')}
    try:
        size = path.stat().st_size
        if size > EXPORT_CAP: return {**base, 'state': 'OVERSIZE', 'size_bytes': size}
        value = json.loads(path.read_bytes())
    except FileNotFoundError: return {**base, 'state': 'MISSING'}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {**base, 'state': 'INVALID_OR_PARTIAL', 'error': str(exc)}
    if value is None: return {**base, 'state': 'NULL'}
    if not isinstance(value, dict): return {**base, 'state': 'WRONG_TOP_LEVEL_TYPE'}
    errors = _schema_validate(value)
    if errors: return {**base, 'state': 'SCHEMA_INVALID', 'schema_errors': errors[:20]}
    if value.get('schema_version') != '0.1.0' or value.get('run_state') != 'COMPLETE':
        return {**base, 'state': 'INCOMPLETE_EXPORT'}
    if value.get('kani_commit') != PIN['sha'] or value.get('kani_commit_dirty') is not False:
        return {**base, 'state': 'TOOL_PIN_MISMATCH'}
    if (value['harness_selection'] != {'requested_filters': [row['harness']], 'exact': True,
                                       'unmatched_filters': [], 'matched_count': 1} or
            len(value['harnesses']) != 1): return {**base, 'state': 'SELECTION_MISMATCH'}
    h = value['harnesses'][0]
    if h['name'] != row['harness']: return {**base, 'state': 'SELECTION_MISMATCH'}
    file_value = Path(h['file'])
    if not file_value.is_absolute(): file_value = Path(run['cwd']) / file_value
    if file_value.resolve() != source.resolve(): return {**base, 'state': 'SOURCE_FILE_MISMATCH'}
    kind = h['attributes']['kind']
    kind_ok = kind == 'Proof' if row['kind'] == 'Proof' else (
        isinstance(kind, dict) and isinstance(kind.get('ProofForContract'), dict) and
        isinstance(kind['ProofForContract'].get('target_fn'), str) and
        (kind['ProofForContract']['target_fn'] == row['contract'] or
         kind['ProofForContract']['target_fn'].endswith('::' + row['contract'])))
    if (not kind_ok or not _contract_matches(h['contract'], row['contract']) or
            not _names_match(h['attributes']['verified_stubs'], row['verified_stubs']) or
            h['attributes']['stubs'] != [] or h['attributes']['should_panic'] is not False or
            h['is_automatically_generated'] is not False):
        return {**base, 'state': 'HARNESS_METADATA_MISMATCH'}
    summary, checks, outcome = value['summary'], h['checks'], h['outcome']
    complete_kind = outcome['kind'] == 'COMPLETED'
    verdict = outcome.get('verdict') if complete_kind else None
    if (summary['total'] != 1 or summary['successful'] != int(verdict == 'SUCCESS') or
            summary['failed'] != int(verdict == 'FAILURE') or
            summary['checks_total'] != checks['total'] or summary['checks_success'] != checks['success'] or
            summary['covers_total'] != h['covers']['total'] or
            summary['covers_satisfied'] != len(h['covers']['satisfied'])):
        return {**base, 'state': 'SUMMARY_MISMATCH'}
    if not isinstance(value.get('tools', {}).get('kani'), str): return {**base, 'state': 'MISSING_TOOL_VERSION'}
    features = set(value['enabled_unstable_features'])
    expected_features = {'export-json'} | set(row['flags'][1::2])
    if features != expected_features: return {**base, 'state': 'FEATURE_MISMATCH', 'features': sorted(features)}
    if any(value['configuration']['checks'].get(k) is not True for k in
           ('memory_safety', 'overflow', 'unwinding', 'undefined_function', 'assert_contracts')):
        return {**base, 'state': 'CONFIGURATION_MISMATCH'}
    if (value['configuration']['checks'].get('prove_safety_only') is not False or
            value['configuration'].get('cbmc_args') != [] or value.get('harness_timeout_s') is not None):
        return {**base, 'state': 'CONFIGURATION_MISMATCH'}
    if run.get('original_exit_code') == 0 and verdict == 'SUCCESS':
        covers = h['covers']
        if (checks['total'] <= 0 or checks['success'] != checks['total'] or
                any(checks[k] for k in ('failure', 'unreachable', 'undetermined', 'error', 'unknown', 'other')) or
                h.get('failure_kind') != 'NONE' or h.get('n_failed') != 0 or
                h.get('unsupported_constructs') or h.get('n_properties') != checks['total'] + covers['total'] or
                covers['total'] != 0 or any(covers[k] for k in ('satisfied','unsatisfiable','unreachable',
                    'undetermined','error','unknown','other'))):
            return {**base, 'state': 'INCONSISTENT_SUCCESS'}
        observed = 'SUCCESS'
        return {**base, 'state': 'VALIDATED', 'outcome': observed,
                'expected': row['expected'], 'expected_match': row['expected'] == observed}
    if type(run.get('original_exit_code')) is not int or run['original_exit_code'] <= 0 or run.get('signal') is not None or verdict != 'FAILURE':
        return {**base, 'state': 'PROCESS_EXIT_MISMATCH'}
    failed = h['failed_properties']
    ids = checks['failure']
    unsupported = h.get('unsupported_constructs', [])
    failed_ids = {p['id'] for p in failed}
    covers = h['covers']
    expected_class = 'unsupported_construct' if row['expected'] == 'COPY_UNSUPPORTED' else 'safety_check'
    status_map = {p['id']: p['status'] for p in failed}
    for key, status_name in (('unreachable','UNREACHABLE'),('undetermined','UNDETERMINED'),
                             ('error','ERROR'),('unknown','UNKNOWN')):
        status_map.update({item:status_name for item in checks[key]})
    status_map.update({item['id']:item['status'] for item in checks['other']})
    all_status_ids = (list(failed_ids) + checks['unreachable'] + checks['undetermined'] +
                      checks['error'] + checks['unknown'] + [x['id'] for x in checks['other']])
    if (not failed or failed_ids != set(ids) or h.get('n_failed') != len(failed) or
            h.get('n_properties') != checks['total'] + h['covers']['total'] or
            len(ids) != len(set(ids)) or covers['total'] != 0 or
            any(covers[k] for k in ('satisfied','unsatisfiable','unreachable','undetermined','error','unknown','other')) or
            checks['success'] + len(failed) + len(checks['unreachable']) != checks['total'] or
            any(checks[k] for k in ('undetermined', 'error', 'unknown', 'other')) or
            len(failed_ids) != len(failed) or len(set(all_status_ids)) != len(all_status_ids) or
            any(p.get('status') != 'FAILURE' or p.get('class') != expected_class for p in failed) or
            any(status_map.get(p.get('id')) != p.get('status') for p in unsupported)):
        return {**base, 'state': 'UNBOUND_FAILURE', 'failed_properties': failed,
                'unsupported_constructs': unsupported}
    descriptions = [p.get('description') for p in failed]
    if row['expected'] == 'COPY_UNSUPPORTED' and all(d == row['failure_description'] for d in descriptions):
        observed = 'COPY_UNSUPPORTED'
    elif row['expected'] == 'UNINIT_FAILURE' and all(d == row['failure_description'] for d in descriptions):
        observed = 'UNINIT_FAILURE'
    else:
        return {**base, 'state': 'UNCLASSIFIED_FAILURE', 'failed_properties': failed,
                'unsupported_constructs': unsupported}
    return {**base, 'state': 'VALIDATED_FAILURE_OBSERVATION', 'outcome': observed,
            'expected': row['expected'], 'expected_match': observed == row['expected'],
            'failed_properties': failed, 'unreachable_ids': checks['unreachable'],
            'unsupported_constructs': unsupported}


def _identity(row: dict[str, Any], request_sha: str, rows_sha: str, tool: dict[str, str], source: Path) -> dict[str, Any]:
    return {'id': row['id'], 'file': str(source.resolve()), 'file_sha256': sha256(source),
            'harness': row['harness'], 'flags': row['flags'], 'expected': row['expected'],
            'desired': row['desired'], 'proof_credit': 'NONE', 'pin': 'upstream', 'tool': tool,
            'request_sha256': request_sha, 'rows_sha256': rows_sha, 'attempt': 1}


def build(tool: Path, out: Path) -> int:
    started, run = time.monotonic(), None
    try:
        request, request_sha = load_request()
        binding, env = verify_tool(tool), _guard_env()
        argv = ['cargo', 'build-dev', '--', '--release']
        run = execute(argv, tool.resolve(), out/'build', BUILD_SECONDS, env)
        final = verify_tool(tool)
        status = 'COMPLETE' if run.get('original_exit_code') == 0 and not run.get('termination_reason') and not run.get('runner_error') and binding == final else 'FAILED'
        record = {'status': status, 'pin': 'upstream', 'tool': binding, 'tool_after': final,
                  'request_sha256': request_sha, 'argv': argv, 'cwd': str(tool.resolve()), 'run': run}
    except Exception as exc:
        record = {'status': 'FAILED', 'pin': 'upstream', 'error': f'{type(exc).__name__}: {exc}'}
        if run is not None: record['run'] = run
    record['elapsed_seconds'] = round(time.monotonic()-started, 3)
    out.mkdir(parents=True, exist_ok=True)
    (out/'build.json').write_text(json.dumps(record, indent=2, sort_keys=True)+'\n')
    return 0 if record['status'] == 'COMPLETE' else 1


def run_rows(tool: Path, out: Path) -> int:
    started, receipts = time.monotonic(), []
    out.mkdir(parents=True, exist_ok=True)
    status_path = out/'run.json'
    try:
        request, request_sha = load_request()
        binding = verify_tool(tool)
        rows, rows_sha = load_rows(request)
        build_record = json.loads((out/'build.json').read_text())
        build_run = build_record.get('run', {})
        if (build_record.get('status') != 'COMPLETE' or build_record.get('pin') != 'upstream' or
                build_record.get('request_sha256') != request_sha or build_record.get('tool') != binding or
                build_run.get('original_exit_code') != 0 or build_run.get('signal') is not None or
                any(build_run.get(k) for k in ('termination_reason','runner_error','timed_out','output_truncated'))):
            raise RunnerError('matching successful build receipt is required')
        env = _guard_env()
    except Exception as exc:
        status_path.write_text(json.dumps({'status':'FAILED', 'error':f'{type(exc).__name__}: {exc}',
                                           'proof_credit':'NONE'}, indent=2)+'\n')
        return 1
    def persist(status: str, **extra: Any) -> None:
        status_path.write_text(json.dumps({'status':status, 'pin':'upstream', 'tool':binding,
            'request_sha256':request_sha, 'rows_sha256':rows_sha, 'phase_cap_seconds':PHASE_SECONDS,
            'receipts':receipts, 'proof_credit':'NONE', **extra}, indent=2, sort_keys=True)+'\n')
    persist('RUNNING')
    for row in rows:
        source = (HERE / row['file']).resolve()
        entry = _identity(row, request_sha, rows_sha, binding, source)
        slot = out/'rows'/row['id']
        if sha256(source) != _row_payload_hash(request, row['file']):
            entry.update(status='NOT_RUN', reason='source SHA drift after request validation')
            receipts.append(entry); persist('RUNNING'); continue
        remaining = PHASE_SECONDS - (time.monotonic() - started)
        if remaining < ROW_SECONDS:
            entry.update(status='NOT_RUN', reason='insufficient phase envelope')
            receipts.append(entry); persist('RUNNING'); continue
        slot.mkdir(parents=True, exist_ok=True)
        row_path, export_path = slot/'receipt.json', (slot/'export.json').resolve()
        argv = [str((tool.resolve()/'scripts/kani').resolve()), *row['flags'], '--harness', row['harness'],
                '--exact', str(source), '-Z', 'export-json', '--export-json', str(export_path)]
        entry.update(status='RUNNING', cwd=str(slot.resolve()), argv=argv, export_path=str(export_path))
        receipts.append(entry); row_path.write_text(json.dumps(entry, indent=2, sort_keys=True)+'\n'); persist('RUNNING')
        try:
            run = execute(argv, slot.resolve(), slot, min(ROW_SECONDS, int(remaining)), env, export_path)
            entry.update(argv=argv, run=run, export_path=str(export_path))
            entry['status'] = 'EXECUTED'
            row_path.write_text(json.dumps(entry, indent=2, sort_keys=True)+'\n')
            entry['export_snapshot'] = cap_export_snapshot(export_path)
            if entry['export_snapshot'].get('truncated'):
                parsed = {'state':'OVERSIZE', 'outcome':'UNKNOWN', 'proof_credit':'NONE'}
            else:
                parsed = parse_export(export_path, row, source, run)
            entry.update(status='OBSERVED', export=parsed)
        except Exception as exc:
            entry.update(status='ERROR', error=f'{type(exc).__name__}: {exc}',
                         export={'state':'RUNNER_EXCEPTION','outcome':'UNKNOWN','proof_credit':'NONE'})
        row_path.write_text(json.dumps(entry, indent=2, sort_keys=True)+'\n')
        persist('RUNNING', elapsed_seconds=round(time.monotonic()-started, 3))
        if entry.get('run', {}).get('interrupted_by_signal'):
            persist('INTERRUPTED'); return 1
    try:
        final = verify_tool(tool)
    except Exception as exc:
        persist('ERROR', tool_after_error=f'{type(exc).__name__}: {exc}',
                elapsed_seconds=round(time.monotonic()-started, 3))
        return 1
    successful = all(x.get('status') == 'OBSERVED' and x.get('export', {}).get('expected_match') is True
                     for x in receipts) and len(receipts) == len(rows)
    persist('COMPLETE' if successful else 'COMPLETE_WITH_UNEXPECTED', tool_after=final,
            elapsed_seconds=round(time.monotonic()-started, 3))
    return 0 if successful else 1


def fallback(out: Path) -> int:
    out.mkdir(parents=True, exist_ok=True)
    request, request_sha = load_request()
    rows, rows_sha = load_rows(request)
    path = out/'run.json'
    try: existing = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError): existing = {}
    known = {}
    if isinstance(existing, dict) and isinstance(existing.get('receipts'), list):
        known = {(x.get('id')): x for x in existing['receipts'] if isinstance(x, dict) and isinstance(x.get('id'), str)}
    for row in rows:
        slot = out/'rows'/row['id']/'receipt.json'
        try:
            rec = json.loads(slot.read_text(encoding='utf-8'))
            if isinstance(rec, dict) and rec.get('id') == row['id']: known[row['id']] = rec
        except (OSError, UnicodeDecodeError, json.JSONDecodeError): pass
    missing = []
    for row in rows:
        if row['id'] not in known:
            rec = _identity(row, request_sha, rows_sha, {'pin':'upstream','sha':PIN['sha'],'tree':PIN['tree']}, HERE/row['file'])
            rec.update(status='NOT_RUN', reason='fallback synthesized missing receipt')
            missing.append(rec)
        elif known[row['id']].get('status') in ('RUNNING','EXECUTED'):
            known[row['id']]['status'] = 'UNKNOWN'
            known[row['id']]['reason'] = 'fallback preserved in-progress receipt as UNKNOWN'
    (out/'missing-not-run.json').write_text(json.dumps({'status':'FALLBACK_MISSING_ONLY','pin':'upstream',
        'request_sha256':request_sha,'rows_sha256':rows_sha,'receipts':missing,'proof_credit':'NONE'},
        indent=2,sort_keys=True)+'\n')
    (out/'recovered-receipts.json').write_text(json.dumps({'status':'FALLBACK_RECOVERED','receipts':list(known.values()),
        'proof_credit':'NONE'},indent=2,sort_keys=True)+'\n')
    cleanup = []
    try:
        targets = [p for p in out.rglob('target') if p.is_dir() and out.resolve() in p.resolve().parents]
        for target in sorted(targets, key=lambda p: len(p.parts), reverse=True):
            if not target.is_symlink(): shutil.rmtree(target)
        cleanup.append({'status':'REMOVED_OR_ABSENT','targets':[str(p) for p in targets]})
    except OSError as exc: cleanup.append({'status':'ERROR','error':f'{type(exc).__name__}: {exc}'})
    (out/'job-status.json').write_text(json.dumps({'status':'FALLBACK', 'pin':'upstream',
        'preserved_run_status':existing.get('status') if isinstance(existing,dict) else None,
        'incomplete_receipts':[{'id':x.get('id'),'original_status':x.get('status'),'outcome':'UNKNOWN'}
                               for x in known.values() if x.get('status') not in ('OBSERVED','NOT_RUN','ERROR')],
        'target_cleanup':cleanup,'proof_credit':'NONE'},indent=2,sort_keys=True)+'\n')
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for cmd in ('build','run'):
        p = sub.add_parser(cmd); p.add_argument('--tool', required=True, type=Path); p.add_argument('--out', required=True, type=Path)
    p = sub.add_parser('fallback'); p.add_argument('--out', required=True, type=Path)
    args = parser.parse_args(argv)
    if args.command == 'build': return build(args.tool, args.out)
    if args.command == 'run': return run_rows(args.tool, args.out)
    try: return fallback(args.out)
    except Exception as exc:
        print(f'fallback failed: {type(exc).__name__}: {exc}', file=sys.stderr); return 1


if __name__ == '__main__': raise SystemExit(main())
