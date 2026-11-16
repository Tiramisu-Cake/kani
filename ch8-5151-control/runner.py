#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Run bounded, pinned Kani issue-5151 observations with explicit UNKNOWN states."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

CONTROL = Path(__file__).resolve().parent
ROOT = CONTROL.parent
ROWS = json.loads((CONTROL / 'rows.json').read_text())
PINS = {
    'stock': {'repository': 'model-checking/kani', 'sha': '0aac16ef62da9e9d5645782d458593e5d78143ba', 'tree': '9d8bc9312bf955ef126d32b819b3cd0ed105ed2b'},
    'prototype': {'repository': 'Tiramisu-Cake/kani', 'sha': '8e299aa6243bc5f06a29c51e98aafa9564478220', 'tree': '9829702c1aa0ecb73c860fc0ad5451757917d6cb'},
}
ROW_SECONDS = 60
BUILD_SECONDS = 1800
EXPORT_LIMIT = 8 * 1024 * 1024
LOG_LIMIT = 128 * 1024
STOCK_UNSUPPORTED_DIAGNOSTIC = ('Checking memory initialization of type [std::mem::MaybeUninit<D>; 2] is not supported. '
    'Cannot determine layout for a type that contains union of type std::mem::MaybeUninit<D> as a field.')


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def git(tool, *args):
    return subprocess.run(['git', '-C', str(tool), *args], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.strip()


def tool_identity(tool, pin_name):
    pin = PINS[pin_name]
    identity = {'repository': pin['repository'], 'sha': git(tool, 'rev-parse', 'HEAD'),
                'tree': git(tool, 'rev-parse', 'HEAD^{tree}'),
                'dirty': bool(git(tool, 'status', '--porcelain=v1', '--untracked-files=no'))}
    if (identity['sha'], identity['tree'], identity['dirty']) != (pin['sha'], pin['tree'], False):
        raise ValueError('tool checkout identity or clean tracked state mismatch')
    return identity


def version(argv, cwd):
    try:
        result = subprocess.run(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=15, check=False, text=True)
        return {'command': argv, 'cwd': str(cwd.resolve()), 'exit_code': result.returncode,
                'output': result.stdout[:4096]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'command': argv, 'cwd': str(cwd.resolve()), 'error': f'{type(exc).__name__}: {exc}'}


def versions_before_build(tool):
    return {label: version(argv, tool) for label, argv in (
        ('rustc', ['rustc', '--version']), ('cbmc', ['cbmc', '--version']))}


def harness_environment(row):
    if row.get('compile_flags') != ['--edition', '2021']:
        raise ValueError('harness requires the pinned Rust 2021 compiler flags')
    env = os.environ.copy()
    env['RUSTFLAGS'] = ' '.join(row['compile_flags'])
    return env


def run_harness(argv, cwd, out, row):
    return bounded_run(argv, cwd, out, ROW_SECONDS, env=harness_environment(row))


def bounded_run(argv, cwd, out, timeout, env=None):
    out.mkdir(parents=True, exist_ok=True)
    record = {'command': argv, 'cwd': str(cwd.resolve()), 'exit_code': None, 'timed_out': False,
              'timeout_seconds': timeout, 'started': True}
    if env is not None:
        record['compiler_environment'] = {'RUSTFLAGS': env.get('RUSTFLAGS', '')}
    started = time.monotonic()
    stdout_path, stderr_path = out / 'stdout.spool', out / 'stderr.spool'
    with stdout_path.open('wb') as stdout_file, stderr_path.open('wb') as stderr_file:
        try:
            proc = subprocess.Popen(argv, cwd=cwd, stdout=stdout_file, stderr=stderr_file,
                                    start_new_session=True, env=env)
        except OSError as exc:
            record.update(runner_error=f'{type(exc).__name__}: {exc}', original_exit_code=None,
                          elapsed_seconds=round(time.monotonic() - started, 3),
                          stdout_bytes=0, stderr_bytes=0, stdout_truncated=False, stderr_truncated=False,
                          stdout_excerpt='', stderr_excerpt='')
            return record
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            record['timed_out'] = True
            try: os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError: pass
            grace_deadline = time.monotonic() + 2
            while time.monotonic() < grace_deadline:
                try:
                    os.killpg(proc.pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(.05)
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait()
    def bounded(path):
        size = path.stat().st_size
        with path.open('rb') as stream:
            head = stream.read(LOG_LIMIT)
            if size > LOG_LIMIT:
                stream.seek(max(0, size - 4096))
                data = head + b'\n[tail]\n' + stream.read()
            else: data = head
        return size, size > LOG_LIMIT, data
    out_size, out_truncated, out_data = bounded(stdout_path)
    err_size, err_truncated, err_data = bounded(stderr_path)
    (out / 'stdout.log').write_bytes(out_data)
    (out / 'stderr.log').write_bytes(err_data)
    stdout_path.unlink(); stderr_path.unlink()
    record.update(exit_code=proc.returncode, original_exit_code=proc.returncode,
                  elapsed_seconds=round(time.monotonic() - started, 3),
                  stdout_bytes=out_size, stderr_bytes=err_size,
                  stdout_truncated=out_truncated, stderr_truncated=err_truncated,
                  stdout_excerpt=out_data.decode('utf-8', 'replace'),
                  stderr_excerpt=err_data.decode('utf-8', 'replace'))
    return record


def status_from_export(path, row, source, run, pin_name):
    unknown = {'outcome': 'UNKNOWN', 'proof_credit': 'NONE'}
    if (run['timed_out'] or run['exit_code'] is None or run.get('runner_error') or
            run['stdout_truncated'] or run['stderr_truncated']):
        return {**unknown, 'state': 'EXECUTION_INCOMPLETE'}
    output = run['stdout_excerpt'] + run['stderr_excerpt']
    unsupported = STOCK_UNSUPPORTED_DIAGNOSTIC in output
    residue = output.replace(STOCK_UNSUPPORTED_DIAGNOSTIC, '')
    unrelated_fatal = any(re.search(
        r'^\s*(?:error(?:\[[^]]+\])?:|fatal error|internal compiler error|thread .+ panicked at|could not compile)',
        line.lower()) for line in residue.splitlines())
    if unsupported and not unrelated_fatal and type(run['exit_code']) is int and run['exit_code'] > 0:
        return {'outcome': 'UNSUPPORTED_UNION', 'state': 'UNSUPPORTED_UNION',
                'diagnostic': 'MaybeUninit union layout unsupported', 'proof_credit': 'NONE'}
    if pin_name == 'stock':
        return {**unknown, 'state': 'UNCLASSIFIED_STOCK_RESULT'}
    try:
        if path.stat().st_size > EXPORT_LIMIT:
            return {**unknown, 'state': 'EXPORT_OVERSIZE'}
        value = json.loads(path.read_text())
    except FileNotFoundError:
        return {**unknown, 'state': 'EXPORT_MISSING'}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {**unknown, 'state': 'EXPORT_INVALID_OR_PARTIAL'}
    if not isinstance(value, dict): return {**unknown, 'state': 'EXPORT_WRONG_TYPE'}
    if value.get('schema_version') != '0.1.0' or value.get('run_state') != 'COMPLETE':
        return {**unknown, 'state': 'EXPORT_INCOMPLETE'}
    pin = PINS[pin_name]
    if value.get('kani_commit') != pin['sha'] or value.get('kani_commit_dirty') is not False:
        return {**unknown, 'state': 'TOOL_PIN_MISMATCH'}
    selection = value.get('harness_selection')
    harnesses = value.get('harnesses')
    if (not isinstance(selection, dict) or selection.get('requested_filters') != [row['harness']]
            or selection.get('exact') is not True or selection.get('unmatched_filters') != []
            or selection.get('matched_count') != 1 or not isinstance(harnesses, list)
            or len(harnesses) != 1):
        return {**unknown, 'state': 'HARNESS_SELECTION_MISMATCH'}
    harness = harnesses[0]
    filename = harness.get('file')
    if not isinstance(filename, str) or harness.get('name') != row['harness']:
        return {**unknown, 'state': 'HARNESS_METADATA_MISMATCH'}
    file_path = Path(filename)
    if not file_path.is_absolute(): file_path = Path(run['cwd']) / file_path
    if file_path.resolve() != source.resolve(): return {**unknown, 'state': 'SOURCE_STAGE_TARGET_MISMATCH'}
    outcome = harness.get('outcome')
    checks, summary, covers = harness.get('checks'), value.get('summary'), harness.get('covers')
    if not all(isinstance(x, dict) for x in (outcome, checks, summary, covers)):
        return {**unknown, 'state': 'EXPORT_METADATA_MISSING'}
    list_fields = ('failure', 'unreachable', 'undetermined', 'error', 'unknown', 'other')
    if any(not isinstance(checks.get(k), list) for k in list_fields):
        return {**unknown, 'state': 'EXPORT_CHECKS_MALFORMED'}
    if (type(checks.get('total')) is not int or type(checks.get('success')) is not int or
            type(harness.get('n_failed')) is not int or type(harness.get('n_properties')) is not int or
            not isinstance(harness.get('failed_properties'), list) or
            not isinstance(harness.get('unsupported_constructs'), list) or
            type(covers.get('total')) is not int or type(summary.get('total')) is not int):
        return {**unknown, 'state': 'EXPORT_COUNTERS_MISSING'}
    if (summary.get('checks_total') != checks['total'] or summary.get('checks_success') != checks['success'] or
            summary.get('covers_total') != covers['total'] or
            summary.get('covers_satisfied') != len(covers.get('satisfied', [])) or
            harness['n_properties'] != checks['total'] + covers['total']):
        return {**unknown, 'state': 'EXPORT_SUMMARY_MISMATCH'}
    if isinstance(outcome, dict) and outcome.get('kind') == 'COMPLETED' and outcome.get('verdict') == 'SUCCESS' and run['exit_code'] == 0:
        if (checks.get('total', 0) > 0 and checks.get('success') == checks.get('total') and
                checks.get('failure') == [] and checks.get('unreachable') == [] and
                checks.get('undetermined') == [] and checks.get('error') == [] and
                checks.get('unknown') == [] and checks.get('other') == [] and
                not harness.get('unsupported_constructs') and harness.get('n_failed') == 0 and
                harness.get('failure_kind') == 'NONE' and summary.get('total') == 1 and
                summary.get('successful') == 1 and summary.get('failed') == 0):
            return {'outcome': 'SUCCESS', 'state': 'VALIDATED_SUCCESS', 'proof_credit': 'NONE'}
        return {**unknown, 'state': 'SUCCESS_SUMMARY_MISMATCH'}
    if isinstance(outcome, dict) and outcome.get('kind') == 'COMPLETED' and outcome.get('verdict') == 'FAILURE':
        failed = harness.get('failed_properties')
        if (isinstance(failed, list) and failed and all(isinstance(p, dict) for p in failed) and
                checks.get('failure') == [p.get('id') for p in failed] and
                all(p.get('status') == 'FAILURE' and p.get('class') == 'safety_check' for p in failed) and
                not harness.get('unsupported_constructs') and checks.get('undetermined') == [] and
                checks.get('error') == [] and checks.get('unknown') == [] and checks.get('other') == [] and
                checks.get('success', 0) + len(failed) + len(checks['unreachable']) == checks['total'] and
                harness['n_failed'] == len(failed) and summary.get('total') == 1 and
                summary.get('successful') == 0 and summary.get('failed') == 1 and
                type(run['exit_code']) is int and run['exit_code'] > 0):
            expected_function = (row['harness'], '::drop', 'read_volatile') if row.get('harness') == 'read_in_drop_of_uninit_slot' else (row['harness'], '::drop', 'drop_in_place')
            descriptions = {
                'read_in_drop_of_uninit_slot': (
                    'Undefined Behavior: Reading from an uninitialized pointer of type `u8`',
                    'Undefined Behavior: Reading from an uninitialized pointer of type `*const u8`'),
                'drop_uninit_in_array': (
                    'Undefined Behavior: Reading from an uninitialized pointer of type `D`',
                    'Undefined Behavior: Reading from an uninitialized pointer of type `*mut D`')}
            if any(not isinstance(p.get('id'), str) or not any(part in p['id'] for part in expected_function)
                   or p.get('description') not in descriptions[row['harness']] for p in failed):
                return {**unknown, 'state': 'FAILURE_TARGET_MISMATCH'}
            return {'outcome': 'UNINIT_FAILURE', 'state': 'VALIDATED_FAILURE', 'proof_credit': 'NONE',
                    'failed_properties': failed}
    return {**unknown, 'state': 'UNCLASSIFIED_EXPORT_RESULT'}


def guard(pin_name):
    if os.environ.get('GITHUB_REPOSITORY') != 'Tiramisu-Cake/kani': raise ValueError('repository guard failed')
    if os.environ.get('GITHUB_EVENT_NAME') != 'push' or os.environ.get('GITHUB_RUN_ATTEMPT') != '1': raise ValueError('event/attempt guard failed')
    if not os.environ.get('GITHUB_REF', '').startswith('refs/heads/uninit-ci/ch8-5151-'): raise ValueError('branch guard failed')
    for key in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'KANI_FLAGS', 'KANI_OPTS'):
        if os.environ.get(key, '').strip(): raise ValueError(f'refusing inherited {key}')
    for key in ('KANI_ATTEMPT', 'SMALLSORT_ATTEMPT'):
        if key in os.environ and os.environ[key] != '1': raise ValueError(f'refusing {key} other than attempt 1')
    os.environ['KANI_ATTEMPT'] = '1'
    return pin_name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('build', 'run', 'fallback'))
    parser.add_argument('--tool', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--pin', choices=PINS)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    if args.mode == 'fallback':
        report = args.out / 'run.json'
        try: prior = json.loads(report.read_text())
        except (OSError, json.JSONDecodeError): prior = {}
        receipts = []
        for row in ROWS:
            receipt_path = args.out / 'rows' / row['id'] / 'receipt.json'
            try: receipt = json.loads(receipt_path.read_text())
            except (OSError, json.JSONDecodeError): receipt = None
            if not isinstance(receipt, dict):
                receipt = {'id': row['id'], 'status': 'NOT_RUN', 'outcome': 'UNKNOWN', 'reason': 'row never started', 'proof_credit': 'NONE'}
            elif receipt.get('status') == 'RUNNING':
                receipt.update(status='UNKNOWN', outcome='UNKNOWN', reason='job ended during row execution')
            receipts.append(receipt)
        (args.out / 'fallback.json').write_text(json.dumps({'rows': receipts, 'proof_credit': 'NONE'}, indent=2) + '\n')
        return 0
    if args.tool is None or args.pin is None: parser.error('--tool and --pin are required')
    tool, pin_name = args.tool.resolve(), guard(args.pin)
    before = tool_identity(tool, pin_name)
    if args.mode == 'build':
        versions_before = versions_before_build(tool)
        run = bounded_run(['cargo', 'build-dev', '--', '--release'], tool, args.out / 'build', BUILD_SECONDS)
        after = tool_identity(tool, pin_name)
        status = 'COMPLETE' if run['exit_code'] == 0 and not run['timed_out'] and before == after else 'FAILED'
        versions_after = {}
        if status == 'COMPLETE':
            versions_after['kani'] = version([str(tool / 'scripts/kani'), '--version'], tool)
            versions_after['rustc'] = version(['rustc', '--version'], tool)
            versions_after['cbmc'] = version(['cbmc', '--version'], tool)
        record = {'status': status, 'pin': PINS[pin_name], 'tool_before': before, 'tool_after': after,
                  'versions_before_build': versions_before, 'versions_after_build': versions_after,
                  'run': run, 'proof_credit': 'NONE'}
        (args.out / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
        return 0 if record['status'] == 'COMPLETE' else 1
    build = json.loads((args.out / 'build.json').read_text())
    if build.get('status') != 'COMPLETE' or build.get('tool_after') != before or build.get('pin') != PINS[pin_name]:
        raise ValueError('matching successful build receipt required')
    request = json.loads((CONTROL / 'CI-REQUEST.json').read_text())
    request_sha = __import__('hashlib').sha256((CONTROL / 'CI-REQUEST.json').read_bytes()).hexdigest()
    receipts = []
    def persist(status):
        (args.out / 'run.json').write_text(json.dumps({'status': status, 'pin': PINS[pin_name],
            'tool_before': before, 'request_sha256': request_sha, 'rows': receipts,
            'proof_credit': 'NONE'}, indent=2) + '\n')
    persist('RUNNING')
    for row in ROWS:
        source = ROOT / row['file']
        frozen_source_hash = request['payload_sha256'][row['file']]
        entry = {'id': row['id'], 'source': str(source.resolve()), 'source_sha256': sha(source),
                 'harness': row['harness'], 'flags': row['flags'], 'compile_flags': row['compile_flags'],
                 'expected': row['expected_stock' if pin_name == 'stock' else 'expected_prototype'],
                 'frozen_source_sha256': frozen_source_hash, 'request_sha256': request_sha,
                 'pin': PINS[pin_name], 'tool_before': before, 'versions': build.get('versions_after_build', {}),
                 'proof_credit': 'NONE'}
        slot = args.out / 'rows' / row['id']
        export = slot / 'export.json'
        argv = [str(tool / 'scripts/kani'), '-Z', 'uninit-checks', '--harness', row['harness'], '--exact', str(source),
                '-Z', 'export-json', '--export-json', str(export)]
        entry['command'] = argv
        entry['cwd'] = str(slot.resolve())
        slot.mkdir(parents=True, exist_ok=True)
        if entry['source_sha256'] != frozen_source_hash:
            entry.update(status='UNKNOWN', outcome='UNKNOWN', reason='source hash differs from frozen request', expected_match=False)
        else:
            entry.update(status='RUNNING')
            (slot / 'receipt.json').write_text(json.dumps(entry, indent=2) + '\n')
            receipts.append(entry); persist('RUNNING')
            run = run_harness(argv, slot, slot, row)
            entry['run'] = run
            if export.exists():
                export_size = export.stat().st_size
                entry['export'] = {'path': str(export.resolve()), 'size_bytes': export_size,
                                   'sha256': sha(export), 'retained': export_size <= EXPORT_LIMIT}
            entry['observation'] = status_from_export(export, row, source, run, pin_name)
            if export.exists() and export.stat().st_size > EXPORT_LIMIT: export.unlink()
            observed = entry['observation']['outcome']
            if pin_name == 'prototype' and row['id'] == 'original-empty-drop':
                accepted = observed in ('SUCCESS', 'UNINIT_FAILURE') and entry['observation']['state'] in ('VALIDATED_SUCCESS', 'VALIDATED_FAILURE')
            else:
                accepted = observed == entry['expected'] and entry['observation']['state'] in ('UNSUPPORTED_UNION', 'VALIDATED_SUCCESS', 'VALIDATED_FAILURE')
            source_after_hash = sha(source)
            entry['source_sha256_after'] = source_after_hash
            if source_after_hash != frozen_source_hash:
                entry['observation'] = {'outcome': 'UNKNOWN', 'state': 'SOURCE_HASH_CHANGED', 'proof_credit': 'NONE'}
                observed = 'UNKNOWN'; accepted = False
            entry.update(status='OBSERVED' if observed != 'UNKNOWN' else 'UNKNOWN', outcome=observed,
                         expected_match=accepted)
        entry['tool_after'] = tool_identity(tool, pin_name)
        if entry not in receipts: receipts.append(entry)
        (args.out / 'rows' / row['id'] / 'receipt.json').write_text(json.dumps(entry, indent=2) + '\n')
        persist('RUNNING')
    final = tool_identity(tool, pin_name)
    all_accepted = len(receipts) == len(ROWS) and all(r.get('expected_match') for r in receipts)
    report = {'status': 'COMPLETE' if all_accepted and final == before else 'COMPLETE_WITH_UNEXPECTED',
              'pin': PINS[pin_name], 'tool_before': before, 'tool_after': final, 'rows': receipts,
              'proof_credit': 'NONE'}
    (args.out / 'run.json').write_text(json.dumps(report, indent=2) + '\n')
    return 0 if report['status'] == 'COMPLETE' else 1


if __name__ == '__main__':
    try: raise SystemExit(main())
    except Exception as exc:
        print(f'{type(exc).__name__}: {exc}', file=__import__('sys').stderr)
        raise SystemExit(1)
