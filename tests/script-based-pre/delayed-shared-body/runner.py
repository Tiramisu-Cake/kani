#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Compare shared function checks for isolated and paired harnesses."""
import collections
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from service import execute

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PROFILE = ROOT / '.github/f4-confirm/profile.json'
BASE = 'faffcee3bca2770c03bd21c3bde89cc8f6f7a14e'
TARGET = 'x86_64-unknown-linux-gnu'
UNINIT = 'Undefined Behavior: Reading from an uninitialized pointer'
NAMES = ['delayed_harness', 'initialized_control_harness']
OUT = Path(os.environ.get('F4_EVIDENCE_DIR', tempfile.gettempdir() + '/f4-confirm-evidence'))
RESULT = OUT / 'result.json'


class Unknown(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Unknown(reason)


def save(value):
    OUT.mkdir(parents=True, exist_ok=True)
    temporary = RESULT.with_suffix('.json.next')
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    temporary.replace(RESULT)


def read_result():
    if RESULT.exists():
        try:
            value = json.loads(RESULT.read_text())
            require(isinstance(value, dict) and value.get('schema') == 'kani-f4-confirm-v2'
                    and isinstance(value.get('runs'), dict), 'invalid collector state')
            return value
        except (OSError, ValueError):
            pass
    return {'schema': 'kani-f4-confirm-v2', 'classification': 'INCONCLUSIVE',
            'reason': 'NOT_RUN', 'runs': {}, 'order_coverage': 'UNKNOWN',
            'order_reason': 'Native exports identify verification results, not compiler processing order.'}


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, stderr=subprocess.PIPE).decode().strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(built=False):
    record = {'base': BASE, 'problems': []}
    try:
        profile = json.loads(PROFILE.read_text())
        require(profile['base'] == BASE, 'profile base mismatch')
        expected_profile = os.environ.get('F4_PROFILE_SHA256')
        if expected_profile:
            require(sha(PROFILE) == expected_profile, 'profile hash mismatch')
        record.update(head=git('rev-parse', 'HEAD'), tree=git('rev-parse', 'HEAD^{tree}'),
                      base_tree=git('rev-parse', BASE + '^{tree}'),
                      shallow=git('rev-parse', '--is-shallow-repository'), profile_sha256=sha(PROFILE))
        require(record['base_tree'] == profile['base_tree'], 'base tree mismatch')
        parent = git('rev-parse', 'HEAD^')
        require(len(git('show', '-s', '--format=%P', 'HEAD').split()) == 1, 'merge head')
        control = record['head']
        if parent != BASE:
            require(git('rev-parse', 'HEAD^^') == BASE, 'missing or wrong shallow ancestry')
            require(len(git('show', '-s', '--format=%P', 'HEAD^').split()) == 1, 'merge control')
            require(git('rev-parse', 'HEAD^^{tree}') == record['tree'], 'trigger tree mismatch')
            control = parent
        record['control'] = control
        changes = git('diff', '--name-status', BASE, 'HEAD').splitlines()
        record['changes'] = changes
        for change in changes:
            status, path = change.split('\t')
            allowed = path.startswith(('tests/script-based-pre/delayed-shared-body/', '.github/f4-confirm/'))
            allowed |= path == '.github/workflows/f4-confirm.yml'
            allowed |= status == 'D' and path.startswith('.github/workflows/')
            require(allowed, 'source path mismatch: ' + path)
        require(not git('diff', 'HEAD', '--'), 'tracked source changed')
        untracked = git('ls-files', '--others', '--exclude-standard').splitlines()
        require(not any(p.endswith(('.rs', '.toml', '.py', '.sh', '.yml')) for p in untracked),
                'untracked source')
        record['source_sha256'] = {}
        for path, expected in profile['source_sha256'].items():
            actual = sha(ROOT / path)
            record['source_sha256'][path] = actual
            require(actual == expected, 'source hash mismatch: ' + path)
        record['tools'] = {}
        for name in ('kani-driver', 'kani-compiler'):
            path = ROOT / 'target/kani/bin' / name
            if built:
                require(path.is_file(), 'missing built tool: ' + str(path))
                record['tools'][name] = {'path': str(path.resolve()), 'sha256': sha(path)}
        if built:
            for name in ('cbmc', 'cargo', 'rustc'):
                path = shutil.which(name)
                require(path is not None, 'missing PATH tool: ' + name)
                record['tools'][name] = {'path': path, 'resolved': str(Path(path).resolve()), 'sha256': sha(Path(path))}
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as exc:
        record['problems'].append(str(exc))
    return record


def parse_document(doc, wanted, process):
    require(isinstance(doc, dict) and doc.get('schema_version') == '0.1.0', 'unsupported export schema')
    require(doc.get('run_state') == 'COMPLETE' and doc.get('outcome') == {'kind': 'COMPLETED'}, 'incomplete export')
    require(doc.get('target') == TARGET, 'target mismatch')
    require({'uninit-checks', 'ghost-state', 'export-json'} <= set(doc.get('enabled_unstable_features', [])),
            'missing check feature')
    config = doc.get('configuration')
    require(isinstance(config, dict), 'missing configuration')
    require(config.get('coverage_enabled') is False and config.get('cbmc_args') == [], 'unexpected solver configuration')
    flags = config.get('checks')
    require(isinstance(flags, dict), 'missing check flags')
    for name in ('memory_safety', 'overflow', 'unwinding', 'undefined_function', 'assertion_reach_checks'):
        require(flags.get(name) is True, 'disabled check: ' + name)
    require(flags.get('prove_safety_only') is False and flags.get('ignore_global_asm') is False, 'weakened checks')
    selection = doc.get('harness_selection')
    require(isinstance(selection, dict), 'missing harness selection')
    require(selection.get('exact') is True and selection.get('requested_filters') == wanted
            and selection.get('unmatched_filters') == []
            and type(selection.get('matched_count')) is int
            and selection['matched_count'] == len(wanted), 'selection mismatch')
    entries = doc.get('harnesses')
    require(isinstance(entries, list) and all(isinstance(e, dict) for e in entries), 'invalid harnesses')
    require(len(entries) == len(wanted) and {e.get('name') for e in entries} == set(wanted), 'wrong harness inventory')
    require(process.get('stdout_inventory_complete') is True, 'stdout inventory size cap')
    regular = process.get('property_inventory')
    require(isinstance(regular, dict) and set(regular) == set(wanted), 'regular inventory selection mismatch')
    result = {}
    for entry in entries:
        name = entry['name']
        outcome = entry.get('outcome')
        require(entry.get('is_automatically_generated') is False and entry.get('is_bounded') is False,
                'unexpected harness kind')
        require(isinstance(outcome, dict) and outcome.get('kind') == 'COMPLETED'
                and outcome.get('verdict') in ('SUCCESS', 'FAILURE'), 'nonterminal harness')
        checks = entry.get('checks')
        require(isinstance(checks, dict), 'missing checks')
        for key in ('total', 'success'):
            require(type(checks.get(key)) is int and checks[key] >= 0, 'invalid check count')
        require(0 < checks['total'] <= 256 and entry.get('n_properties') == checks['total']
                and type(entry.get('n_properties')) is int, 'invalid property count')
        require(isinstance(entry.get('covers'), dict) and entry['covers'].get('total') == 0, 'unexpected covers')
        for key in ('failure', 'unreachable', 'undetermined', 'error', 'unknown', 'other'):
            require(isinstance(checks.get(key), list), 'missing check bucket')
        require(all(checks[key] == [] for key in ('undetermined', 'error', 'unknown', 'other')), 'unresolved checks')
        require(all(isinstance(x, str) for key in ('failure', 'unreachable') for x in checks[key]), 'invalid check identity')
        props = regular[name]
        require(isinstance(props, list) and len(props) == checks['total'], 'regular/export count mismatch')
        ids = []
        for prop in props:
            require(isinstance(prop, dict) and all(isinstance(prop.get(k), str) and prop[k]
                    for k in ('id', 'status', 'description', 'location')), 'incomplete check identity')
            require(prop['status'] in ('SUCCESS', 'FAILURE', 'UNREACHABLE'), 'unresolved property status')
            ids.append(prop['id'])
        require(len(ids) == len(set(ids)), 'duplicate property identity')
        require([p.get('index') for p in props] == list(range(1, len(props) + 1)), 'partial property inventory')
        counts = collections.Counter(p['status'] for p in props)
        require(counts['SUCCESS'] == checks['success']
                and counts['FAILURE'] == len(checks['failure'])
                and counts['UNREACHABLE'] == len(checks['unreachable']), 'check composition mismatch')
        require({p['id'] for p in props if p['status'] == 'FAILURE'} == set(checks['failure'])
                and {p['id'] for p in props if p['status'] == 'UNREACHABLE'} == set(checks['unreachable']),
                'check identity mismatch')
        failed = entry.get('failed_properties')
        require(isinstance(failed, list) and all(isinstance(p, dict) for p in failed), 'invalid failures')
        require(type(entry.get('n_failed')) is int and entry['n_failed'] == len(failed) == counts['FAILURE'], 'failure count mismatch')
        require({p.get('id') for p in failed} == set(checks['failure']), 'failure identity mismatch')
        unsupported = entry.get('unsupported_constructs')
        require(isinstance(unsupported, list) and all(isinstance(p, dict) for p in unsupported), 'invalid unsupported inventory')
        for prop in unsupported:
            require(prop.get('status') in ('SUCCESS', 'UNREACHABLE') and prop.get('id') in ids,
                    'reachable or unresolved unsupported construct')
            native = next(p for p in props if p['id'] == prop['id'])
            require(native['status'] == prop['status'] and native['description'] == prop.get('description'),
                    'unsupported identity mismatch')
        require((outcome['verdict'] == 'FAILURE') == bool(failed), 'verdict mismatch')
        for prop in failed:
            require(isinstance(prop.get('file'), str) and isinstance(prop.get('line'), str), 'missing failure source')
            require(prop.get('status') == 'FAILURE' and prop.get('class') == 'safety_check'
                    and isinstance(prop.get('description'), str) and prop['description'].startswith(UNINIT),
                    'unexpected failure')
            native = next(p for p in props if p['id'] == prop['id'])
            require(native['description'] == prop['description'], 'failure description mismatch')
        result[name] = {'verdict': outcome['verdict'], 'checks': checks, 'properties': props,
                        'failed_properties': failed, 'unsupported_constructs': unsupported,
                        'n_properties': entry['n_properties'], 'n_failed': entry['n_failed']}
    require(process.get('termination') == 'EXITED' and process.get('exit') == int(any(
        h['verdict'] == 'FAILURE' for h in result.values())), 'native exit mismatch')
    return result


def argv_for(mode, wanted, export, target):
    args = [str(ROOT / 'scripts/cargo-kani'), 'kani', '--manifest-path', str(HERE / 'Cargo.toml'),
            '--lib', '--exact', '-j1', '-Z', 'ghost-state', '-Z', 'uninit-checks',
            '-Z', 'export-json', '--export-json', str(export), '--output-format=regular',
            '--target-dir', str(target)]
    if mode == 'delayed_first':
        args += ['--features', 'delayed-first']
    for name in wanted:
        args += ['--harness', name]
    return args


def environment():
    return {'RUSTFLAGS': '', 'CARGO_ENCODED_RUSTFLAGS': None, 'KANIFLAGS': '', 'KANI_LOG': '',
            'KANI_FAIL_ON_UNEXPECTED_DESCRIPTION': 'true', 'NO_COLOR': '1', 'RUST_BACKTRACE': '0',
            'CARGO_TARGET_DIR': None, 'CARGO_BUILD_TARGET': None}


def probe(argv, wanted, export, env):
    record = execute(argv, HERE, 120, env=env)
    record['classification'] = 'UNKNOWN'
    record['resolved_tools'] = {name: str((ROOT / path).resolve()) for name, path in (
        ('cargo-kani', 'scripts/cargo-kani'), ('kani-driver', 'target/kani/bin/kani-driver'),
        ('kani-compiler', 'target/kani/bin/kani-compiler'))}
    record['resolved_tools'].update({name: shutil.which(name) for name in ('cargo', 'rustc', 'cbmc')})
    try:
        require(record['termination'] == 'EXITED', record['termination'])
        require(record['exit'] in (0, 1), 'native error exit')
        require(export.is_file(), 'MISSING_EXPORT: build/invocation failure remains UNKNOWN')
        require(export.stat().st_size <= 2 * 1024 * 1024, 'export size cap')
        record['export_sha256'] = sha(export)
        doc = json.loads(export.read_text())
        record['harnesses'] = parse_document(doc, wanted, record)
        record['native_configuration'] = {key: doc.get(key) for key in ('tools', 'kani_commit', 'kani_commit_dirty', 'target', 'configuration', 'enabled_unstable_features', 'harness_selection')}
        record['classification'] = 'COMPLETE'
        record['reason'] = 'complete per-harness checks'
    except (OSError, ValueError, TypeError, KeyError) as exc:
        record['reason'] = str(exc)
    record.pop('output_excerpt', None)
    return record


def signature(harness):
    # Preserve multiplicity, function, class, description, status, and source location.
    rows = []
    for prop in harness['properties']:
        rows.append((re.sub(r'\.\d+$', '', prop['id']), prop['status'], prop['description'],
                     prop['location'].replace(str(ROOT) + '/', '')))
    return sorted(rows)


def classify(runs):
    require(set(runs) == {'uninitialized_control'} | {f'{mode}/{case}' for mode in (
        'delayed_first', 'control_first') for case in ('delayed_alone', 'control_alone', 'paired')},
        'missing invocation')
    require(all(r.get('classification') == 'COMPLETE' for r in runs.values()), 'incomplete native invocation')
    control = runs['uninitialized_control']['harnesses']['uninitialized_control']
    require(control['verdict'] == 'FAILURE' and control['n_failed'] > 0, 'uninitialized control was not detected')
    require(all(p.get('file', '').endswith('control.rs') and p.get('line') == '16'
                for p in control['failed_properties']), 'uninitialized control failure site mismatch')
    differences = []
    for mode in ('delayed_first', 'control_first'):
        delayed = runs[mode + '/delayed_alone']['harnesses'][NAMES[0]]
        good = runs[mode + '/control_alone']['harnesses'][NAMES[1]]
        require(delayed['verdict'] == 'FAILURE' and delayed['n_failed'] > 0, 'isolated delayed check was not detected')
        require(all(p.get('file', '').endswith('src/lib.rs') and p.get('line') == '12'
                    for p in delayed['failed_properties']), 'delayed failure site mismatch')
        require(good['verdict'] == 'SUCCESS' and any(p['status'] == 'SUCCESS' and
                    p['description'] == 'assertion failed: result == 7' for p in good['properties']),
                'initialized control assertion missing or failing')
        pair = runs[mode + '/paired']['harnesses']
        for name, single in zip(NAMES, (delayed, good)):
            # A new unrelated failure remains inconclusive, even when inventories differ.
            for prop in pair[name]['failed_properties']:
                require(prop.get('file', '').endswith('src/lib.rs') and prop.get('line') == '12',
                        'paired failure site mismatch')
            if signature(single) != signature(pair[name]) or single['verdict'] != pair[name]['verdict']:
                differences.append({'mode': mode, 'harness': name})
    return ('DEFECT_PRESENT' if differences else 'DEFECT_ABSENT_FOR_TEST'), differences


def build():
    value = read_result()
    record = execute(['cargo', 'build-dev'], ROOT, 900, env=environment())
    record.pop('output_excerpt', None)
    record.pop('property_inventory', None)
    record['classification'] = 'BUILD_SUCCESS' if record['termination'] == 'EXITED' and record['exit'] == 0 else 'UNKNOWN'
    record['reason'] = 'completed build' if record['classification'] == 'BUILD_SUCCESS' else 'build process failed'
    value['build'] = record
    save(value)
    return 0 if record['classification'] == 'BUILD_SUCCESS' else 2


def run():
    value = read_result()
    value['source_run'] = snapshot(built=True)
    if value['source_run']['problems']:
        value.update(classification='INCONCLUSIVE', reason='source or built tool gate failed')
        save(value)
        return 2
    value['runs'] = {}
    lock = HERE / 'Cargo.lock'
    had_lock = lock.exists()
    try:
        with tempfile.TemporaryDirectory(prefix='f4-confirm-') as temporary:
            scratch = Path(temporary)
            export = scratch / 'uninitialized-control.json'
            argv = [str(ROOT / 'scripts/kani'), str(HERE / 'control.rs'), '--exact', '--harness',
                    'uninitialized_control', '-j1', '-Z', 'ghost-state', '-Z', 'uninit-checks',
                    '-Z', 'export-json', '--export-json', str(export), '--output-format=regular',
                    '--target-dir', str(scratch / 'control-target')]
            env = environment() | {'RUSTFLAGS': '--edition=2021'}
            value['runs']['uninitialized_control'] = probe(argv, ['uninitialized_control'], export, env)
            save(value)
            for mode in ('delayed_first', 'control_first'):
                for case, wanted in [('delayed_alone', NAMES[:1]), ('control_alone', NAMES[1:]), ('paired', NAMES)]:
                    label = mode + '/' + case
                    export = scratch / (mode + '-' + case + '.json')
                    target = scratch / (mode + '-' + case + '-target')
                    value['runs'][label] = probe(argv_for(mode, wanted, export, target), wanted, export, environment())
                    save(value)
        value['classification'], value['differences'] = classify(value['runs'])
        value['reason'] = 'per-harness singleton/paired comparison complete; compiler order coverage UNKNOWN'
    except (OSError, ValueError, TypeError, KeyError) as exc:
        value.update(classification='INCONCLUSIVE', reason=str(exc))
    finally:
        if not had_lock:
            lock.unlink(missing_ok=True)
        save(value)
    if value['classification'] == 'DEFECT_ABSENT_FOR_TEST':
        print('Delayed UB check results are consistent across isolated and paired harness verification.')
        return 0
    print('Delayed UB check results: ' + value['classification'])
    return 1 if value['classification'] == 'DEFECT_PRESENT' else 2


def finish():
    value = read_result()
    value['source_after'] = snapshot()
    value['job_status'] = os.environ.get('F4_JOB_STATUS')
    for label in ['uninitialized_control'] + [f'{mode}/{case}' for mode in (
            'delayed_first', 'control_first') for case in ('delayed_alone', 'control_alone', 'paired')]:
        value.setdefault('runs', {}).setdefault(label, {'classification': 'UNKNOWN', 'termination': 'NOT_RUN',
            'exit': None, 'signal': None, 'reason': 'earlier setup, build, source gate, or job termination'})
    if value['source_after']['problems'] or any(r['classification'] != 'COMPLETE' for r in value['runs'].values()):
        value.update(classification='INCONCLUSIVE', reason='source gate or incomplete invocation')
    save(value)
    return 2 if value['classification'] == 'INCONCLUSIVE' else 0


if __name__ == '__main__':
    if sys.argv[1:] == ['before']:
        value = read_result()
        value['source_before'] = snapshot()
        save(value)
        sys.exit(int(bool(value['source_before']['problems'])))
    if sys.argv[1:] == ['build']:
        sys.exit(build())
    if sys.argv[1:] == ['run']:
        sys.exit(run())
    if sys.argv[1:] == ['finish']:
        sys.exit(finish())
    sys.exit('usage: runner.py before|build|run|finish')
