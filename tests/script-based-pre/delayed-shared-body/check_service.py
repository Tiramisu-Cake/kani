#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Exercise result collection with synthetic exports and Python processes."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tempfile
from unittest.mock import patch

import runner
from service import execute, regular_inventory
from workflow_checks import workflow_expressions


def sample(names, leak=False, lost=False):
    entries, inventories = [], {}
    for name in names:
        bad = name in (runner.NAMES[0], 'uninitialized_control')
        failing = (bad and not lost) or (leak and name == runner.NAMES[1])
        file = 'control.rs' if name == 'uninitialized_control' else 'src/lib.rs'
        line = '16' if file == 'control.rs' else '12'
        props = [{'index': 1, 'id': 'read_value.safety_check.1',
                  'description': runner.UNINIT + ' of type `u64`',
                  'status': 'FAILURE' if failing else 'SUCCESS',
                  'location': file + ':' + line + ':5 in function read_value'},
                 {'index': 2, 'id': 'kani::mem::cbmc::same_allocation.unsupported_construct.1',
                  'description': 'Kani does not support reasoning about pointer to unallocated memory',
                  'status': 'SUCCESS', 'location': 'library/kani/src/lib.rs:63:1 in function same_allocation'}]
        if name == runner.NAMES[1]:
            props.append({'index': 3, 'id': 'initialized_control_harness.assertion.1',
                          'description': 'assertion failed: result == 7', 'status': 'SUCCESS',
                          'location': 'src/lib.rs:40:5 in function initialized_control_harness'})
        failed = ([{'id': props[0]['id'], 'description': props[0]['description'], 'status': 'FAILURE',
                    'class': 'safety_check', 'file': file, 'line': line}] if failing else [])
        unsupported = [{'id': props[1]['id'], 'description': props[1]['description'],
                        'status': 'SUCCESS', 'class': 'unsupported_construct', 'file': 'library/kani/src/lib.rs', 'line': '63'}]
        entries.append({'name': name, 'is_automatically_generated': False, 'is_bounded': False,
            'outcome': {'kind': 'COMPLETED', 'verdict': 'FAILURE' if failing else 'SUCCESS'},
            'checks': {'total': len(props), 'success': len(props) - len(failed), 'failure': [p['id'] for p in failed],
                       'unreachable': [], 'undetermined': [], 'error': [], 'unknown': [], 'other': []},
            'n_properties': len(props), 'n_failed': len(failed), 'failed_properties': failed,
            'unsupported_constructs': unsupported, 'covers': {'total': 0}})
        inventories[name] = props
    doc = {'schema_version': '0.1.0', 'run_state': 'COMPLETE', 'outcome': {'kind': 'COMPLETED'},
           'target': runner.TARGET, 'enabled_unstable_features': ['ghost-state', 'uninit-checks', 'export-json'],
           'configuration': {'coverage_enabled': False, 'cbmc_args': [], 'checks': {
               'memory_safety': True, 'overflow': True, 'unwinding': True, 'undefined_function': True,
               'assertion_reach_checks': True, 'prove_safety_only': False, 'ignore_global_asm': False}},
           'harness_selection': {'requested_filters': names, 'exact': True, 'unmatched_filters': [], 'matched_count': len(names)},
           'harnesses': entries}
    process = {'exit': int(any(e['n_failed'] > 0 for e in entries)), 'signal': None, 'termination': 'EXITED',
               'stdout_inventory_complete': True, 'property_inventory': inventories,
               'stderr_first_lines': [], 'stderr_tail': []}
    return doc, process


def rejects(doc, process, wanted=None):
    try:
        runner.parse_document(doc, wanted or runner.NAMES, process)
    except (ValueError, TypeError, KeyError):
        return
    raise AssertionError('malformed or mismatched export accepted')


def complete(names, **kwargs):
    doc, process = sample(names, **kwargs)
    return {'classification': 'COMPLETE', 'harnesses': runner.parse_document(doc, names, process)}


def six_runs():
    result = {'uninitialized_control': complete(['uninitialized_control'])}
    for mode in ('delayed_first', 'control_first'):
        for case, names in [('delayed_alone', runner.NAMES[:1]), ('control_alone', runner.NAMES[1:]), ('paired', runner.NAMES)]:
            result[mode + '/' + case] = complete(names)
    return result


workflow = (runner.ROOT / '.github/workflows/f4-confirm.yml').read_text()
expressions = workflow_expressions(workflow)
assert expressions and len(expressions) == workflow.count('${{')
for value in ('runner.temp', 'job.status', 'env.F4_EVIDENCE_DIR', 'always()'):
    invalid = workflow.replace('${{ github.workspace }}', '${{ ' + value + ' }}', 1)
    try:
        workflow_expressions(invalid)
    except ValueError:
        pass
    else:
        raise AssertionError('job environment context regression accepted')
path = re.search(r'(?m)^      F4_EVIDENCE_DIR: (.+)$', workflow)[1]
assert path.startswith('${{ github.workspace }}/')
assert '..' not in PurePosixPath(path[len('${{ github.workspace }}/'):]).parts
assert 'path: ${{ env.F4_EVIDENCE_DIR }}/result.json' in workflow
assert 'fetch-depth: 3' in workflow and 'runner.py build' in workflow
assert 'unset CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR CARGO_BUILD_TARGET' in workflow

runs = six_runs()
assert runner.classify(runs) == ('DEFECT_ABSENT_FOR_TEST', [])
leaked = copy.deepcopy(runs)
leaked['delayed_first/paired'] = complete(runner.NAMES, leak=True)
assert runner.classify(leaked)[0] == 'DEFECT_PRESENT'
lost = copy.deepcopy(runs)
lost['control_first/paired'] = complete(runner.NAMES, lost=True)
assert runner.classify(lost)[0] == 'DEFECT_PRESENT'
composition = copy.deepcopy(runs)
composition['control_first/paired']['harnesses'][runner.NAMES[1]]['properties'][0]['description'] += ' changed'
assert runner.classify(composition)[0] == 'DEFECT_PRESENT'
# The paired native process exits 1 in the consistent and contaminated cases.
assert sample(runner.NAMES)[1]['exit'] == sample(runner.NAMES, leak=True)[1]['exit'] == 1
for label in runs:
    broken = copy.deepcopy(runs)
    broken[label] = {'classification': 'UNKNOWN', 'termination': 'NOT_RUN'}
    try:
        runner.classify(broken)
    except ValueError:
        pass
    else:
        raise AssertionError('partial six-run result accepted')

for label, names in [('uninitialized_control', ['uninitialized_control']),
                     ('delayed_first/delayed_alone', runner.NAMES[:1])]:
    broken = copy.deepcopy(runs)
    broken[label] = complete(names, lost=True)
    try:
        runner.classify(broken)
    except ValueError:
        pass
    else:
        raise AssertionError('undetected singleton uninitialized read accepted')
broken = copy.deepcopy(runs)
for prop in broken['control_first/control_alone']['harnesses'][runner.NAMES[1]]['properties']:
    if prop['description'] == 'assertion failed: result == 7':
        prop['description'] = 'different assertion'
try:
    runner.classify(broken)
except ValueError:
    pass
else:
    raise AssertionError('missing initialized control assertion accepted')

base, process = sample(runner.NAMES)
runner.parse_document(base, runner.NAMES, process)
for value in (None, [], {}, 'SUCCESS'):
    rejects(value, process)
for key, values in {
    'schema_version': [None, 1, 'other'], 'run_state': ['PARTIAL', 'NOT_RUN', None],
    'outcome': [None, {'kind': 'TIMEOUT'}], 'target': ['other'], 'enabled_unstable_features': [[]],
    'harnesses': [[], None, 'wrong'], 'configuration': [None], 'harness_selection': [None],
}.items():
    for value in values:
        doc = copy.deepcopy(base); doc[key] = value; rejects(doc, process)
for key, value in [('outcome', {'kind': 'CRASHED', 'code': 101}), ('checks', None), ('n_properties', True),
                   ('n_failed', None), ('failed_properties', [None]), ('unsupported_constructs', [None]),
                   ('is_automatically_generated', True), ('is_bounded', True)]:
    doc = copy.deepcopy(base); doc['harnesses'][0][key] = value; rejects(doc, process)
for key, value in [('success', None), ('total', True), ('unknown', ['x']), ('other', [{}]), ('unreachable', None)]:
    doc = copy.deepcopy(base); doc['harnesses'][0]['checks'][key] = value; rejects(doc, process)
for key in ('memory_safety', 'overflow', 'unwinding', 'undefined_function', 'assertion_reach_checks'):
    doc = copy.deepcopy(base); doc['configuration']['checks'][key] = False; rejects(doc, process)
for key, value in [('matched_count', 1), ('exact', False), ('unmatched_filters', ['missing']), ('requested_filters', ['other'])]:
    doc = copy.deepcopy(base); doc['harness_selection'][key] = value; rejects(doc, process)
for status in ('FAILURE', 'UNKNOWN', 'UNDETERMINED', None):
    doc = copy.deepcopy(base); doc['harnesses'][0]['unsupported_constructs'][0]['status'] = status; rejects(doc, process)
for key, value in [('exit', 0), ('termination', 'TIMEOUT'), ('stdout_inventory_complete', False), ('property_inventory', {})]:
    native = copy.deepcopy(process); native[key] = value; rejects(base, native)
for key, value in [('id', 'other.id.1'), ('status', 'UNKNOWN'), ('description', None), ('location', None), ('index', 4)]:
    native = copy.deepcopy(process); native['property_inventory'][runner.NAMES[0]][0][key] = value; rejects(base, native)

with tempfile.TemporaryDirectory() as directory:
    cwd = Path(directory)
    for program, expected in [('print("ok")', (0, 'EXITED')), ('raise SystemExit(7)', (7, 'EXITED')),
                              ('import os,signal; os.kill(os.getpid(), signal.SIGTERM)', (-15, 'EXITED'))]:
        record = execute([sys.executable, '-c', program], cwd, 2)
        assert (record['exit'], record['termination']) == expected
        assert record['signal'] == (15 if expected[0] == -15 else None)
    record = execute([sys.executable, '-c', 'import time; time.sleep(10)'], cwd, .03)
    assert record['termination'] == 'TIMEOUT' and record['exit'] < 0 and record['signal']
    record = execute([str(cwd / 'absent')], cwd, 2)
    assert record['termination'] == 'SPAWN_ERROR' and record['exit'] is None and record['error']
    record = execute([sys.executable, '-c', 'import sys; [print("message " + str(i), file=sys.stderr) for i in range(100)]; sys.exit(1)'], cwd, 2)
    assert len(record['stderr_first_lines']) == 18 and len(record['stderr_tail']) == 8
    assert record['stderr_tail'][-1] == 'message 99'
    export = cwd / 'export.json'
    for content in (None, 'null', '{}', '{"run_state":"PARTIAL"}', '"NOT_RUN"'):
        export.unlink(missing_ok=True)
        if content is not None:
            export.write_text(content)
        with patch.object(runner, 'execute', return_value=copy.deepcopy(process)):
            result = runner.probe(['synthetic'], runner.NAMES, export, {})
        assert result['classification'] == 'UNKNOWN' and result['exit'] == 1 and result['reason']
    calls = []
    def failed_execute(argv, workdir, timeout, env=None):
        calls.append((argv, env))
        return {'termination': 'EXITED', 'exit': 101, 'signal': None,
                'stderr_first_lines': ['error: synthetic build failure'], 'stderr_tail': ['cause: synthetic'],
                'stdout_inventory_complete': True, 'property_inventory': {}}
    with patch.object(runner, 'OUT', cwd), patch.object(runner, 'RESULT', cwd / 'result.json'), \
            patch.object(runner, 'HERE', cwd), patch.object(runner, 'snapshot', return_value={'problems': []}), \
            patch.object(runner, 'execute', failed_execute), contextlib.redirect_stdout(io.StringIO()):
        assert runner.build() == 2
        assert calls[0][0] == ['cargo', 'build-dev']
        assert json.loads((cwd / 'result.json').read_text())['build']['exit'] == 101
        calls.clear()
        assert runner.run() == 2
        value = json.loads((cwd / 'result.json').read_text())
        assert len(calls) == len(value['runs']) == 7
        assert all(r['classification'] == 'UNKNOWN' and r['exit'] == 101 and r['stderr_tail'] for r in value['runs'].values())
        assert calls[0][1]['RUSTFLAGS'] == '--edition=2021'
        for argv, env in calls[1:]:
            assert argv[0] == str(runner.ROOT / 'scripts/cargo-kani') and argv[1] == 'kani'
            assert env['RUSTFLAGS'] == '' and env['CARGO_ENCODED_RUSTFLAGS'] is None
            assert '--exact' in argv and '-j1' in argv and '--lib' in argv
        (cwd / 'result.json').unlink()
        assert runner.finish() == 2
        value = json.loads((cwd / 'result.json').read_text())
        assert len(value['runs']) == 7 and all(r['termination'] == 'NOT_RUN' for r in value['runs'].values())

# Exercise complete collection through the same seven-invocation path.
with tempfile.TemporaryDirectory() as directory:
    cwd = Path(directory)
    for leak in (False, True):
        calls = []
        def native_execute(argv, workdir, timeout, env=None):
            names = [argv[i + 1] for i, arg in enumerate(argv) if arg == '--harness']
            doc, process = sample(names, leak=leak and len(names) == 2)
            Path(argv[argv.index('--export-json') + 1]).write_text(json.dumps(doc))
            calls.append(argv)
            return process | {'argv': argv, 'cwd': str(workdir), 'environment': env}
        with patch.object(runner, 'OUT', cwd), patch.object(runner, 'RESULT', cwd / 'result.json'), \
                patch.object(runner, 'HERE', cwd), patch.object(runner, 'snapshot', return_value={'problems': []}), \
                patch.object(runner, 'execute', native_execute), contextlib.redirect_stdout(io.StringIO()):
            assert runner.run() == (1 if leak else 0)
            assert len(calls) == 7
            result = json.loads((cwd / 'result.json').read_text())
            assert result['classification'] == ('DEFECT_PRESENT' if leak else 'DEFECT_ABSENT_FOR_TEST')
            assert runner.finish() == 0
            assert json.loads((cwd / 'result.json').read_text())['classification'] == result['classification']

# Check the native rendering parser using complete per-harness sections.
stdout = ''
for name, props in process['property_inventory'].items():
    stdout += 'Checking harness ' + name + '...\nRESULTS:\n'
    for prop in props:
        stdout += 'Check ' + str(prop['index']) + ': ' + prop['id'] + '\n'
        stdout += '\t - Status: ' + prop['status'] + '\n\t - Description: "' + prop['description'] + '"\n'
        stdout += '\t - Location: ' + prop['location'] + '\n\n'
assert regular_inventory(stdout) == process['property_inventory']

# Exercise the real Git source gate against a depth-three checkout.
with tempfile.TemporaryDirectory() as directory:
    source, checkout = Path(directory) / 'source', Path(directory) / 'checkout'
    source.mkdir()
    def git(*args, cwd=source):
        return subprocess.check_output(['git', *args], cwd=cwd, stderr=subprocess.PIPE).decode().strip()
    def commit(message, empty=False):
        args = ['-c', 'user.name=Service test', '-c', 'user.email=test@example.invalid', 'commit', '-q', '--no-gpg-sign', '-m', message]
        if empty:
            args.append('--allow-empty')
        git(*args)
        return git('rev-parse', 'HEAD')
    git('init', '-q')
    (source / 'base.txt').write_text('base\n');git('add', 'base.txt');commit('ancestor')
    commit('base', empty=True);base_sha = git('rev-parse', 'HEAD');base_tree = git('rev-parse', 'HEAD^{tree}')
    profile = source / '.github/f4-confirm/profile.json';profile.parent.mkdir(parents=True)
    profile.write_text(json.dumps({'base': base_sha, 'base_tree': base_tree, 'source_sha256': {}}))
    git('add', '.github/f4-confirm/profile.json');control = commit('control')
    trigger = commit('trigger', empty=True)
    git('clone', '-q', '--depth=3', source.as_uri(), str(checkout))
    with patch.object(runner, 'ROOT', checkout), patch.object(runner, 'BASE', base_sha), \
            patch.object(runner, 'PROFILE', checkout / '.github/f4-confirm/profile.json'), patch.dict(os.environ, {}, clear=True):
        result = runner.snapshot()
        assert not result['problems'] and result['shallow'] == 'true' and result['control'] == control, result
        git('checkout', '-q', control, cwd=checkout)
        assert not runner.snapshot()['problems']
        (checkout / 'base.txt').write_text('changed\n')
        assert runner.snapshot()['problems']
        git('checkout', '--', 'base.txt', cwd=checkout)
        (checkout / 'extra.rs').write_text('// extra\n')
        assert runner.snapshot()['problems']
        (checkout / 'extra.rs').unlink()
        git('checkout', '-q', trigger, cwd=checkout)
        git('fetch', '-q', '--depth=2', 'origin', trigger, cwd=checkout)
        assert runner.snapshot()['problems']

print(json.dumps({'status': 'PASS', 'scope': 'STATIC_AND_SYNTHETIC', 'checks': [
    'complete success/failure, per-harness property identities and partition',
    'successful unsupported checks accepted; reachable/unresolved rejected',
    'native exits/signals, timeout, spawn, missing/null/type/PARTIAL/NOT_RUN',
    'target/source/selection mismatch, disabled checks, missing assertion',
    'six-run partial and paired false-negative/false-positive/composition cases',
    'all six invocations continue after control/build failures with native diagnostics',
    'argv, edition, sanitized environment, bounded head/tail stderr',
    'depth-three control/trigger ancestry accepted; depth-two and source mutations rejected',
    'workflow contexts and artifact path'], 'workflow_expressions': expressions}, sort_keys=True))
