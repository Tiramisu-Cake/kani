#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Exercise contract confirmation collection with synthetic processes and documents."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

import runner
import service
from workflow_checks import workflow_expressions


def sample(slot):
    name = runner.SLOTS[slot][1]
    description = {'provider': '|result| *result == x + 1',
                   'verified': 'assertion failed: f(x) == x + 1',
                   'ordinary': 'assertion failed: f(x) == x + 2'}[slot]
    props = [{'index': 1, 'id': name + '.assertion.1', 'description': description,
              'status': 'SUCCESS', 'location': 'src/lib.rs:20:5 in function ' + name}]
    process = {'termination': 'EXITED', 'exit': 0, 'signal': None, 'diagnostics': [],
               'diagnostics_complete': True, 'verification_success': 1,
               'streams': {x: {'complete': True} for x in ('stdout', 'stderr')},
               'property_inventory': {name: props}}
    checks = {x: True for x in ('memory_safety', 'overflow', 'unwinding', 'undefined_function', 'assertion_reach_checks')}
    checks.update(prove_safety_only=False, ignore_global_asm=False)
    doc = {'schema_version': '0.1.0', 'run_state': 'COMPLETE', 'outcome': {'kind': 'COMPLETED'},
           'target': 'x86_64-unknown-linux-gnu', 'enabled_unstable_features': ['function-contracts', 'stubbing', 'export-json'],
           'configuration': {'checks': checks, 'coverage_enabled': False, 'cbmc_args': []},
           'harness_selection': {'exact': True, 'requested_filters': [name], 'unmatched_filters': [], 'matched_count': 1},
           'harnesses': [{'name': name, 'is_automatically_generated': False, 'is_bounded': False,
             'outcome': {'kind': 'COMPLETED', 'verdict': 'SUCCESS'}, 'n_properties': 1,
             'n_failed': 0, 'failed_properties': [], 'unsupported_constructs': [], 'covers': {'total': 0},
             'checks': dict(total=1, success=1, **{x: [] for x in ('failure', 'unreachable', 'undetermined', 'error', 'unknown', 'other')})}]}
    return process, doc


def failure(header=None):
    process, _ = sample('ordinary')
    process.update(exit=1, verification_success=0, property_inventory={}, diagnostics=[{
        'header': header or 'error: Failed to find contract closure `__kani_recursion_check_f` in function `stub_contract_confirm::f`',
        'text': header or 'synthetic contract error', 'stream': 'stdout', 'complete': True}])
    return process


def state(ordinary='SUCCESS'):
    value = runner.initial()
    value.update(setup='SUCCESS', build=sample('provider')[0],
                 source_before={'problems': [], 'tools': {'compiler': 'synthetic'}},
                 source_after={'problems': [], 'tools': {'compiler': 'synthetic'}})
    for slot in runner.SLOTS:
        p, doc = sample(slot)
        if slot == 'ordinary' and ordinary != 'SUCCESS':
            p, doc = failure(runner.UNSUPPORTED if ordinary == 'EXPLICIT_UNSUPPORTED' else None), None
        value['slots'][slot] = {'process': p, 'observation': runner.observe(slot, p, doc)}
    return value


def check():
    count = 0
    for outcome, classification in [('SUCCESS', 'DEFECT_ABSENT'),
                                     ('MISSING_CONTRACT_CLOSURE', 'DEFECT_PRESENT'),
                                     ('EXPLICIT_UNSUPPORTED', 'INCONCLUSIVE')]:
        value = state(outcome)
        assert runner.classify(value)[0] == classification
        count += 1
    for slot in ('provider', 'verified'):
        value = state('MISSING_CONTRACT_CLOSURE')
        del value['slots'][slot]
        assert runner.classify(value)[0] == 'INCONCLUSIVE'
        count += 1
    for key, replacement in [('setup', 'NOT_RUN'), ('build', {'exit': 101, 'termination': 'EXITED'}),
                             ('source_after', {'problems': ['wrong target'], 'tools': {}}),
                             ('source_before', None), ('slots', None)]:
        value = state('MISSING_CONTRACT_CLOSURE'); value[key] = replacement
        assert runner.classify(value)[0] == 'INCONCLUSIVE'
        count += 1
    for p in [None, {}, {'termination': 'NOT_RUN'}, failure('error: unrelated'),
              failure('error: Failed to find contract closure `__kani_recursion_check_other` in function `other`')]:
        assert runner.observe('ordinary', p, None)['outcome'] == 'INCONCLUSIVE'
        count += 1
    for key, replacement in [('termination', 'TIMEOUT'), ('termination', 'RSS_CAP'),
                             ('termination', 'SPAWN_ERROR'), ('diagnostics_complete', False),
                             ('streams', {}), ('exit', None), ('exit', True), ('property_inventory', {'other': []})]:
        p = failure(); p[key] = replacement
        assert runner.observe('ordinary', p, None)['outcome'] == 'INCONCLUSIVE'
        count += 1
    p = failure(); p['diagnostics'].append({'header': 'error: unrelated'})
    assert runner.observe('ordinary', p, None)['outcome'] == 'INCONCLUSIVE'
    for slot in runner.SLOTS:
        p, doc = sample(slot)
        assert runner.observe(slot, p, doc)['outcome'] == 'SUCCESS'
        for replacement in (None, [], {}, 'NOT_RUN'):
            assert runner.observe(slot, p, replacement)['outcome'] == 'INCONCLUSIVE'
            count += 1
        for key, replacement in [('run_state', 'PARTIAL'), ('target', 'other'),
                                 ('harnesses', []), ('enabled_unstable_features', []), ('configuration', None)]:
            broken = copy.deepcopy(doc); broken[key] = replacement
            assert runner.observe(slot, p, broken)['outcome'] == 'INCONCLUSIVE'
            count += 1
        broken = copy.deepcopy(doc); broken['harness_selection']['requested_filters'] = ['wrong']
        assert runner.observe(slot, p, broken)['outcome'] == 'INCONCLUSIVE'
        broken = copy.deepcopy(p); broken['property_inventory'] = {'other': []}
        assert runner.observe(slot, broken, doc)['outcome'] == 'INCONCLUSIVE'
        for key in doc['configuration']['checks']:
            broken = copy.deepcopy(doc); broken['configuration']['checks'][key] = not broken['configuration']['checks'][key]
            assert runner.observe(slot, p, broken)['outcome'] == 'INCONCLUSIVE'
            count += 1
        broken = copy.deepcopy(p)
        broken['property_inventory'][runner.SLOTS[slot][1]][0]['description'] = 'unrelated assertion'
        assert runner.observe(slot, broken, doc)['outcome'] == 'INCONCLUSIVE'

    for slot in runner.SLOTS:
        process = {'argv': runner.argv_for(slot, '/synthetic-export.json', '/synthetic-target'),
                   'cwd': str(runner.HERE), 'environment': runner.ENV.copy()}
        runner.check_invocation(slot, process)
        for flag, replacement in [('--features', 'other'), ('--harness', 'other'),
                                  ('--manifest-path', '/wrong/Cargo.toml')]:
            bad = copy.deepcopy(process); bad['argv'][bad['argv'].index(flag) + 1] = replacement
            try:
                runner.check_invocation(slot, bad)
            except ValueError:
                pass
            else:
                raise AssertionError('wrong source/cfg/selection accepted')
        bad = copy.deepcopy(process); bad['environment']['RUSTFLAGS'] = '--cfg other'
        try:
            runner.check_invocation(slot, bad)
        except ValueError:
            pass
        else:
            raise AssertionError('wrong compiler flags accepted')

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory)
        for code, expected in [('print("ok")', 0), ('raise SystemExit(7)', 7),
                               ('import os,signal; os.kill(os.getpid(),signal.SIGTERM)', -15)]:
            record = service.execute([sys.executable, '-c', code], path, 2)
            assert record['exit'] == expected and record['termination'] == 'EXITED'
            assert record['signal'] == (15 if expected == -15 else None)
        assert service.execute([sys.executable, '-c', 'import time;time.sleep(5)'], path, .05)['termination'] == 'TIMEOUT'
        assert service.execute([str(path / 'missing')], path, 1)['termination'] == 'SPAWN_ERROR'
        with patch.object(service, 'group_rss', return_value=service.RSS_CAP + 1):
            assert service.execute([sys.executable, '-c', 'import time;time.sleep(1)'], path, 1)['termination'] == 'RSS_CAP'
        with patch.object(service, 'STREAM_CAP', 1024):
            record = service.execute([sys.executable, '-c', 'print("x"*100000)'], path, 1)
            assert record['termination'] == 'OUTPUT_CAP' and not record['diagnostics_complete']
        # Place the relevant diagnostic beyond both the head and tail previews.
        header = failure()['diagnostics'][0]['header']
        code = 'print("x\\n"*5000 + ' + repr(header) + ' + "\\n" + "y\\n"*5000);raise SystemExit(1)'
        record = service.execute([sys.executable, '-c', code], path, 2)
        assert record['diagnostics'][0]['header'] == header
        assert not any(header in x for x in record['streams']['stdout']['head'] + record['streams']['stdout']['tail'])
        assert runner.observe('ordinary', record, None)['outcome'] == 'INCONCLUSIVE'  # diagnostic block cap
        # A bounded error block between unrelated lines remains independently available.
        code = 'print("x\\n"*5000 + ' + repr(header) + ' + "\\nerror: aborting due to 1 previous error\\n");raise SystemExit(1)'
        record = service.execute([sys.executable, '-c', code], path, 2)
        assert runner.observe('ordinary', record, None)['outcome'] == 'MISSING_CONTRACT_CLOSURE'
        # Run all three slots despite a target failure, preserving each native exit.
        for mode, expected in [('SUCCESS', 'DEFECT_ABSENT'), ('MISSING_CONTRACT_CLOSURE', 'DEFECT_PRESENT')]:
            calls = []
            def execute(argv, cwd, timeout, env):
                slot = next(k for k, (_, name) in runner.SLOTS.items() if name == argv[argv.index('--harness') + 1])
                calls.append(slot)
                process, doc = sample(slot)
                if slot == 'ordinary' and mode != 'SUCCESS':
                    process, doc = failure(), None
                if doc:
                    Path(argv[argv.index('--export-json') + 1]).write_text(json.dumps(doc))
                return process | {'argv': argv, 'cwd': str(cwd), 'environment': env}
            value = state()
            with patch.object(runner, 'OUT', path), patch.object(runner, 'execute', execute):
                runner.run_slots(value)
                assert calls == list(runner.SLOTS)
                assert runner.classify(value)[0] == expected
                stored = json.loads((path / 'result.json').read_text())
                integrity = stored.pop('integrity')
                assert hashlib.sha256(runner.canonical(stored)).hexdigest() == integrity['canonical_payload_sha256']
        calls = []
        def broken_execute(argv, cwd, timeout, env):
            calls.append(argv)
            return failure('error: unrelated')
        with patch.object(runner, 'OUT', path), patch.object(runner, 'execute', broken_execute):
            value = state(); runner.run_slots(value)
            assert len(calls) == 3 and runner.classify(value)[0] == 'INCONCLUSIVE'
        for argv in calls:
            assert argv[0].startswith(str(runner.SOURCE)) and '--exact' in argv and '-j1' in argv
            assert argv[argv.index('--features') + 1] in runner.SLOTS

    from check_push_identity import check as check_push_identity
    identity_checks = check_push_identity()

    with tempfile.TemporaryDirectory() as directory:
        out = Path(directory)
        calls = []
        def build_error(argv, cwd, timeout, env):
            calls.append(argv)
            return failure('error: synthetic build failure') | {'exit': 101}
        with patch.object(runner, 'OUT', out), patch.object(runner, 'execute', build_error), \
                patch.object(runner, 'snapshot', return_value={'problems': [], 'tools': {}}):
            assert runner.main('build') == 1
            assert calls == [['cargo', 'build-dev']]
            assert runner.load()['build']['exit'] == 101
            assert runner.main('run') == 2 and len(calls) == 1
            assert all(s['observation']['outcome'] == 'NOT_RUN' for s in runner.load()['slots'].values())
            (out / 'result.json').unlink()
            assert runner.main('finish') == 0
            value = runner.load()
            assert value['classification'] == 'INCONCLUSIVE'
            assert all(s['observation']['outcome'] == 'NOT_RUN' for s in value['slots'].values())

    workflow = (runner.ROOT / '.github/workflows/stub-contract-confirm.yml').read_text()
    expressions = workflow_expressions(workflow)
    assert expressions and workflow.count('${{') == len(expressions)
    assert 'fetch-depth: 2' in workflow and 'path: stock' in workflow and 'path: control' in workflow
    assert 'ref: ' + runner.BASE in workflow
    assert "on:\n  push:\n    branches:\n      - 'stub-contract-confirm-ci/**'\npermissions:" in workflow
    assert all(x not in workflow for x in ('workflow_dispatch', 'schedule:', 'inputs.', 'SC_CONTROL_HEAD', 'SC_CONTROL_TREE', 'SC_REQUEST_SHA256'))
    assert not (runner.ROOT / '.github/workflows/slow-tests.yml').exists()
    assert 'path: ${{ env.SC_EVIDENCE_DIR }}/result.json' in workflow
    for stage in ('before', 'build', 'run', 'finish'):
        assert 'runner.py ' + stage in workflow
    print(json.dumps({'status': 'PASS', 'scope': 'STATIC_PYTHON_MOCK_ONLY', 'mutation_cases': count, 'push_identity': identity_checks,
                      'native_compiler_kani_ci': 'NOT_RUN', 'service': ['success', 'nonzero', 'signal',
                       'timeout', 'RSS', 'output cap', 'spawn', 'middle diagnostics', 'partial',
                       'wrong target', 'missing control', 'three-slot collection', 'workflow contexts']}))


if __name__ == '__main__':
    check()
