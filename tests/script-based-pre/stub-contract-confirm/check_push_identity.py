# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Exercise push admission and publication binding using disposable Git repositories."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch

import final_head
import runner
from push_identity import PREFIX, REPOSITORY


def event_for(root, head, ref):
    return {'repository': {'full_name': REPOSITORY}, 'ref': ref, 'after': head,
            'before': '0' * 40, 'created': True, 'deleted': False, 'forced': False,
            'head_commit': {'id': head, 'message': runner.git(root, 'show', '-s', '--format=%B', head)}}


def check():
    cases = []
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        repo, stock, control = [root / p for p in ('repo', 'stock', 'control')]
        repo.mkdir()
        def git(*args, cwd=repo):
            return runner.git(cwd, *args)
        def commit(message):
            git('-c', 'user.name=Service test', '-c', 'user.email=test@example.invalid',
                'commit', '-q', '--no-gpg-sign', '--allow-empty', '-m', message)
            return git('rev-parse', 'HEAD')
        git('init', '-q')
        (repo / 'stock.txt').write_text('stock\n'); git('add', 'stock.txt')
        parent = commit('parent'); base = commit('base'); tree = git('rev-parse', 'HEAD^{tree}')
        git('clone', '-q', '--depth=2', repo.as_uri(), str(stock))
        profile = repo / '.github/stub-contract-confirm/profile.json'
        profile.parent.mkdir(parents=True)
        profile.write_text(json.dumps({'base': base, 'tree': tree, 'source_sha256': {}, 'control_sha256': {}}))
        git('add', str(profile)); head = commit('confirmation candidate'); control_tree = git('rev-parse', 'HEAD^{tree}')
        git('clone', '-q', '--depth=2', repo.as_uri(), str(control))
        assert git('rev-parse', '--is-shallow-repository', cwd=control) == 'true'
        assert git('rev-list', '--count', 'HEAD', cwd=control) == '2'
        event_path = root / 'event.json'
        ref = PREFIX + 'synthetic'
        event = event_for(control, head, ref)
        event_path.write_text(json.dumps(event))
        env = {'GITHUB_EVENT_NAME': 'push', 'GITHUB_REPOSITORY': REPOSITORY,
               'GITHUB_REF': ref, 'GITHUB_SHA': head, 'GITHUB_EVENT_PATH': str(event_path)}
        clean_env = {k: v for k, v in os.environ.items() if not k.startswith('SC_') and not k.startswith('GITHUB_')}
        with patch.object(runner, 'ROOT', control), patch.object(runner, 'SOURCE', stock), \
                patch.object(runner, 'PROFILE', control / '.github/stub-contract-confirm/profile.json'), \
                patch.object(runner, 'BASE', base), patch.object(runner, 'TREE', tree), patch.object(runner, 'PARENT', parent), \
                patch.object(runner, 'OUT', root / 'out'), patch.dict(os.environ, clean_env | env, clear=True):
            value = runner.snapshot()
            assert not value['problems'], value
            request = runner.binding(head, control_tree, runner.sha(runner.PROFILE))
            assert value['request'] == request
            assert value['request_sha256'] == hashlib.sha256(runner.canonical(request)).hexdigest()
            cases.append('real depth2 actual push binding')
            nested_ref = PREFIX + 'nested/confirmation'
            event_path.write_text(json.dumps(event | {'ref': nested_ref}))
            with patch.dict(os.environ, {'GITHUB_REF': nested_ref}):
                assert not runner.snapshot()['problems']
            event_path.write_text(json.dumps(event))
            cases.append('nested branch matches exact filter')
            def rejected(label):
                with patch.object(runner, 'execute', side_effect=AssertionError('build invoked before admission')):
                    assert runner.snapshot()['problems'], label
                    assert runner.main('build') == 1, label
                    cases.append(label)
            for key in env:
                with patch.dict(os.environ, clear=False):
                    del os.environ[key]
                    rejected('missing ' + key)
            for key, bad in [('GITHUB_EVENT_NAME', 'workflow_dispatch'), ('GITHUB_EVENT_NAME', 'schedule'),
                             ('GITHUB_REPOSITORY', 'model-checking/kani'), ('GITHUB_SHA', base),
                             ('GITHUB_SHA', 'wrong'), ('GITHUB_REF', 'refs/heads/main'),
                             ('GITHUB_REF', 'refs/tags/stub-contract-confirm-ci/x'),
                             ('GITHUB_REF', PREFIX), ('GITHUB_REF', PREFIX + '../bad'),
                             ('SC_CONTROL_HEAD', head), ('SC_CONTROL_TREE', control_tree),
                             ('SC_REQUEST_SHA256', value['request_sha256'])]:
                with patch.dict(os.environ, {key: bad}):
                    rejected(key + '=' + bad)
            for key, bad in [('ref', PREFIX + 'other'), ('after', base), ('before', base),
                             ('created', False), ('created', 1), ('deleted', True), ('forced', True),
                             ('inputs', {}), ('repository', None), ('head_commit', None),
                             ('head_commit', {'id': base, 'message': 'wrong'}),
                             ('head_commit', {'id': head, 'message': 'wrong'})]:
                event_path.write_text(json.dumps(event | {key: bad}))
                rejected('payload ' + key + '=' + str(bad))
            for bad in (None, [], {}, 'NOT_RUN'):
                event_path.write_text(json.dumps(bad)); rejected('payload type ' + str(bad))
            event_path.write_text('{'); rejected('malformed payload')
            event_path.write_text(json.dumps(event))
            (stock / 'stock.txt').write_text('changed\n'); rejected('stock mutation')
            git('checkout', '--', 'stock.txt', cwd=stock)
            (control / 'extra.rs').write_text('// source\n'); rejected('untracked source'); (control / 'extra.rs').unlink()
            original = runner.PROFILE.read_bytes()
            runner.PROFILE.write_text('{}'); rejected('profile mutation'); runner.PROFILE.write_bytes(original)
            with patch.object(runner, 'BASE', parent):
                rejected('wrong stock parent baseline')
            git('fetch', '-q', '--depth=1', 'origin', base, cwd=stock); rejected('source depth1')
            git('fetch', '-q', '--depth=2', 'origin', base, cwd=stock)
            git('fetch', '-q', '--depth=1', 'origin', head, cwd=control); rejected('control depth1')

        pins = {'stock': {'head': base, 'tree': tree, 'parent': parent},
                'control': {'head': head, 'tree': control_tree, 'parent': base},
                'profile_sha256': hashlib.sha256(original).hexdigest(), 'publication': {'ref': ref}}
        def gate(final, supplied=None, expected_pins=pins):
            return final_head.check(repo, final, ref, supplied, expected_pins)
        gate_before = (git('rev-parse', 'HEAD'), git('status', '--porcelain'))
        derived = gate(head)
        assert derived['status'] == 'DERIVED_REQUIRES_EXACT_REQUEST_GATE'
        assert derived['request_binding'] == request
        assert gate(head, derived['request_sha256'])['status'] == 'FINAL_HEAD_REQUEST_GATE_PASS'
        assert gate_before == (git('rev-parse', 'HEAD'), git('status', '--porcelain'))
        cases.append('read-only exact no-skip candidate request gate')
        def gate_reject(label, final=head, supplied=derived['request_sha256'], expected_pins=pins):
            try:
                gate(final, supplied, expected_pins)
            except (ValueError, subprocess.SubprocessError):
                cases.append(label)
            else:
                raise AssertionError(label)
        gate_reject('wrong final request', supplied='0' * 64)
        gate_reject('exact final sha required', final='HEAD')
        for section, key, bad in [('control', 'tree', tree), ('control', 'parent', parent),
                                   ('stock', 'tree', control_tree), ('stock', 'parent', base),
                                   ('control', 'head', base), ('publication', 'ref', PREFIX + 'wrong')]:
            broken = copy.deepcopy(pins); broken[section][key] = bad
            gate_reject('wrong pins ' + section + '/' + key, expected_pins=broken)
        broken = copy.deepcopy(pins); broken['profile_sha256'] = '0' * 64
        gate_reject('wrong profile digest', expected_pins=broken)
        def sibling(message):
            return git('-c', 'user.name=Service test', '-c', 'user.email=test@example.invalid',
                       'commit-tree', control_tree, '-p', base, '-m', message)
        final = sibling('confirmation publication sibling')
        derived_final = gate(final)
        assert derived_final['same_tree_sibling'] and derived_final['request_sha256'] != derived['request_sha256']
        assert gate(final, derived_final['request_sha256'])['status'] == 'FINAL_HEAD_REQUEST_GATE_PASS'
        gate_reject('sibling rejects candidate request', final=final)
        for marker in ('[skip ci]', '[ci skip]', '[no ci]', '[skip actions]', '[actions skip]', 'skip-checks: true'):
            gate_reject('skip marker ' + marker, final=sibling('confirmation\n\n' + marker))
        extra = commit('additional control commit')
        gate_reject('multi-commit publication range', final=extra)
        merge = git('-c', 'user.name=Service test', '-c', 'user.email=test@example.invalid',
                    'commit-tree', control_tree, '-p', base, '-p', parent, '-m', 'merge')
        gate_reject('merge parent', final=merge)
        git('fetch', '-q', '--depth=2', 'origin', final, cwd=control)
        git('checkout', '-q', '--detach', final, cwd=control)
        event_path.write_text(json.dumps(event_for(control, final, ref)))
        with patch.object(runner, 'ROOT', control), patch.object(runner, 'SOURCE', stock), \
                patch.object(runner, 'PROFILE', control / '.github/stub-contract-confirm/profile.json'), \
                patch.object(runner, 'BASE', base), patch.object(runner, 'TREE', tree), patch.object(runner, 'PARENT', parent), \
                patch.dict(os.environ, clean_env | env | {'GITHUB_SHA': final}, clear=True):
            value = runner.snapshot()
            assert not value['problems'], value
            assert value['request'] == derived_final['request_binding']
            assert value['request_sha256'] == derived_final['request_sha256']
            cases.append('sibling runtime actual head/request rebinding')
            skipped = sibling('confirmation [skip ci]')
            git('fetch', '-q', '--depth=2', 'origin', skipped, cwd=control)
            git('checkout', '-q', '--detach', skipped, cwd=control)
            event_path.write_text(json.dumps(event_for(control, skipped, ref)))
            with patch.dict(os.environ, {'GITHUB_SHA': skipped}):
                assert runner.snapshot()['problems']
                cases.append('runtime skip head rejected')
    return {'status': 'PASS', 'scope': 'DISPOSABLE_GIT_PYTHON_MOCK_ONLY', 'checks': len(cases), 'cases': cases}
