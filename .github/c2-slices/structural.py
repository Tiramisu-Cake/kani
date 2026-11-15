#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Bounded CI-only C2-S4 fresh mixed/isolated comparison. Never bless snapshots."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import time
import structural_observation as observer
from structural_compare import compare_root, compare_selection, require

HERE = Path(__file__).resolve().parent


def digest(path):
    result = hashlib.sha256()
    with Path(path).open('rb') as data:
        for block in iter(lambda: data.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def invocations(manifest):
    roots = manifest['roots']
    result = [dict(id='isolated-' + r['name'], selectors=[r['name']]) for r in roots]
    result.extend(dict(id=r['id'], selectors=r['selectors']) for r in manifest['orders'])
    for row in result:
        row['expected_exit'] = int(any(r['expected_verdict'] == 'FAILURE' for r in roots if r['name'] in row['selectors']))
    return result


def command(root, manifest, row, directory):
    argv = [str(root / 'scripts/kani'), str(HERE / Path(manifest['source']).name),
            '-Z', 'uninit-checks', '-Z', 'function-contracts', '-Z', 'export-json', '-Z', 'unstable-options']
    for selector in row['selectors']:
        argv += ['--harness', selector]
    return argv + ['--exact', '--jobs', '1', '--target-dir', str(directory / 'target'),
                   '--export-json', str(directory / 'export.json'), '--output-format=regular',
                   '--cbmc-args', '--object-bits', '12']


def validate_result(record, expected_exit):
    require(record.get('termination_reason') == 'EXIT', 'nonterminal/timeout/launch result')
    require(type(record.get('exit')) is int and record['exit'] == expected_exit, 'unexpected original Kani exit')
    require(not record.get('problems') and not record.get('exception'), 'process/output error')


def tools(root):
    paths = {name: root / 'target/kani/bin' / name for name in ('kani-driver', 'kani-compiler')}
    for name in ('cbmc', 'kissat'):
        found = shutil.which(name)
        require(found is not None, 'missing tool: ' + name)
        paths[name] = Path(found)
    return {name: dict(path=str(path), resolved=str(path.resolve(strict=True)), sha256=digest(path))
            for name, path in paths.items()}


def run(ci, out):
    directory = out / 'structural'
    directory.mkdir(parents=True, exist_ok=True)
    summary = dict(status='NOT_RUN', native_result='NOT_RUN', source_sha=None, runs=[], comparisons=[],
                   binding_status='NOT_CHECKED_CAPTURE', producer_order='ORDER_UNCONTROLLED',
                   order_credit='NOT_ESTABLISHED', independent_proof_credit='NOT_ESTABLISHED')
    old_env = {key: os.environ.get(key) for key in ('RUSTFLAGS', 'NO_COLOR', 'KANI_LOG')}
    try:
        config, _ = ci.inputs()
        summary['source_sha'] = config['source_sha']
        data = (HERE / 'structural-manifest.json').read_bytes()
        require(hashlib.sha256(data).hexdigest() == config['structural']['manifest_sha256'], 'structural manifest hash mismatch')
        manifest = json.loads(data)
        cases = {r['name']: r for r in manifest['roots']}
        calls = invocations(manifest)
        require(len(cases) == 7 and len(calls) == 11 and sum(len(r['selectors']) for r in calls[7:]) == 18, 'structural selection drift')
        source = HERE / Path(manifest['source']).name
        require(digest(source) == manifest['source_sha256'], 'structural input hash mismatch')
        require(not any(source.parent.glob('roots.json')), 'bound legacy inventory must not be installed')
        ci.snapshot('structural-before', directory)
        summary.update(source_tree=config['source_tree'], tools=tools(ci.ROOT), cpu_count=os.cpu_count(),
                       toolchain=(ci.ROOT / 'rust-toolchain.toml').read_text(),
                       manifest_sha256=hashlib.sha256(data).hexdigest(), source_sha256=manifest['source_sha256'])
        os.environ.update(RUSTFLAGS='--edition 2021 -D warnings', NO_COLOR='1', KANI_LOG='kani_compiler::kani_middle::codegen_units=debug')
        isolated = {}
        for row in calls:
            action = 'structural-' + row['id']
            base = out / action
            base.mkdir(parents=True, exist_ok=True)
            require(not (base / 'export.json').exists() and not (base / 'target').exists(), 'stale invocation outputs')
            before = digest(source)
            require(before == manifest['source_sha256'], 'input changed before invocation')
            started = time.time()
            ci.execute(action, command(ci.ROOT, manifest, row, base), out, timeout=180)
            record = json.loads((base / 'result.json').read_text())
            receipt = dict(id=row['id'], original_exit=record['exit'], termination_reason=record['termination_reason'],
                           argv=record['argv'], environment=record['environment'], expected_exit=row['expected_exit'],
                           started_epoch=started, finished_epoch=time.time(), build_prefix=str(ci.ROOT.parent), cwd=str(ci.ROOT),
                           source_sha256=before, input_sha256_after=digest(source))
            for name in ('export.json', 'stdout.txt', 'stderr.txt'):
                path = base / name
                receipt[name + '_sha256'] = digest(path) if path.exists() else None
            ci.save(base / 'receipt.json', receipt)
            summary['runs'].append(receipt)
            validate_result(record, row['expected_exit'])
            require(receipt['input_sha256_after'] == before, 'input changed during invocation')
            data = observer.load_export(base / 'export.json')
            regular = (base / 'stdout.txt').read_text(errors='replace') + '\n' + (base / 'stderr.txt').read_text(errors='replace')
            observation = observer.observation(data, regular, row['selectors'], cases, receipt)
            roots = compare_selection(observation, cases)
            require(set(roots) == set(row['selectors']), 'incomplete selected roots')
            ci.save(base / 'observation.json', observation)
            if row['id'].startswith('isolated-'):
                isolated.update(roots)
            else:
                for name in row['selectors']:
                    comparison = compare_root(isolated[name], roots[name])
                    summary['comparisons'].append(dict(order=row['id'], **comparison))
        require(len(summary['comparisons']) == 18, 'missing mixed comparison')
        require(all(r['accepted'] is True and r['exact_match'] is True and r['differences'] == {} for r in summary['comparisons']), 'mixed inventory drift')
        require(digest(source) == manifest['source_sha256'], 'structural input changed after runs')
        ci.snapshot('structural-after', directory)
        summary.update(status='PASS_EXACT_FRESH_MIXED_VS_OWN_ISOLATED', native_result='11_COMPLETED_INVOCATIONS_18_EXACT_COMPARISONS',
                       isolated_goldens='NOT_BOUND; semantic oracles checked separately by cumulative expected suite',
                       historical_baseline='run43621472749 reused as unchanged-source discriminator, not rerun or new credit')
        return True
    except (Exception, KeyboardInterrupt) as error:
        summary.update(status='FAIL_OR_UNKNOWN', error=repr(error))
        if isinstance(error, KeyboardInterrupt):
            raise
        return False
    finally:
        for key, value in old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        ci.save(directory / 'summary.json', summary)
        ci.save(directory / 'result.json', dict(name='structural', result=summary['status'], exit=None,
                aggregation_exit=0 if summary['status'] == 'PASS_EXACT_FRESH_MIXED_VS_OWN_ISOLATED' else 1,
                termination_reason='IN_PROCESS_AGGREGATION', original_child_exits='See structural-*/result.json and receipt.json'))
