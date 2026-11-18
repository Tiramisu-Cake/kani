#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Collect separately selected contract and ordinary-stub observations."""
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
from push_identity import push_event

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SOURCE = Path(os.environ.get('SC_SOURCE_DIR', str(ROOT.parent / 'stock'))).resolve()
OUT = Path(os.environ.get('SC_EVIDENCE_DIR', str(ROOT.parent / 'stub-contract-evidence')))
PROFILE = ROOT / '.github/stub-contract-confirm/profile.json'
BASE = 'faffcee3bca2770c03bd21c3bde89cc8f6f7a14e'
TREE = '09b828b47c93e90e140e8c41f9048109a2f4a786'
PARENT = 'a3c8b8610739aab7d2c864bd4021086a5e7c0d94'
SLOTS = {'provider': ('provider', 'provider'), 'verified': ('verified', 'verified_control'),
         'ordinary': ('ordinary', 'ordinary_stub')}
ENV = {'RUSTFLAGS': '', 'CARGO_ENCODED_RUSTFLAGS': None, 'KANIFLAGS': '', 'KANI_LOG': '',
       'RUST_BACKTRACE': '0', 'NO_COLOR': '1', 'CARGO_TARGET_DIR': None,
       'CARGO_BUILD_TARGET': None, 'RUSTUP_TOOLCHAIN': 'nightly-2026-11-12',
       'KANI_FAIL_ON_UNEXPECTED_DESCRIPTION': 'true', 'FLAMEGRAPH': None}
MISSING = re.compile(r'^error: Failed to find contract closure `__kani_recursion_check_f` '
                     r'in function `(?:stub_contract_confirm::)?f`$')
UNSUPPORTED = ('error: ordinary stubbing of contracted function `stub_contract_confirm::f` '
               'is unsupported; use `kani::stub_verified` to use its contract')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1048576), b''):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE).decode().strip()


def binding(control_head, control_tree, profile_sha):
    return {'schema': 'stub-contract-request-v1', 'base': BASE, 'base_tree': TREE,
            'base_parent': PARENT, 'control_head': control_head, 'control_tree': control_tree,
            'control_parent': BASE, 'profile_sha256': profile_sha}


def snapshot(built=False):
    value = {'problems': [], 'source': {}, 'control': {}, 'tools': {}}
    try:
        profile = json.loads(PROFILE.read_text())
        require(profile['base'] == BASE and profile['tree'] == TREE, 'profile baseline')
        for label, root in [('source', SOURCE), ('control', ROOT)]:
            record = {key: git(root, 'rev-parse', ref) for key, ref in (
                ('head', 'HEAD'), ('tree', 'HEAD^{tree}'), ('parent', 'HEAD^'),
                ('shallow', '--is-shallow-repository'))}
            require(len(git(root, 'show', '-s', '--format=%P', 'HEAD').split()) == 1, 'merge head')
            value[label] = record
            require(not git(root, 'diff', 'HEAD', '--'), label + ' tracked mutation')
            extra = git(root, 'ls-files', '--others', '--exclude-standard').splitlines()
            require(not any(p.endswith(('.rs', '.toml', '.py', '.sh', '.yml', '.json')) for p in extra),
                    label + ' untracked source')
        require(value['source']['head'] == BASE and value['source']['tree'] == TREE
                and value['source']['parent'] == PARENT, 'stock source identity')
        require(value['control']['parent'] == BASE, 'control parent')
        value['push'] = push_event(ROOT, value['control'])
        request = binding(value['control']['head'], value['control']['tree'], sha(PROFILE))
        value['request'] = request
        value['request_sha256'] = hashlib.sha256(canonical(request)).hexdigest()
        changes = git(ROOT, 'diff', '--name-status', BASE, 'HEAD').splitlines()
        for change in changes:
            status, path = change.split('\t')
            allowed = path.startswith(('tests/script-based-pre/stub-contract-confirm/',
                                       '.github/stub-contract-confirm/'))
            allowed |= path == '.github/workflows/stub-contract-confirm.yml'
            allowed |= status == 'D' and path.startswith('.github/workflows/')
            require(allowed, 'control source changed: ' + path)
        value['control']['changes'] = changes
        value['files'] = {}
        for scope, root in [('source_sha256', SOURCE), ('control_sha256', ROOT)]:
            for path, digest in profile[scope].items():
                actual = sha(root / path)
                value['files'][scope + '/' + path] = actual
                require(actual == digest, 'file identity: ' + path)
        if built:
            for name in ('kani-driver', 'kani-compiler'):
                path = SOURCE / 'target/kani/bin' / name
                require(path.is_file(), 'missing built ' + name)
                value['tools'][name] = {'path': str(path.resolve()), 'sha256': sha(path)}
            for name in ('cargo', 'rustc', 'cbmc'):
                path = shutil.which(name)
                require(path is not None, 'missing tool ' + name)
                if name in ('cargo', 'rustc'):
                    path = subprocess.check_output(['rustup', 'which', '--toolchain',
                        ENV['RUSTUP_TOOLCHAIN'], name], stderr=subprocess.PIPE).decode().strip()
                value['tools'][name] = {'path': path, 'resolved': str(Path(path).resolve()),
                                        'sha256': sha(Path(path))}
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        value['problems'].append(str(error))
    return value


def valid_process(process):
    require(isinstance(process, dict) and process.get('termination') == 'EXITED', 'native termination')
    require(type(process.get('exit')) is int, 'native exit')
    require(process.get('diagnostics_complete') is True, 'incomplete diagnostics')
    require(set(process.get('streams', {})) == {'stdout', 'stderr'}, 'missing streams')
    require(all(x.get('complete') is True for x in process['streams'].values()), 'incomplete streams')


def success(doc, process, name, assertion=None):
    valid_process(process)
    require(process['exit'] == 0 and process.get('signal') is None, 'success exit')
    require(not process['diagnostics'], 'error during success')
    require(isinstance(doc, dict) and doc.get('schema_version') == '0.1.0', 'export schema')
    require(doc.get('run_state') == 'COMPLETE' and doc.get('outcome') == {'kind': 'COMPLETED'}, 'partial export')
    require(doc.get('target') == 'x86_64-unknown-linux-gnu', 'target mismatch')
    require({'function-contracts', 'stubbing', 'export-json'} <= set(doc.get('enabled_unstable_features', [])),
            'feature mismatch')
    selection = doc['harness_selection']
    require(selection['exact'] is True and selection['requested_filters'] == [name]
            and selection['unmatched_filters'] == [] and type(selection['matched_count']) is int
            and selection['matched_count'] == 1, 'selection mismatch')
    config = doc['configuration']
    require(config['coverage_enabled'] is False and config['cbmc_args'] == [], 'solver configuration')
    for check in ('memory_safety', 'overflow', 'unwinding', 'undefined_function', 'assertion_reach_checks'):
        require(config['checks'][check] is True, 'disabled check ' + check)
    require(config['checks']['prove_safety_only'] is False and config['checks']['ignore_global_asm'] is False,
            'weakened checks')
    entries = doc['harnesses']
    require(isinstance(entries, list) and len(entries) == 1, 'harness count')
    entry = entries[0]
    require(entry['name'] == name and entry['outcome'] == {'kind': 'COMPLETED', 'verdict': 'SUCCESS'}, 'harness outcome')
    require(entry['is_automatically_generated'] is False and entry['is_bounded'] is False, 'harness kind')
    checks = entry['checks']
    count = checks['total']
    require(type(count) is int and 0 < count <= 256 and entry['n_properties'] == count
            and type(checks['success']) is int and checks['success'] == count, 'check counts')
    for bucket in ('failure', 'unreachable', 'undetermined', 'error', 'unknown', 'other'):
        require(checks[bucket] == [], 'unresolved or unreachable check')
    require(entry['n_failed'] == 0 and entry['failed_properties'] == []
            and entry['covers']['total'] == 0, 'unexpected failures/covers')
    inventory = process['property_inventory']
    require(set(inventory) == {name}, 'stdout target inventory')
    props = inventory[name]
    require(len(props) == count and [p['index'] for p in props] == list(range(1, count + 1)), 'property partition')
    require(len({p['id'] for p in props}) == count, 'duplicate property')
    require(all(p['status'] == 'SUCCESS' and p['description'] and p['location'] for p in props), 'property state')
    for unsupported in entry['unsupported_constructs']:
        require(any(p['id'] == unsupported['id'] and p['status'] == unsupported['status'] == 'SUCCESS'
                    and p['description'] == unsupported['description'] for p in props), 'unsupported construct')
    if assertion:
        require(any(p['description'] == assertion and p['location'].endswith('in function ' + name)
                    for p in props), 'missing semantic assertion')
    else:
        require(any(re.sub(r'\s+', '', p['description']) == '|result|*result==x+1'
                    for p in props), 'missing provider postcondition')
    require(process['verification_success'] == 1, 'missing verification result')
    return {'outcome': 'SUCCESS', 'export': doc}


def observe(slot, process, doc):
    try:
        valid_process(process)
        headers = [d['header'] for d in process['diagnostics']]
        if slot == 'ordinary' and process['exit'] != 0:
            require(doc is None and not process.get('property_inventory'), 'mixed compile/verification evidence')
            primary = [h for h in headers if not h.startswith(('error: aborting due to ', 'error: could not compile '))]
            if len(primary) == 1 and MISSING.fullmatch(primary[0]):
                return {'outcome': 'MISSING_CONTRACT_CLOSURE', 'export_present': doc is not None}
            if primary == [UNSUPPORTED]:
                return {'outcome': 'EXPLICIT_UNSUPPORTED', 'export_present': doc is not None}
            raise ValueError('unrelated or ambiguous compiler error')
        name = SLOTS[slot][1]
        assertion = {'verified': 'assertion failed: f(x) == x + 1',
                     'ordinary': 'assertion failed: f(x) == x + 2'}.get(slot)
        return success(doc, process, name, assertion)
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        return {'outcome': 'INCONCLUSIVE', 'reason': str(error)}


def classify(value):
    try:
        require(value.get('setup') == 'SUCCESS', 'setup not successful')
        valid_process(value['build'])
        require(value['build']['exit'] == 0, 'compiler build failure')
        require(value.get('source_before', {}).get('problems') == []
                and value.get('source_after', {}).get('problems') == [], 'source binding incomplete')
        require(value['source_before']['tools'] == value['source_after']['tools'], 'tool drift')
        require(set(value['slots']) == set(SLOTS), 'missing slot')
        for slot in ('provider', 'verified'):
            require(value['slots'][slot]['observation']['outcome'] == 'SUCCESS', slot + ' control failure')
        outcome = value['slots']['ordinary']['observation']['outcome']
        if outcome == 'MISSING_CONTRACT_CLOSURE':
            return 'DEFECT_PRESENT', ['selected ordinary target has the exact missing-closure diagnostic']
        if outcome == 'SUCCESS':
            return 'DEFECT_ABSENT', ['ordinary substitution assertion verified']
        if outcome == 'EXPLICIT_UNSUPPORTED':
            return 'INCONCLUSIVE', ['EXPLICIT_UNSUPPORTED: the frozen main documentation does not declare this restriction; review the support policy separately']
        raise ValueError('ordinary result inconclusive')
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        return 'INCONCLUSIVE', [str(error)]


def initial():
    return {'schema': 'stub-contract-result-v1', 'classification': 'INCONCLUSIVE', 'reasons': ['NOT_RUN'],
            'setup': 'NOT_RUN', 'build': {'termination': 'NOT_RUN', 'exit': None},
            'slots': {s: {'observation': {'outcome': 'NOT_RUN'}, 'process': {'termination': 'NOT_RUN'}} for s in SLOTS}}


def load():
    path = OUT / 'result.json'
    return json.loads(path.read_text()) if path.exists() else initial()


def save(value):
    OUT.mkdir(parents=True, exist_ok=True)
    value.pop('integrity', None)
    payload = canonical(value)
    value['integrity'] = {'algorithm': 'sha256', 'canonical_payload_sha256': hashlib.sha256(payload).hexdigest(),
                          'canonicalization': 'json sort_keys separators comma/colon UTF-8; omit integrity'}
    path = OUT / 'result.json'
    path.with_suffix('.next').write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
    path.with_suffix('.next').replace(path)


def argv_for(slot, export, target):
    feature, name = SLOTS[slot]
    return [str(SOURCE / 'scripts/cargo-kani'), 'kani', '--manifest-path', str(HERE / 'Cargo.toml'),
            '--lib', '--no-default-features', '--features', feature, '--exact', '--harness', name,
            '-j1', '-Z', 'function-contracts', '-Z', 'stubbing', '-Z', 'export-json',
            '--export-json', str(export), '--output-format=regular', '--target-dir', str(target)]


def check_invocation(slot, process):
    argv = process['argv']
    export = argv[argv.index('--export-json') + 1]
    target = argv[argv.index('--target-dir') + 1]
    require(argv == argv_for(slot, export, target), 'native argv/target/cfg mismatch')
    require(process['cwd'] == str(HERE), 'native cwd mismatch')
    require(all(process['environment'].get(k) == v for k, v in ENV.items()), 'native environment mismatch')


def run_slots(value):
    for slot in SLOTS:
        with tempfile.TemporaryDirectory(prefix='stub-contract-' + slot + '-') as directory:
            scratch = Path(directory)
            export = scratch / 'export.json'
            argv = argv_for(slot, export, scratch / 'target')
            process = execute(argv, HERE, 120, ENV)
            identity = {'slot': slot, 'feature': SLOTS[slot][0], 'harness': SLOTS[slot][1],
                        'argv': argv, 'environment': ENV,
                        'request_sha256': value.get('source_before', {}).get('request_sha256'),
                        'manifest_sha256': sha(HERE / 'Cargo.toml'),
                        'fixture_sha256': sha(HERE / 'src/lib.rs')}
            process['invocation_identity'] = identity
            process['invocation_sha256'] = hashlib.sha256(canonical(identity)).hexdigest()
            doc = None
            export_record = {'present': export.exists(), 'complete': False}
            if export.exists():
                export_record['bytes'] = export.stat().st_size
                if export_record['bytes'] <= 2 * 1024 * 1024:
                    export_record['sha256'] = sha(export)
                    try:
                        doc = json.loads(export.read_text())
                        export_record['complete'] = True
                    except (ValueError, OSError):
                        pass
            try:
                check_invocation(slot, process)
                observation = observe(slot, process, doc)
            except (ValueError, KeyError, TypeError, AttributeError, IndexError) as error:
                observation = {'outcome': 'INCONCLUSIVE', 'reason': str(error)}
            if export_record['present'] and not export_record['complete']:
                observation = {'outcome': 'INCONCLUSIVE', 'reason': 'incomplete export'}
            # The exact invocation and immutable fixture inventory bind errors without a RESULTS section.
            value['slots'][slot] = {'feature': SLOTS[slot][0], 'selected_harness': SLOTS[slot][1],
                                    'process': process, 'export_inventory': export_record,
                                    'observation': observation}
            save(value)


def main(stage):
    value = load()
    if stage == 'before':
        value = initial()
        value['preflight'] = snapshot()
        save(value)
        return int(bool(value['preflight']['problems']))
    if stage == 'build':
        value['setup'] = 'SUCCESS'
        preflight = snapshot()
        value['build_preflight'] = preflight
        if not preflight['problems']:
            value['build'] = execute(['cargo', 'build-dev'], SOURCE, 900, ENV)
        save(value)
        return int(value['build'].get('exit') != 0)
    if stage == 'run':
        value['source_before'] = snapshot(built=True)
        if (value.get('setup') == 'SUCCESS' and value['build'].get('exit') == 0
                and not value['source_before']['problems']):
            run_slots(value)
        value['source_after'] = snapshot(built=True)
    if stage in ('run', 'finish'):
        if stage == 'finish':
            value['setup_action_outcome'] = os.environ.get('SC_SETUP_OUTCOME', 'UNKNOWN')
            if value['setup_action_outcome'] != 'success':
                value['setup'] = value['setup_action_outcome'].upper()
            value.setdefault('source_after', snapshot(built=value['build'].get('exit') == 0))
            value['job_status'] = os.environ.get('SC_JOB_STATUS', 'UNKNOWN')
        value['classification'], value['reasons'] = classify(value)
        if stage == 'finish' and value['job_status'] != 'success':
            value['classification'] = 'INCONCLUSIVE'
            value['reasons'].append('workflow status: ' + value['job_status'])
        save(value)
        return 0 if stage == 'finish' else (2 if value['classification'] == 'INCONCLUSIVE' else 0)
    raise ValueError('unknown stage')


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))
