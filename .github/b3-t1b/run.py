#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""CI-only display of existing T1 models. Never compiles or invokes a solver."""
import difflib
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'b3-t1'))
from compare import (load_arm, _object_no_duplicates, _contained_file, sha256,
                     Invalid, MODEL_KINDS, EXCLUDED_AB_TOOLS)
from analysis import normalize, classify, control

ARMS = ('A1', 'A2', 'B1')
MODES = ('symbol-table', 'goto-functions')
RUN_ID = '43701550489'
ARTIFACT = 'b3-t1-43701550489-1'
DEB = 'ubuntu-24.04-cbmc-6.11.0-Linux.deb'
URL = 'https://github.com/diffblue/cbmc/releases/download/cbmc-6.11.0/' + DEB


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    tmp.replace(path)


def read(path):
    return json.loads(path.read_text(), object_pairs_hook=_object_no_duplicates)


def require(value, message):
    if not value:
        raise Invalid(message)


def ident(key):
    return hashlib.sha256(key.encode()).hexdigest()[:32]


def validate(root):
    """Re-use T1's strict census; independently bind records and tools.json."""
    arms = {a: load_arm(root, a) for a in ARMS}
    baseline = arms['A1']
    keys = set(baseline['records'])
    require(len(keys) == 409, 'expected 409 records per arm from pinned T1 run')
    require(sum(r['kind'] == 'final' for r in baseline['records'].values()) == 131,
            'expected 131 final models including control')
    for arm, data in arms.items():
        require(set(data['records']) == keys, f'{arm}: logical inventory drift')
        require(data['rows'] == baseline['rows'] and data['locks'] == baseline['locks'],
                f'{arm}: rows/locks drift')
        tools = read(root / arm / 'tools.json')
        require(isinstance(tools, dict), f'{arm}: tools.json not an object')
        require(isinstance(tools.get('goto-instrument'), dict), f'{arm}: missing tool identity')
        require(tools['goto-instrument'].get('sha256') == data['tools']['goto-instrument'],
                f'{arm}: tools.json/index hash mismatch')
        excluded = EXCLUDED_AB_TOOLS if arm == 'B1' else set()
        require({k: v for k, v in data['tools'].items() if k not in excluded} ==
                {k: v for k, v in baseline['tools'].items() if k not in excluded},
                f'{arm}: tool drift')
        records = {}
        for p in sorted((root / arm / 'records').glob('*.json')):
            item = read(p)
            require(isinstance(item, dict) and set(item) == {'key', 'record'}, f'{arm}: malformed record')
            key, rec = item['key'], item['record']
            require(isinstance(key, str) and key not in records, f'{arm}: duplicate/invalid key')
            require(isinstance(rec, dict), f'{arm}: malformed record body')
            model = _contained_file(root / arm, rec.get('path'), key)
            require(sha256(model) == rec.get('sha256'), f'{arm}: record hash mismatch: {key}')
            records[key] = rec
        require(records == data['records'], f'{arm}: records/index mismatch')
        captured_files = {str(p.relative_to(root / arm))
                          for p in (root / arm / 'files').rglob('*') if p.is_file()}
        require(captured_files == {rec['path'] for rec in records.values()},
                f'{arm}: unrecorded or missing captured file')
        for key, rec in records.items():
            base = baseline['records'][key]
            require({k: v for k, v in rec.items() if k != 'sha256'} ==
                    {k: v for k, v in base.items() if k != 'sha256'},
                    f'{arm}: record provenance/argv drift: {key}')
            require(key.startswith(rec['kind'] + '/' + rec['row'] + '/'), f'{arm}: key/kind/row mismatch')
            if rec['kind'] == 'final':
                require(key == f"final/{rec['row']}/{rec['harness']}", f'{arm}: final binding mismatch')
    return arms


class Runner:
    def __init__(self, out, seconds=42 * 60):
        self.out = out
        self.deadline = time.monotonic() + seconds
        self.sequence = 0

    def command(self, argv, stem, timeout=60):
        self.sequence += 1
        output = self.out / (stem + '.txt')
        output.parent.mkdir(parents=True, exist_ok=True)
        stderr = self.out / (stem + '.stderr.txt')
        log = self.out / 'commands' / f'{self.sequence:05d}.json'
        event = {'argv': list(map(str, argv)), 'exit': None, 'state': 'STARTED',
                 'stdout': str(output.relative_to(self.out)),
                 'stderr': str(stderr.relative_to(self.out))}
        write(log, event)
        start = time.monotonic()
        try:
            remaining = self.deadline - start
            require(remaining > 0, 'total display deadline exhausted')
            with output.open('wb') as stdout, stderr.open('wb') as err:
                result = subprocess.run(list(map(str, argv)), stdout=stdout, stderr=err,
                                        timeout=min(timeout, remaining), check=False)
            event.update(exit=result.returncode, state='EXIT')
            require(result.returncode == 0, f'command exit {result.returncode}: {argv[0]} ({stem})')
        except BaseException as error:
            event.update(error=repr(error), state='TIMEOUT' if isinstance(error, subprocess.TimeoutExpired)
                         else ('EXIT' if event['exit'] is not None else 'EXCEPTION'))
            raise
        finally:
            event['elapsed_seconds'] = round(time.monotonic() - start, 3)
            write(log, event)
        return output


def diff(out, key, pair, mode, left, right):
    dest = out / 'diffs' / f'{ident(key)}.{pair}.{mode}.diff'
    dest.parent.mkdir(parents=True, exist_ok=True)
    with dest.open('w') as f:
        f.writelines(difflib.unified_diff(left.splitlines(True), right.splitlines(True),
                                        fromfile=pair.split('-')[0] + '/' + key,
                                        tofile=pair.split('-')[1] + '/' + key))
    return str(dest.relative_to(out))


def execute(root, out, result):
    require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_OS') == 'Linux', 'CI only')
    require(os.environ.get('GITHUB_RUN_ATTEMPT') == '1', 'retry forbidden')
    require(not root.is_relative_to(Path(os.environ['GITHUB_WORKSPACE']).resolve()), 'input must be outside checkout')
    def stage(name):
        result['stage'] = name
        write(out / 'RESULT.json', result)

    stage('INPUT_VALIDATION')
    arms = validate(root)
    runner = Runner(out)
    result['input_indexes'] = {a: sha256(root / a / 'index.json') for a in ARMS}
    for arm in ARMS:
        for name in ('index.json', 'tools.json'):
            dest = out / 'input' / arm / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(root / arm / name, dest)
    stage('INSTALL_TOOL')
    package = out / DEB
    runner.command(['curl', '--fail', '--location', '--output', package, URL], 'setup/download', 180)
    runner.command(['sudo', 'dpkg', '-i', package], 'setup/install', 180)
    package.unlink()
    tool = shutil.which('goto-instrument')
    require(tool is not None, 'goto-instrument missing')
    actual = sha256(Path(tool))
    expected = arms['A1']['tools']['goto-instrument']
    result['tool'] = {'path': tool, 'sha256': actual, 'expected_sha256': expected, 'url': URL}
    require(actual == expected, 'goto-instrument SHA256 mismatch against T1 tools.json')
    version = runner.command([tool, '--version'], 'setup/version').read_text().strip()
    require(version.split()[0] == '6.11.0', 'goto-instrument version mismatch')
    result['tool']['version'] = version
    stage('DUMPS')
    keys = sorted(k for k, rec in arms['A1']['records'].items() if rec['kind'] in MODEL_KINDS)
    ids = [ident(k) for k in keys]
    require(len(set(ids)) == len(ids), 'short filename hash collision')
    control_key = 'final/control/array_typed_copy'
    require(control_key in keys, 'missing exact array_typed_copy control')
    # Three distinct logical final models, one per arm, both modes repeated.
    perf_keys = [k for k in keys if k.startswith('final/') and k != control_key]
    require(len(perf_keys) >= 2, 'need three distinct determinism samples')
    samples = {('A1', control_key), ('A2', perf_keys[0]), ('B1', perf_keys[1])}
    index = {}
    result['determinism'] = []
    for n, key in enumerate(keys):
        entry = {'kind': arms['A1']['records'][key]['kind'], 'arms': {}}
        index[key] = entry
        for arm in ARMS:
            rec = arms[arm]['records'][key]
            entry['arms'][arm] = {'input_sha256': rec['sha256'], 'modes': {}}
            for mode in MODES:
                stem = f'dumps/{ident(key)}.{arm}.{mode}'
                raw = runner.command([tool, '--show-' + mode, root / arm / rec['path'], '--verbosity', '4'], stem)
                if (arm, key) in samples:
                    repeat = runner.command([tool, '--show-' + mode, root / arm / rec['path'], '--verbosity', '4'], stem + '.repeat')
                    equal = sha256(raw) == sha256(repeat)
                    result['determinism'].append({'key': key, 'arm': arm, 'mode': mode, 'equal': equal,
                                                  'first_sha256': sha256(raw), 'repeat_sha256': sha256(repeat)})
                    require(equal, 'display tool is not deterministic on identical input')
                # Preserve all whitespace and line endings. Only AllocId is rewritten.
                raw_text = raw.read_bytes().decode('utf-8', errors='strict')
                normalized = normalize(raw_text)
                path = out / 'normalized' / f'{ident(key)}.{arm}.{mode}.txt'
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(normalized.encode('utf-8'))
                entry['arms'][arm]['modes'][mode] = {
                    'raw': str(raw.relative_to(out)), 'raw_sha256': sha256(raw),
                    'normalized': str(path.relative_to(out)), 'normalized_sha256': sha256(path)}
        write(out / 'INDEX.json', index)
        result['dumped_logical_models'] = n + 1
        write(out / 'RESULT.json', result)
        if n % 10 == 0:
            print(f'T1b dumped {n + 1}/{len(keys)} logical models', flush=True)
    stage('COMPARE_AA_THEN_AB')
    result.update(AA_EQUAL_AFTER_NORMALIZATION={'equal': 0, 'total': 131}, AA_DIFF=[], B_DIFF=[], B_PAIR_DIFFS=[])

    def texts(key, arm):
        return [(out / index[key]['arms'][arm]['modes'][m]['normalized']).read_bytes().decode('utf-8') for m in MODES]

    # Complete all A/A classifications before inspecting B.
    stable = set()
    for key in keys:
        a, a2 = texts(key, 'A1'), texts(key, 'A2')
        if a == a2:
            stable.add(key)
            if index[key]['kind'] == 'final':
                result['AA_EQUAL_AFTER_NORMALIZATION']['equal'] += 1
        else:
            detail = classify(a[0], a2[0], a[1], a2[1])
            paths = [diff(out, key, 'A1-A2', m, x, y) for m, x, y in zip(MODES, a, a2) if x != y]
            result['AA_DIFF'].append({'key': key, **detail, 'diffs': paths})
    for key in keys:
        a, a2, b = texts(key, 'A1'), texts(key, 'A2'), texts(key, 'B1')
        for name, left in (('A1', a), ('A2', a2)):
            if left != b:
                detail = classify(left[0], b[0], left[1], b[1])
                paths = [diff(out, key, name + '-B1', m, x, y) for m, x, y in zip(MODES, left, b) if x != y]
                record = {'key': key, 'pair': name + '-B1', 'aa_equal': key in stable, **detail, 'diffs': paths}
                result['B_PAIR_DIFFS'].append(record)
                if name == 'A1' and key in stable:
                    result['B_DIFF'].append(record)
    a, a2, b = texts(control_key, 'A1'), texts(control_key, 'A2'), texts(control_key, 'B1')
    gate = control(a[0], b[0], a[1], b[1])
    result['control'] = {'key': control_key, **gate, 'aa_equal': a == a2, 'ab_different': a != b}
    if not (a == a2 and a != b and gate['valid']):
        result.update(status='INVALID', error='INVALID_CONTROL')
    elif result['AA_DIFF']:
        result['status'] = 'INCONCLUSIVE_AA'
    else:
        perf = [r for r in result['B_DIFF'] if not r['key'].startswith(('final/control/', 'linked/control/', 'symtab/control/'))]
        result['status'] = ('MODELS_EQUAL' if not perf else
                            'WRAPPER_ONLY' if all(r['class'] == 'WRAPPER_ONLY' for r in perf) else 'OTHER_CHANGES')
    stage('COMPLETE')


def main(argv):
    out = Path(argv[2]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    result = {'status': 'INVALID', 'stage': 'START', 'source_run': RUN_ID, 'source_artifact': ARTIFACT,
              'normalization': 'Only AllocId(N, ThreadLocalIndex), first occurrence per dump',
              'coordinator_review_required': True, 'no_harmlessness_or_proof_credit': True,
              'task_base': 'b2737f00565bfa73649290cecd31ac42c4097598',
              'source_ci_sha': 'cfa4b0c5296b1f7735b0d4a138d339431dfbf93d',
              'ci_sha': os.environ.get('GITHUB_SHA'), 'run_id': os.environ.get('GITHUB_RUN_ID'),
              'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT')}
    try:
        execute(Path(argv[1]).resolve(), out, result)
    except BaseException as error:
        result.update(status='INVALID', error=repr(error))
    finally:
        write(out / 'RESULT.json', result)
    print('T1b ' + result['status'], flush=True)
    return 2 if result['status'] in {'INVALID', 'INCONCLUSIVE_AA'} else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
