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
from function_dump import extract_functions

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
                model = root / arm / rec['path']
                verbosity = '6' if mode == 'goto-functions' else '4'
                raw = runner.command([tool, '--show-' + mode, model, '--verbosity', verbosity], stem)
                require(not raw.with_name(raw.stem + '.stderr.txt').read_bytes(), f'nonempty display stderr: {stem}')
                require(raw.stat().st_size > 0, f'empty display stdout: {stem}')
                if mode == 'goto-functions':
                    body, banner, counts = extract_functions(raw.read_bytes(), str(model))
                    content = out / (stem + '.functions.txt')
                    content.write_bytes(body)
                    status = out / (stem + '.status.txt')
                    status.write_bytes(banner)
                if (arm, key) in samples:
                    repeat = runner.command([tool, '--show-' + mode, model, '--verbosity', verbosity], stem + '.repeat')
                    require(not repeat.with_name(repeat.stem + '.stderr.txt').read_bytes(), 'nonempty repeat stderr')
                    if mode == 'goto-functions':
                        extract_functions(repeat.read_bytes(), str(model))
                    equal = sha256(raw) == sha256(repeat)
                    result['determinism'].append({'key': key, 'arm': arm, 'mode': mode, 'equal': equal,
                                                  'first_sha256': sha256(raw), 'repeat_sha256': sha256(repeat)})
                    require(equal, 'display tool is not deterministic on identical input')
                entry['arms'][arm]['modes'][mode] = {
                    'raw': str(raw.relative_to(out)), 'raw_sha256': sha256(raw),
                    'verbosity': verbosity}
                if mode == 'goto-functions':
                    entry['arms'][arm]['modes'][mode].update(
                        content=str(content.relative_to(out)), content_sha256=sha256(content),
                        status=str(status.relative_to(out)), status_sha256=sha256(status), **counts)
        write(out / 'INDEX.json', index)
        result['dumped_logical_models'] = n + 1
        write(out / 'RESULT.json', result)
        if n % 10 == 0:
            print(f'T1b dumped {n + 1}/{len(keys)} logical models', flush=True)
    require(len(keys) == 393, 'expected 393 logical models')
    require(len(result['determinism']) == 6, 'expected six raw repeat checks')
    result.update(status='CAPTURE_COMPLETE_OFFLINE_REQUIRED',
                  function_dumps=3 * len(keys), symbol_dumps=3 * len(keys),
                  classification='NOT_RUN: use t0 b3p/t1b/offline.py --r2 after download')
    stage('COMPLETE')


def main(argv):
    out = Path(argv[2]).resolve()
    out.mkdir(parents=True, exist_ok=True)
    result = {'status': 'INVALID', 'stage': 'START', 'source_run': RUN_ID, 'source_artifact': ARTIFACT,
              'schema': 'b3-t1b-r2-capture-v1',
              'normalization': 'None in capture; exact input-path status line split from functions only',
              'coordinator_review_required': True, 'no_harmlessness_or_proof_credit': True,
              'task_base': '43b065bb9d0fc78cb66aef81584a8241a85f461d',
              'ci_parent': '1a8faa3b60ee9a19534cdb57315e8887f5666301',
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
