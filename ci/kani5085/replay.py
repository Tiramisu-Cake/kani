#!/usr/bin/env python3
"""Static checks locally; build receipts and replay only in coordinator CI."""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
INPUTS = json.loads((HERE / 'INPUTS.json').read_text())
CAP = 8 * 1024 * 1024


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(obj, indent=2) + '\n')
    temp.replace(path)


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args], text=True).strip()


def capture(argv, cwd, prefix, timeout, env=None, forward=False):
    """Drain both streams to bounded files, retain exit/signal even on overflow."""
    prefix = Path(prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    result = dict(argv=list(map(str, argv)), cwd=str(cwd), exit=None, signal=None,
                  timeout=False, complete=False, raw_bytes=0, retained_bytes=0,
                  exception=None, status='IN_PROGRESS')
    started = time.monotonic()
    streams = {}
    process = None
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=not forward)
        selector = selectors.DefaultSelector()
        for fd, pipe in [(1, process.stdout), (2, process.stderr)]:
            out = open(str(prefix) + ('.stdout' if fd == 1 else '.stderr'), 'wb')
            streams[fd] = out
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, fd)
        while selector.get_map() or process.poll() is None:
            if time.monotonic() - started > timeout:
                result['timeout'] = True
                if forward:
                    process.kill()
                else:
                    os.killpg(process.pid, signal.SIGKILL)
                # Drain after kill, with a finite final deadline.
                if time.monotonic() - started > timeout + 5:
                    break
            for key, _ in selector.select(0.05):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                result['raw_bytes'] += len(chunk)
                keep = chunk[:max(0, CAP - result['retained_bytes'])]
                streams[key.data].write(keep)
                result['retained_bytes'] += len(keep)
                if forward:
                    try:
                        os.write(key.data, chunk)
                    except BrokenPipeError:
                        pass
        code = process.wait(timeout=5)
        result.update(exit=code, signal=-code if code < 0 else None,
                      complete=not selector.get_map())
        selector.close()
        result['status'] = 'FINISHED'
    except Exception as error:
        result['exception'] = {'type': type(error).__name__, 'message': str(error)}
        result['status'] = 'CAPTURE_ERROR'
        if process and process.poll() is None:
            if forward:
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
            code = process.wait()
            result.update(exit=code, signal=-code if code < 0 else None)
    finally:
        for out in streams.values():
            out.close()
    result['wall_seconds'] = round(time.monotonic() - started, 3)
    result['overflow'] = result['raw_bytes'] > result['retained_bytes']
    result['logs'] = {suffix: {'path': str(prefix) + '.' + suffix,
                              'sha256': sha(str(prefix) + '.' + suffix)}
                      for suffix in ['stdout', 'stderr']
                      if Path(str(prefix) + '.' + suffix).exists()}
    write(str(prefix) + '.json', result)
    return result


def sound_capture(row):
    return (isinstance(row, dict) and row.get('status') == 'FINISHED'
            and type(row.get('exit')) is int and row.get('complete') is True
            and row.get('timeout') is False and row.get('overflow') is False
            and row.get('exception') is None)


def text_logs(prefix):
    return '\n'.join(Path(str(prefix) + '.' + suffix).read_text(errors='replace')
                     for suffix in ['stdout', 'stderr']
                     if Path(str(prefix) + '.' + suffix).exists())


def invariant_blocks(text):
    # Keep verbatim original lines, including the Reason and surrounding report.
    lines = text.splitlines(keepends=True)
    spans = []
    for i, line in enumerate(lines):
        if 'Invariant check failed' in line:
            begin = i - 1 if i and 'begin invariant' in lines[i - 1] else i
            end = next((k + 1 for k in range(i + 1, len(lines))
                        if 'end invariant' in lines[k]), len(lines))
            spans.append(''.join(lines[begin:end]))
    return spans


def classify(row, text, invocations, expected_binary):
    if not sound_capture(row):
        return 'INCOMPLETE_OR_SETUP_ERROR'
    # Version probes do not establish that model checking reached the backend.
    models = [x for x in invocations if isinstance(x, dict)
              and isinstance(x.get('argv'), list) and '--json-ui' in x['argv']]
    if not models:
        return 'NO_CBMC_MODEL_INVOCATION'
    if any(x.get('binary_sha256') != expected_binary or not sound_capture(x)
           for x in models):
        return 'CBMC_IDENTITY_OR_CAPTURE_ERROR'
    backend = '\n'.join(x.get('output', '') for x in models)
    if 'Invariant check failed' in backend:
        return ('BITS2EXPR_ARRAY_INVARIANT' if 'bits2expr' in backend and
                'el_size_opt' in backend else 'OTHER_INVARIANT')
    if (row['exit'] == 0 and all(x['exit'] == 0 for x in models)
            and re.search(r'^VERIFICATION:- SUCCESSFUL\s*$', text, re.M)):
        return 'VERIFIED'
    return 'OTHER_FAILURE'


def check_inputs():
    for name, expected in INPUTS['hashes'].items():
        assert sha(HERE / name) == expected, name
    issue = json.loads((HERE / 'issue-5085.json').read_text())
    assert (HERE / 'issue-5085.md').read_bytes() == issue['body'].encode()
    blocks = re.findall(r'```rust\n(.*?)```', issue['body'], re.S)
    assert (HERE / 'roots/static_zst_arr.rs').read_text() == blocks[0] == blocks[2]
    assert (HERE / 'roots/runtime_control.rs').read_text() == blocks[1]


def check_delta(source):
    base, fix = INPUTS['cbmc_base'], INPUTS['cbmc_fix']
    assert git(source, 'rev-parse', fix + '^') == base
    names = git(source, 'diff', '--name-only', base, fix).splitlines()
    assert set(names) == {'src/util/simplify_utils.cpp', 'unit/util/simplify_expr.cpp',
                          'regression/cbmc/byte_extract_empty_struct_array/main.c',
                          'regression/cbmc/byte_extract_empty_struct_array/test.desc'}
    old = git(source, 'show', base + ':src/util/simplify_utils.cpp')
    new = git(source, 'show', fix + ':src/util/simplify_utils.cpp')
    before = 'el_size_opt.has_value() && *el_size_opt > bitst{0}'
    # The later vector branch has the same guard and stays unchanged.
    assert old.count(before) == 2
    assert old.replace(before, before.replace(' > ', ' >= '), 1) == new


def receipt(kind, source, binary, evidence):
    source, binary, evidence = Path(source), Path(binary), Path(evidence)
    expected = INPUTS['cbmc_' + kind]
    assert git(source, 'rev-parse', 'HEAD') == expected
    assert not git(source, 'status', '--porcelain', '--untracked-files=no')
    version = capture([str(binary), '--version'], source, evidence / 'build' / (kind + '-version'), 15)
    assert sound_capture(version) and version['exit'] == 0
    shutil.copyfile(source / 'build/CMakeCache.txt', evidence / 'build' / (kind + '-CMakeCache.txt'))
    write(evidence / 'build' / (kind + '.json'), dict(
        source_sha=expected, source_tree=git(source, 'rev-parse', 'HEAD^{tree}'),
        binary=str(binary.resolve()), binary_sha256=sha(binary),
        cmake_cache_sha256=sha(source / 'build/CMakeCache.txt'),
        version=text_logs(evidence / 'build' / (kind + '-version')), version_capture=version))


def init(evidence):
    check_inputs()
    write(Path(evidence) / 'RESULT.json', dict(status='NOT_RUN', inputs=INPUTS,
          cases=[dict(root=root, variant=variant, verdict='NOT_RUN')
                 for root in INPUTS['roots'] for variant in ['base', 'fix']]))


def proxy():
    binary = Path(os.environ['K5085_BINARY']).resolve()
    prefix = Path(os.environ['K5085_CASE']) / ('cbmc-' + uuid.uuid4().hex)
    row = capture([str(binary), *sys.argv[2:]], Path.cwd(), prefix, 50, forward=True)
    row.update(binary=str(binary), binary_sha256=sha(binary))
    write(str(prefix) + '.json', row)
    if row['timeout'] or row['overflow'] or row['exception']:
        sys.exit(125)
    if row['exit'] < 0:
        signal.signal(-row['exit'], signal.SIG_DFL)
        os.kill(os.getpid(), -row['exit'])
    sys.exit(row['exit'])


def run(evidence, source, pair):
    check_inputs()
    evidence, source, pair = map(lambda p: Path(p).resolve(), [evidence, source, pair])
    result = json.loads((evidence / 'RESULT.json').read_text())
    assert git(source, 'rev-parse', 'HEAD') == INPUTS['kani_sha']
    assert not git(source, 'status', '--porcelain', '--untracked-files=no')
    build = {v: json.loads((evidence / 'build' / (v + '.json')).read_text()) for v in ['base', 'fix']}
    for v in build:
        assert build[v]['source_sha'] == INPUTS['cbmc_' + v]
        assert sha(pair / v) == build[v]['binary_sha256']
    shim = evidence / 'shim'
    shim.mkdir(exist_ok=True)
    # The interpreter path is fixed by the CI Python executable, no PATH recursion.
    (shim / 'cbmc').write_text('#!' + sys.executable + '\nimport runpy, sys\n'
                              'sys.argv.insert(1, "proxy")\nrunpy.run_path(' +
                              repr(str(Path(__file__).resolve())) + ', run_name="__main__")\n')
    (shim / 'cbmc').chmod(0o755)
    driver = source / 'target/kani/bin/kani-driver'
    version = capture([str(source / 'scripts/kani'), '--version'], source,
                      evidence / 'tooling/kani-version', 15)
    assert sound_capture(version) and version['exit'] == 0
    result.update(status='IN_PROGRESS', cbmc_builds=build, kani_source=INPUTS['kani_sha'],
                  kani_driver_sha256=sha(driver),
                  kani_compiler_sha256=sha(source / 'target/kani/bin/kani-compiler'),
                  kani_version=text_logs(evidence / 'tooling/kani-version'),
                  rust_toolchain=(source / 'rust-toolchain.toml').read_text(),
                  cargo_lock_sha256=sha(source / 'Cargo.lock'),
                  workflow_commit=os.environ.get('GITHUB_SHA'),
                  run_id=os.environ.get('GITHUB_RUN_ID'), attempt=os.environ.get('GITHUB_RUN_ATTEMPT'))
    write(evidence / 'RESULT.json', result)
    for row in result['cases']:
        root, variant = row['root'], row['variant']
        case = evidence / 'cases' / root / variant
        case.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(HERE / 'roots' / (root + '.rs'), case / 'input.rs')
        env = dict(os.environ, PATH=str(shim) + os.pathsep + os.environ['PATH'],
                   K5085_BINARY=str(pair / variant), K5085_CASE=str(case))
        row.update(verdict='IN_PROGRESS', source_sha256=sha(case / 'input.rs'))
        write(evidence / 'RESULT.json', result)
        command = [str(source / 'scripts/kani'), '--verbose', 'input.rs']
        execution = capture(command, case, case / 'kani', 60, env=env)
        invocations = []
        for path in sorted(case.glob('cbmc-*.json')):
            invocation = json.loads(path.read_text())
            invocation['output'] = text_logs(path.with_suffix(''))
            invocations.append(invocation)
        output = text_logs(case / 'kani')
        verdict = classify(execution, output, invocations, build[variant]['binary_sha256'])
        blocks = invariant_blocks(output)
        for invocation in invocations:
            blocks.extend(invariant_blocks(invocation['output']))
        # Full verbatim blocks are available separately; concise summary stays bounded.
        (case / 'invariants.txt').write_text('\n'.join(dict.fromkeys(blocks)))
        row.update(verdict=verdict, execution=execution, cbmc_invocations=[
            {k: v for k, v in i.items() if k != 'output'} for i in invocations],
            invariant_file=str(case / 'invariants.txt'),
            kani_verdict_lines=re.findall(r'^VERIFICATION:.*$', output, re.M))
        write(evidence / 'RESULT.json', result)
    # Record observations, without requiring the hypothesis to hold for a green data-collection job.
    result['status'] = ('COLLECTED' if all(sound_capture(r.get('execution')) and
                        r['verdict'] != 'CBMC_IDENTITY_OR_CAPTURE_ERROR' and
                        all(sound_capture(i) for i in r['cbmc_invocations'])
                        for r in result['cases'])
                        else 'COLLECTION_INCOMPLETE')
    write(evidence / 'RESULT.json', result)
    summary(evidence)
    return 0 if result['status'] == 'COLLECTED' else 1


def summary(evidence):
    path = Path(evidence) / 'RESULT.json'
    if not path.exists():
        print('KANI5085: SETUP_FAILURE; all cases NOT_RUN.')
        return
    result = json.loads(path.read_text())
    print('KANI5085: ' + result['status'] + '; observations only, no proof credit.\n')
    print('| Root | CBMC | Verdict | Kani exit |\n|---|---|---|---|')
    for row in result['cases']:
        print('| {} | {} | {} | {} |'.format(row['root'], row['variant'], row['verdict'],
                                            row.get('execution', {}).get('exit', 'NOT_RUN')))
    for variant, item in result.get('cbmc_builds', {}).items():
        print('\nCBMC {}: `{}`; SHA256 `{}`; version `{}`'.format(
            variant, item['source_sha'], item['binary_sha256'], item['version'].strip()))
    print('\nDetailed exits, signals, invocation paths, versions and verbatim invariant blocks: artifact receipts. '
          'NOT_RUN/NO_CBMC_MODEL_INVOCATION does not establish a CBMC outcome. '
          'An absent invariant alone does not establish verification success.')


if __name__ == '__main__':
    mode, *args = sys.argv[1:]
    if mode == 'proxy':
        proxy()
    elif mode == 'init':
        init(*args)
    elif mode == 'check-delta':
        check_delta(*args)
    elif mode == 'receipt':
        receipt(*args)
    elif mode == 'run':
        sys.exit(run(*args))
    elif mode == 'summary':
        summary(*args)
    else:
        raise ValueError(mode)
