# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""CI-only census; local use is limited to static/synthetic checks."""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import threading
import time

HERE = Path(__file__).resolve().parent
PREFIX = 'slice::sort::shared::smallsort::verify::'
KANI = '0aac16ef62da9e9d5645782d458593e5d78143ba'
STD = 'c5ff36ff433692140605891f646043f991db05de'
CATCHALL = 'compile-resource-not-run'
GROUPS = set()
LOCK = threading.Lock()


def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def write(p, obj):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix('.tmp')
    tmp.write_text(json.dumps(obj, indent=2, sort_keys=True) + '\n')
    tmp.replace(p)


def load():
    req = json.loads((HERE / 'CI-REQUEST.json').read_text())
    roots = json.loads((HERE / 'roots.json').read_text())
    assert req['kani']['sha'] == KANI and req['std']['sha'] == STD
    assert digest(HERE / 'roots.json') == req['inventory']['manifest_sha256']
    assert len(roots) == 235 and len({r['selector'] for r in roots}) == 235
    assert [r['id'] for r in roots] == list(range(1, 236))
    assert {s: sum(r['shard'] == s for r in roots) for s in range(1, 5)} == {1: 0, 2: 183, 3: 0, 4: 52}
    assert all(r['selector'] == PREFIX + r['root'] and r['intended_invalid_value'] is False for r in roots)
    assert req['organizer_features'] == ['function-contracts', 'mem-predicates', 'float-lib', 'c-ffi', 'loop-contracts', 'quantifiers', 'stubbing']
    assert req['jobs'] == 2 and req['object_bits'] == 12
    assert req['cfg_on'] is False and req['autoharness'] is False and req['uninit_checks'] is False
    return req, roots


def git(repo, *args):
    return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()


def bind(repo, pin):
    assert git(repo, 'rev-parse', 'HEAD') == pin['sha'], 'source SHA mismatch'
    assert git(repo, 'rev-parse', 'HEAD^{tree}') == pin['tree'], 'source tree mismatch'
    assert git(repo, 'status', '--porcelain', '--untracked-files=no') == '', 'tracked source dirty'
    return {'sha': pin['sha'], 'tree': pin['tree'], 'tracked_clean': True}


def binary_hashes(export):
    export = Path(export).resolve()
    binaries = {str(p.relative_to(export)): digest(p) for p in (export/'target/kani/bin').glob('*') if p.is_file()}
    assert binaries, 'no built binaries found'
    return binaries


def clean_env():
    env = dict(os.environ)
    # No inherited cfg, feature flags, compiler wrappers, cargo target or injected Kani/CBMC flags.
    for key in list(env):
        if key.startswith(('RUST', 'CARGO_ENCODED_', 'KANI_', 'CBMC_')) or key in ('CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR'):
            env.pop(key, None)
    env['NO_COLOR'] = '1'
    return env


def rss_groups(groups):
    sums = {p: 0 for p in groups}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / 'stat').read_text().rsplit(')', 1)[1].split()
            group = int(stat[2])
            if group in sums:
                sums[group] += int((entry / 'statm').read_text().split()[1]) * os.sysconf('SC_PAGE_SIZE')
        except (OSError, ValueError, IndexError):
            continue
    return sums


def kill_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def guarded(argv, cwd, seconds, req):
    """Drain bounded output and monitor all invocation process groups; keep actual exit/signal."""
    started = time.monotonic()
    if Path('/proc/meminfo').is_file():
        available = next(int(l.split()[1])*1024 for l in Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:'))
        req = dict(req, aggregate_rss_bytes=min(req['aggregate_rss_bytes'], max(1, available-req['os_reserve_bytes'])))
    receipt = {'argv': argv, 'cwd': str(cwd), 'exit': None, 'signal': None,
               'stop': None, 'peak_rss_bytes': 0, 'peak_aggregate_rss_bytes': 0,
               'stdout_bytes': 0, 'diagnostic_tail': '', 'exception': None}
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=clean_env(), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)
    except Exception as exc:
        receipt.update(stop='SPAWN_ERROR', exception=repr(exc), wall_s=time.monotonic() - started)
        return receipt
    with LOCK:
        GROUPS.add(proc.pid)
    tail = bytearray()
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    try:
        while proc.poll() is None or sel.get_map():
            for key, _ in sel.select(0.1):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    sel.unregister(key.fileobj)
                else:
                    receipt['stdout_bytes'] += len(chunk)
                    tail.extend(chunk)
                    del tail[:-4096]
            with LOCK:
                values = rss_groups(GROUPS)
            rss, total = values.get(proc.pid, 0), sum(values.values())
            receipt['peak_rss_bytes'] = max(receipt['peak_rss_bytes'], rss)
            receipt['peak_aggregate_rss_bytes'] = max(receipt['peak_aggregate_rss_bytes'], total)
            why = ('TIMEOUT' if time.monotonic() - started > seconds else
                   'RSS_LIMIT' if rss > req['root_rss_bytes'] or total > req['aggregate_rss_bytes'] else
                   'OUTPUT_LIMIT' if receipt['stdout_bytes'] > req['stdout_cap_bytes'] else None)
            if why and receipt['stop'] is None:
                receipt['stop'] = why
                kill_group(proc.pid)
        code = proc.wait()
        receipt['exit'] = code
        receipt['signal'] = -code if code < 0 else None
    except BaseException as exc:
        kill_group(proc.pid)
        receipt.update(stop='WRAPPER_EXCEPTION', exception=repr(exc), exit=proc.wait())
        receipt['signal'] = -receipt['exit'] if receipt['exit'] < 0 else None
    finally:
        # Do not let orphan verifier children survive a successful parent exit.
        kill_group(proc.pid)
        with LOCK:
            GROUPS.discard(proc.pid)
        sel.close()
        proc.stdout.close()
    receipt['wall_s'] = time.monotonic() - started
    receipt['diagnostic_tail'] = tail.decode(errors='replace')
    receipt['diagnostic_tail_truncated'] = receipt['stdout_bytes'] > len(tail)
    return receipt


def argv_for(req, row, binary, target, export):
    argv = [str(binary), 'verify-std', '-Z', 'unstable-options', './library']
    for feature in req['organizer_features'] + ['valid-value-checks', 'export-json']:
        argv += ['-Z', feature]
    return argv + ['--no-assert-contracts', '--harness', row['selector'], '--exact', '--jobs=1',
                   '--harness-timeout', '600s', '--target-dir', str(target), '--export-json', str(export),
                   '--output-format=terse', '--cbmc-args', '--object-bits', '12']


def unknown(reason):
    return {'classification': CATCHALL, 'complete': False, 'reason': reason, 'observed_classes': []}


def classify(data, row, execution, req):
    """Only complete, exactly bound structured results can receive a scientific class."""
    retained = {}
    try:
        assert isinstance(data, dict) and data['schema_version'] == '0.1.0', 'schema'
        assert data['kani_commit'] == KANI and data['kani_commit_dirty'] is False, 'tool'
        assert data['target'] == req['target'], 'target'
        assert data['enabled_unstable_features'] == sorted(req['organizer_features'] + ['unstable-options', 'valid-value-checks', 'export-json']), 'features'
        cfg = data['configuration']
        expected = dict(memory_safety=True, overflow=True, unwinding=True, undefined_function=True,
                        assertion_reach_checks=True, ignore_global_asm=False, extra_pointer_checks=False,
                        assert_contracts=False, prove_safety_only=False)
        assert isinstance(cfg['checks'], dict) and all(type(cfg['checks'].get(k)) is bool for k in expected), 'check-flag-types'
        assert cfg['checks'] == expected and cfg['cbmc_args'] == ['--object-bits', '12'] and cfg['coverage_enabled'] is False, 'checks'
        selection = data['harness_selection']
        assert isinstance(selection, dict) and type(selection.get('matched_count')) is int and type(selection.get('exact')) is bool, 'selection-types'
        assert selection == dict(requested_filters=[row['selector']], exact=True, unmatched_filters=[], matched_count=1), 'selection'
        assert data['run_state'] == 'COMPLETE' and data['outcome'] == {'kind': 'COMPLETED'}, 'run-state'
        hs = data['harnesses']
        assert isinstance(hs, list) and len(hs) == 1, 'harness-count'
        h = hs[0]
        assert h['name'] == row['selector'] and h['crate_name'] == 'core' and h['is_automatically_generated'] is False, 'harness-binding'
        assert h['outcome']['kind'] == 'COMPLETED', 'harness-not-completed'
        retained['harness'] = h
        checks, covers = h['checks'], h['covers']
        property_partial = False
        for obj, specific in ((checks, ('failure',)), (covers, ('satisfied','unsatisfiable'))):
            assert isinstance(obj, dict), 'property-object'
            for k in specific + ('unreachable','undetermined','error','unknown','other'):
                assert isinstance(obj.get(k), list), 'property-bucket-type'
                if k != 'other':
                    assert all(isinstance(v, str) and v for v in obj[k]) and len(set(obj[k])) == len(obj[k]), 'property-id-types'
            ids = [v for k in specific + ('unreachable','undetermined','error','unknown') for v in obj[k]]
            assert len(set(ids)) == len(ids), 'duplicate-property-ids'
            assert type(obj['total']) is int and obj['total'] >= 0, 'property-total'
            for k in ('unreachable', 'undetermined', 'error', 'unknown', 'other'):
                assert isinstance(obj[k], list), 'property-buckets'
            property_partial |= any(obj[k] for k in ('undetermined', 'error', 'unknown', 'other'))
        failed = h['failed_properties']
        unsupported = h['unsupported_constructs']
        assert isinstance(failed, list) and isinstance(unsupported, list), 'property-lists'
        assert type(h['n_failed']) is int and h['n_failed'] == len(failed) == len(checks['failure']), 'failure-count'
        assert type(checks['success']) is int and checks['success'] >= 0, 'success-count'
        assert checks['total'] == checks['success'] + sum(len(checks[k]) for k in ('failure','unreachable','undetermined','error','unknown','other')), 'check-partition'
        assert covers['total'] == sum(len(covers[k]) for k in ('satisfied', 'unsatisfiable', 'unreachable','undetermined','error','unknown','other')), 'cover-partition'
        assert type(h['n_properties']) is int, 'property-count-type'
        assert h['n_properties'] == checks['total'] + covers['total'] and checks['total'] > 0, 'properties'
        assert all(isinstance(p, dict) and all(isinstance(p.get(k), str) for k in ('id','description','class','status')) for p in failed + unsupported), 'property-entry-types'
        assert {p['id'] for p in failed} == set(checks['failure']), 'failed-property-ids'
        assert {p['id'] for p in unsupported if p['status']=='FAILURE'} == {p['id'] for p in failed if p['class']=='unsupported_construct'}, 'unsupported-failure-partition'
        assert all(p['status'] == 'FAILURE' and isinstance(p['description'], str) for p in failed), 'failed-properties'
        classes = set()
        for p in failed:
            desc = p['description']
            if p['class'] == 'unsupported_construct':
                classes.add('copy Unsupported' if 'checking validity of `copy_nonoverlapping`' in desc else
                            'casts' if 'checking validity of `mutable cast`' in desc else 'other Unsupported')
            elif 'Undefined Behavior: Invalid value of type `' in desc and row['intended_invalid_value'] is True:
                classes.add('intended invalid-value failure')
            else:
                classes.add(CATCHALL)
        verdict = h['outcome']['verdict']
        assert verdict in ('SUCCESS', 'FAILURE'), 'verdict'
        assert verdict == ('FAILURE' if failed else 'SUCCESS'), 'verdict-properties'
        assert execution['exit'] == (1 if failed else 0), 'exit-verdict'
        assert execution['stop'] is None, 'wrapper-stop'
        if not classes:
            result = {'classification': 'PASS', 'complete': True, 'reason': 'bound completed verdict', 'observed_classes': ['PASS']}
        else:
            order = [CATCHALL, 'other Unsupported', 'casts', 'copy Unsupported', 'intended invalid-value failure']
            result = {'classification': next(c for c in order if c in classes), 'complete': CATCHALL not in classes,
                      'reason': 'completed failure; unexpected scientific failures require review' if CATCHALL in classes else 'completed diagnostic failure',
                      'observed_classes': sorted(classes)}
        if property_partial:
            result['complete'] = False
            result['reason'] += '; PARTIAL property buckets'
            if result['classification'] == 'PASS':
                result['classification'] = CATCHALL
                result['observed_classes'] = []
        result['harness'] = h  # Preserve all checks, useful covers, failures and warnings, including mixed classes.
        result['export_identity'] = {k: data[k] for k in ('kani_commit', 'kani_commit_dirty', 'target', 'configuration', 'enabled_unstable_features', 'harness_selection', 'run_state')}
        return result
    except (AssertionError, KeyError, TypeError, ValueError) as exc:
        return dict(unknown('EXPORT_REJECTED: ' + str(exc)), **retained)


def initial(row):
    return dict(schema='ch8-b-root-v1', **row, **unknown('NOT_RUN'), runtime_proof_status='NOT_RUN')


def seed(out, roots):
    out.mkdir(parents=True, exist_ok=True)
    for row in roots:
        p = out / ('root-%03d.json' % row['id'])
        if not p.exists():
            write(p, initial(row))


def run_census(args, req, roots):
    assert os.environ.get('GITHUB_ACTIONS') == 'true', 'actual invocations CI-only'
    out, std, export = Path(args.out).resolve(), Path(args.std).resolve(), Path(args.export).resolve()
    assert std.parent == export.parent and std != export, 'sibling std/export layout required'
    binding = {'std': bind(std, req['std']), 'kani': bind(export, req['kani'])}
    seed(out, roots)
    before_binaries = json.loads((out/'binary-hashes.json').read_text())
    assert before_binaries == binary_hashes(export), 'binary changed between build and census'
    available = next(int(l.split()[1]) * 1024 for l in Path('/proc/meminfo').read_text().splitlines() if l.startswith('MemAvailable:'))
    req = dict(req, aggregate_rss_bytes=min(req['aggregate_rss_bytes'], available - req['os_reserve_bytes']))
    assert req['aggregate_rss_bytes'] > 0, 'no RAM after OS reserve'
    write(out / 'binding.json', dict(binding, available_bytes=available, aggregate_cap_bytes=req['aggregate_rss_bytes'], request_sha256=digest(HERE/'CI-REQUEST.json'), inventory_sha256=digest(HERE/'roots.json')))
    deadline = time.monotonic() + req['stage_seconds']['verify']
    slots = [roots[i::req['jobs']] for i in range(req['jobs'])]

    def lane(slot, rows):
        target = out.parent / ('target-shard-%s-slot-%s' % (args.shard, slot))
        for row in rows:
            remaining = deadline - time.monotonic()
            if remaining < req['root_seconds'] + 5:
                break  # Keep full root envelope; all untouched receipts remain NOT_RUN.
            if sum(p.stat().st_size for p in out.glob('*.json')) > req['artifact_cap_bytes'] - req['export_cap_bytes']:
                break
            raw = target.parent / ('export-%03d.json' % row['id'])
            assert not raw.exists(), 'stale export'
            argv = argv_for(req, row, export/'scripts/kani', target, raw)
            execution = guarded(argv, std, req['root_seconds'], req)
            receipt = initial(row)
            receipt['runtime_proof_status'] = 'ATTEMPTED'
            receipt['execution'] = execution
            if raw.exists() and raw.stat().st_size <= req['export_cap_bytes']:
                receipt['export_sha256'] = digest(raw)
                try:
                    result = classify(json.loads(raw.read_text()), row, execution, req)
                except (ValueError, OSError) as exc:
                    result = unknown('INVALID_EXPORT: ' + repr(exc))
                receipt.update(result)
            else:
                receipt.update(unknown('MISSING_OR_OVERSIZE_EXPORT'))
            if raw.exists():
                raw.unlink()  # Only curated bounded receipts are uploaded; no target/raw logs/archives.
            write(out / ('root-%03d.json' % row['id']), receipt)
    with concurrent.futures.ThreadPoolExecutor(max_workers=req['jobs']) as pool:
        futures = [pool.submit(lane, i, r) for i, r in enumerate(slots)]
        for f in futures:
            f.result()
    after_binaries = binary_hashes(export)
    write(out/'post-binary-hashes.json', after_binaries)
    assert before_binaries == after_binaries, 'binary changed during census'
    write(out / 'post-source.json', {'std': bind(std, req['std']), 'kani': bind(export, req['kani']), 'binary_hashes_unchanged': True})


def finalize(out, roots, status):
    seed(out, roots)
    receipts = [json.loads((out / ('root-%03d.json' % r['id'])).read_text()) for r in roots]
    assert all(p['selector'] == r['selector'] and p['shard'] == r['shard'] for p,r in zip(receipts, roots))
    complete = all(p['complete'] is True for p in receipts) and status == 'success' and (out/'post-source.json').is_file()
    counts = {}
    for p in receipts:
        counts[p['classification']] = counts.get(p['classification'], 0) + 1
    result = {'schema': 'ch8-b-shard-v1', 'status': 'COMPLETE' if complete else 'PARTIAL',
              'expected': len(roots), 'completed': sum(p['complete'] is True for p in receipts),
              'counts': counts, 'job_status': status, 'runtime_credit': 'SOURCE_REPORTED_DIAGNOSTIC_ONLY'}
    write(out / 'summary.json', result)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['seed', 'run', 'finalize', 'bind', 'build'])
    parser.add_argument('--shard', type=int, choices=[2,4], default=2)
    parser.add_argument('--out', required=True)
    parser.add_argument('--std')
    parser.add_argument('--export')
    parser.add_argument('--job-status', default='unknown')
    args = parser.parse_args()
    req, roots = load()
    roots = [r for r in roots if r['shard'] == args.shard]
    out = Path(args.out).resolve()
    if args.action == 'seed':
        seed(out, roots)
    elif args.action == 'bind':
        write(out/'source.json', {'std': bind(args.std, req['std']), 'kani': bind(args.export, req['kani'])})
    elif args.action == 'build':
        assert os.environ.get('GITHUB_ACTIONS') == 'true', 'build CI-only'
        bind(args.export, req['kani'])
        execution = guarded(['cargo', 'build-dev', '--', '--release'], Path(args.export).resolve(), req['stage_seconds']['build'], dict(req, root_rss_bytes=req['aggregate_rss_bytes']))
        write(out/'build.json', execution)
        assert execution['exit'] == 0 and execution['stop'] is None, 'build incomplete'
        bind(args.export, req['kani'])
        write(out/'binary-hashes.json', binary_hashes(args.export))
    elif args.action == 'run':
        run_census(args, req, roots)
    else:
        result = finalize(out, roots, args.job_status)
        print(json.dumps(result))
        return 0 if result['status'] == 'COMPLETE' else 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
