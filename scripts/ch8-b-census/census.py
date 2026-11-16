# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""CI-only census; local use is limited to static/synthetic checks."""
import argparse
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
    assert req['jobs'] == 1 and req['object_bits'] == 12
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


def available_bytes():
    return next(int(line.split()[1])*1024 for line in Path('/proc/meminfo').read_text().splitlines()
                if line.startswith('MemAvailable:'))


def guarded(argv, cwd, seconds, req, export_marker=None, compile_receipt=None):
    """Drain bounded output and monitor all invocation process groups; keep actual exit/signal."""
    started = time.monotonic()
    if Path('/proc/meminfo').is_file():
        available = available_bytes()
        req = dict(req, aggregate_rss_bytes=min(req['aggregate_rss_bytes'], available-req['os_reserve_bytes']))
    receipt = {'argv': argv, 'cwd': str(cwd), 'exit': None, 'signal': None,
               'stop': None, 'peak_rss_bytes': 0, 'peak_aggregate_rss_bytes': 0,
               'stdout_bytes': 0, 'diagnostic_head': '', 'diagnostic_tail': '', 'exception': None,
               'compile': {'status': 'NOT_RUN', 'limit_s': req.get('compile_seconds'),
                           'boundary': 'fresh export marker after compile and selection',
                           'wall_s': None, 'diagnostic_head': '', 'diagnostic_tail': ''}}
    compile_done = export_marker is None
    compile_head, compile_tail, head = bytearray(), bytearray(), bytearray()
    compile_bytes = 0
    def save_compile():
        receipt['compile'].update(diagnostic_head=compile_head.decode(errors='replace'),
                                  diagnostic_tail=compile_tail.decode(errors='replace'), stdout_bytes=compile_bytes,
                                  diagnostic_truncated=compile_bytes > len(compile_head)+len(compile_tail))
        if compile_receipt is not None:
            write(compile_receipt, receipt['compile'])
    if export_marker is not None:
        receipt['compile']['status'] = 'IN_PROGRESS'
        save_compile()
    if req['aggregate_rss_bytes'] <= 0:
        receipt.update(stop='MEMORY_UNAVAILABLE', wall_s=time.monotonic()-started)
        receipt['compile'].update(status='NOT_RUN', reason='no RAM after OS reserve')
        save_compile()
        return receipt
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=clean_env(), stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)
    except Exception as exc:
        receipt.update(stop='SPAWN_ERROR', exception=repr(exc), wall_s=time.monotonic() - started)
        if export_marker is not None:
            receipt['compile'].update(status='SPAWN_ERROR', wall_s=receipt['wall_s'], exception=repr(exc))
            save_compile()
        return receipt
    with LOCK:
        GROUPS.add(proc.pid)
    tail = bytearray()
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    try:
        while proc.poll() is None or sel.get_map():
            if not compile_done and Path(export_marker).exists():
                compile_done = True
                receipt['compile'].update(status='MARKER_OBSERVED', wall_s=time.monotonic()-started)
                save_compile()
            for key, _ in sel.select(0.1):
                chunk = os.read(key.fd, 65536)
                if not chunk:
                    sel.unregister(key.fileobj)
                else:
                    receipt['stdout_bytes'] += len(chunk)
                    head.extend(chunk[:max(0, 4096-len(head))])
                    tail.extend(chunk)
                    del tail[:-4096]
                    if not compile_done:
                        compile_bytes += len(chunk)
                        compile_head.extend(chunk[:max(0, 4096-len(compile_head))])
                        compile_tail.extend(chunk)
                        del compile_tail[:-4096]
            with LOCK:
                values = rss_groups(GROUPS)
            rss, total = values.get(proc.pid, 0), sum(values.values())
            receipt['peak_rss_bytes'] = max(receipt['peak_rss_bytes'], rss)
            receipt['peak_aggregate_rss_bytes'] = max(receipt['peak_aggregate_rss_bytes'], total)
            why = ('COMPILE_TIMEOUT' if not compile_done and time.monotonic()-started > req['compile_seconds'] else
                   'TIMEOUT' if time.monotonic() - started > seconds else
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
    receipt['diagnostic_head'] = head.decode(errors='replace')
    receipt['diagnostic_tail'] = tail.decode(errors='replace')
    if export_marker is not None:
        # This boundary establishes stage timing only; classify validates export identities.
        if not compile_done and Path(export_marker).exists():
            compile_done = True
            receipt['compile'].update(status='MARKER_OBSERVED', wall_s=receipt['wall_s'])
        if not compile_done:
            receipt['compile'].update(status='INCOMPLETE', wall_s=receipt['wall_s'])
        save_compile()
    receipt['diagnostic_tail_truncated'] = receipt['stdout_bytes'] > len(tail)
    return receipt


def argv_for(req, rows, binary, target, export):
    argv = [str(binary), 'verify-std', '-Z', 'unstable-options', './library']
    for feature in req['organizer_features'] + ['valid-value-checks', 'export-json']:
        argv += ['-Z', feature]
    for row in rows:
        argv += ['--harness', row['selector']]
    return argv + ['--no-assert-contracts', '--exact', '--jobs=1',
                   '--harness-timeout', '600s', '--target-dir', str(target), '--export-json', str(export),
                   '--output-format=terse', '--cbmc-args', '--object-bits', '12']


def unknown(reason):
    return {'classification': CATCHALL, 'complete': False, 'reason': reason, 'observed_classes': []}


def classify(data, row, execution, req, rows=None):
    """Only complete, exactly bound structured results can receive a scientific class."""
    retained = {}
    rows = [row] if rows is None else rows
    try:
        assert isinstance(data, dict) and data['schema_version'] == '0.1.0', 'schema'
        assert isinstance(data['configuration'], dict), 'configuration-type'
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
        filters = [r['selector'] for r in rows]
        assert selection == dict(requested_filters=filters, exact=True, unmatched_filters=[], matched_count=len(rows)), 'selection'
        assert type(data['harness_timeout_s']) in (int, float) and data['harness_timeout_s'] == 600, 'harness-timeout'
        assert data['run_state'] in ('COMPLETE', 'PARTIAL') and data['outcome'] == {'kind': 'COMPLETED'}, 'run-state'
        hs = data['harnesses']
        assert isinstance(hs, list) and all(isinstance(h, dict) for h in hs), 'harness-array'
        names = [h['name'] for h in hs]
        assert all(isinstance(n, str) for n in names) and len(set(names)) == len(names), 'duplicate-harness'
        assert set(names) <= set(filters), 'unexpected-harness'
        assert (len(hs) == len(rows)) == (data['run_state'] == 'COMPLETE'), 'run-state-count'
        selected = [h for h in hs if h['name'] == row['selector']]
        assert len(selected) == 1, 'missing-harness'
        h = selected[0]
        assert h['crate_name'] == 'core' and h['is_automatically_generated'] is False, 'harness-binding'
        contract = h['contract']
        assert contract is None or (isinstance(contract, dict)
            and set(contract) == {'contracted_function_name', 'recursion_tracker'}
            and isinstance(contract['contracted_function_name'], str) and contract['contracted_function_name']
            and (contract['recursion_tracker'] is None or isinstance(contract['recursion_tracker'], str))), 'contract'
        retained['harness'] = h
        # A failing/timed-out neighbour determines group exit; the selected row uses its own verdict.
        assert all(isinstance(x.get('outcome'), dict) for x in hs), 'outcome-types'
        all_success = data['run_state'] == 'COMPLETE' and all(x['outcome'] == {'kind':'COMPLETED','verdict':'SUCCESS'} for x in hs)
        assert type(execution['exit']) is int and execution['exit'] == (0 if all_success else 1), 'exit-verdict'
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
    available = available_bytes()
    req = dict(req, aggregate_rss_bytes=min(req['aggregate_rss_bytes'], available - req['os_reserve_bytes']))
    assert req['aggregate_rss_bytes'] > 0, 'no RAM after OS reserve'
    write(out / 'binding.json', dict(binding, available_bytes=available, aggregate_cap_bytes=req['aggregate_rss_bytes'], request_sha256=digest(HERE/'CI-REQUEST.json'), inventory_sha256=digest(HERE/'roots.json')))
    # All frozen B roots share flags/cfg/RUSTFLAGS: exactly one group across historical shards.
    target, raw = out.parent/'target-b-group', out.parent/'export-b-group.json'
    assert not raw.exists() and not target.exists(), 'fresh group scratch required'
    group_seconds = req['compile_seconds'] + sum(req['root_seconds'] for _ in roots)
    argv = argv_for(req, roots, export/'scripts/kani', target, raw)
    execution = guarded(argv, std, group_seconds, dict(req, root_rss_bytes=req['aggregate_rss_bytes']), raw, out/'std-compile.json')
    write(out/'group.json', dict(execution, group_seconds=group_seconds,
        selectors=[r['selector'] for r in roots], per_root_rss_bytes='UNKNOWN',
        rss_attribution='group process-tree peak only; no reliable per-harness attribution'))
    write(out/'std-compile.json', execution['compile'])
    data, export_sha, error = None, None, 'MISSING_OR_OVERSIZE_EXPORT'
    if raw.exists() and raw.stat().st_size <= req['export_cap_bytes']:
        export_sha = digest(raw)
        try:
            data = json.loads(raw.read_text())
            error = None
        except (ValueError, OSError) as exc:
            error = 'INVALID_EXPORT: ' + repr(exc)
    for row in roots:
        receipt = initial(row)
        receipt.update(runtime_proof_status='ATTEMPTED', group_receipt='group.json',
                       export_sha256=export_sha, per_root_rss_bytes='UNKNOWN')
        receipt.update(unknown(error) if error else classify(data, row, execution, req, roots))
        write(out / ('root-%03d.json' % row['id']), receipt)
    if raw.exists():
        raw.unlink()  # Curated per-root structured results and bounded group receipts only.
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
    parser.add_argument('--out', required=True)
    parser.add_argument('--std')
    parser.add_argument('--export')
    parser.add_argument('--job-status', default='unknown')
    args = parser.parse_args()
    req, roots = load()
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
