#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""H1 CI observer. Local use is limited to synthetic tests/static inspection."""
from __future__ import annotations
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

SOURCE = '4f64cc617cbe6ebd13e83c07cc62fcf245e0b53c'
TREE = 'af28e22ec446b254cfa3a28b2882eafa58d5a458'
ROOTS = {
    'P1': ('scalar-pfc-legal.rs', 'postcondition_reads_initialized_return',
           'fe05e646b2ccc9188d073b78b30abecd59eb877b6298abfcdfc8a27aeb3a260b'),
    'P2': ('scalar-pfc-hole.rs', 'postcondition_reads_returned_hole',
           '61fc369a6830c6ff185887b04db36139ca529e4de097c0025ce7b29c8323f759'),
}
HERE = Path(__file__).resolve().parent
MAX_PREFIX = 4 * 1024**2
MAX_TAIL = 1024**2
MAX_OBJECT = 16 * 1024**2
MAX_PROPERTIES = 20000
MAX_EVENTS = 4096


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n')
    tmp.replace(path)


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024**2), b''):
            digest.update(block)
    return digest.hexdigest()


class Bounded:
    """Drain/hash the entire stream; independently retain its start and final tail."""
    def __init__(self, path, prefix=MAX_PREFIX, tail=MAX_TAIL):
        self.path, self.prefix_cap, self.tail_cap = Path(path), prefix, tail
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = self.path.open('wb')
        self.total = self.kept = 0
        self.tail = bytearray()
        self.digest = hashlib.sha256()

    def feed(self, block):
        self.total += len(block)
        self.digest.update(block)
        n = min(len(block), max(0, self.prefix_cap - self.kept))
        self.stream.write(block[:n])
        self.stream.flush()
        self.kept += n
        if self.tail_cap:
            self.tail.extend(block)
            del self.tail[:-self.tail_cap]

    def close(self):
        self.stream.close()
        self.path.with_suffix(self.path.suffix + '.tail').write_bytes(self.tail)
        return dict(total_bytes=self.total, prefix_bytes=self.kept,
                    tail_bytes=len(self.tail), complete=self.total <= self.kept,
                    original_sha256=self.digest.hexdigest())


class Observer:
    """Bounded streaming CBMC JSON objects; incomplete/malformed is never success."""
    def __init__(self, out, object_cap=MAX_OBJECT, property_cap=MAX_PROPERTIES):
        self.out, self.object_cap, self.property_cap = Path(out), object_cap, property_cap
        self.started = self.closed = self.in_string = self.escape = False
        self.depth = 0
        self.buf = bytearray()
        self.overflow = False
        self.errors = []
        self.events = []
        self.event_dropped = self.properties_dropped = self.property_total = 0
        self.properties = []
        self.result_seen = False
        self.prover = None
        self.start = time.monotonic()
        self.rounds = []
        self.counters = []
        self.conversion = []
        self.conversion_windows = []
        self.diagnostics = []

    def error(self, message):
        if len(self.errors) < 20:
            self.errors.append(message)

    def feed(self, block):
        for ch in block:
            if not self.started:
                if chr(ch).isspace():
                    continue
                if ch != ord('['):
                    self.error('non-array CBMC JSON')
                self.started = True
                continue
            if self.depth == 0:
                if ch == ord(']'):
                    self.closed = True
                elif ch == ord('{') and not self.closed:
                    self.depth = 1
                    self.buf = bytearray(b'{')
                elif ch not in b' \t\r\n,':
                    self.error('unexpected top-level token')
                continue
            if len(self.buf) < self.object_cap:
                self.buf.append(ch)
            else:
                self.overflow = True
            if self.in_string:
                if self.escape:
                    self.escape = False
                elif ch == ord('\\'):
                    self.escape = True
                elif ch == ord('"'):
                    self.in_string = False
            elif ch == ord('"'):
                self.in_string = True
            elif ch in b'{[':
                self.depth += 1
            elif ch in b'}]':
                self.depth -= 1
                if self.depth == 0:
                    if self.overflow:
                        self.error('object capture cap: inventory may be truncated')
                    else:
                        try:
                            self.item(json.loads(self.buf))
                        except (ValueError, TypeError) as exc:
                            self.error(str(exc)[:200])
                    self.buf.clear()
                    self.overflow = False

    def item(self, obj):
        if 'messageText' in obj:
            text = obj['messageText']
            if not isinstance(text, str):
                self.error('wrong-type messageText')
                return
            elapsed = time.monotonic() - self.start
            # Full initial phase and all numbered later rounds, bounded independently of logs.
            if re.search(r'symex|VCC|verification condition|SSA|convert|slicing|Passing problem|^Running |Runtime |variables.*clauses|solver|solving|SATISF|object.*bits|offset.*bits|malloc|object.*limit|too many.*object|unsupported|error', text, re.I):
                event = dict(seconds=elapsed, text=text[:4096], text_complete=len(text) <= 4096)
                if len(self.events) < MAX_EVENTS:
                    self.events.append(event)
                else:
                    self.event_dropped += 1
                match = re.search(r'(\d+) variables,?\s+(\d+) clauses', text)
                if match:
                    if len(self.rounds) < MAX_EVENTS:
                        self.rounds.append(dict(round=len(self.rounds)+1, seconds=elapsed,
                                                variables=int(match[1]), clauses=int(match[2])))
                if re.search(r'symex|VCC|verification condition', text, re.I) and len(self.counters) < MAX_EVENTS:
                    self.counters.append(event)
                if re.search(r'SSA|convert|^Running ', text, re.I) and len(self.conversion) < MAX_EVENTS:
                    self.conversion.append(event)
                if text == 'converting SSA' and len(self.conversion_windows) < MAX_EVENTS:
                    self.conversion_windows.append(dict(start_seconds=elapsed, end_seconds=None, elapsed_observed_seconds=None))
                elif text.startswith('Running ') and self.conversion_windows and self.conversion_windows[-1]['end_seconds'] is None:
                    window = self.conversion_windows[-1]
                    window.update(end_seconds=elapsed, elapsed_observed_seconds=elapsed-window['start_seconds'])
            if re.search(r'not enough.*object bits|too many.*object|object.*exhaust|maximum number of.*object|unsupported|invalid|error', text, re.I):
                if len(self.diagnostics) < 100:
                    self.diagnostics.append(text[:4096])
        if 'result' in obj:
            if not isinstance(obj['result'], list):
                self.error('null/wrong-type result')
                return
            if self.result_seen:
                self.error('multiple result arrays')
            self.result_seen = True
            for prop in obj['result']:
                self.property_total += 1
                if not isinstance(prop, dict) or not all(isinstance(prop.get(k), str) for k in ('property', 'description', 'status')):
                    self.error('invalid property')
                    continue
                if len(self.properties) >= self.property_cap:
                    self.properties_dropped += 1
                    continue
                ident = prop['property']
                self.properties.append(dict(id=ident, status=prop['status'],
                    description=prop['description'], source=prop.get('sourceLocation'),
                    property_class=prop.get('propertyClass'),
                    class_from_id=ident.rsplit('.', 2)[-2] if '.' in ident else None))
        if 'cProverStatus' in obj:
            value = obj['cProverStatus']
            if value not in ('success', 'failure'):
                self.error('wrong-type/unknown prover status')
            else:
                self.prover = value
        self.snapshot()

    def snapshot(self):
        write(self.out / 'phase.json', dict(events=self.events, events_dropped=self.event_dropped,
            symex_vcc=self.counters, conversion_messages=self.conversion,
            conversion_time='exact UNKNOWN; observation windows bracket conversion plus goal conversion/logging/scheduling',
            conversion_windows=self.conversion_windows, phase_capture_complete=self.event_dropped == 0,
            rounds=self.rounds, first_cnf=self.rounds[0] if self.rounds else None,
            first_cnf_missing='CENSORED_OR_NOT_REACHED' if not self.rounds else None,
            diagnostics=self.diagnostics, errors=self.errors))

    def finish(self):
        complete = (self.started and self.closed and self.depth == 0 and not self.errors
                    and self.result_seen and not self.properties_dropped and self.prover is not None)
        data = dict(complete=complete, status='COMPLETE' if complete else 'UNKNOWN',
                    errors=self.errors, result_seen=self.result_seen,
                    prover_status=self.prover, property_total=self.property_total,
                    retained=len(self.properties), dropped=self.properties_dropped,
                    properties=self.properties, semantic_oracle='UNKNOWN_REQUIRES_SOURCE_CALLSITE_BINDING')
        write(self.out / 'properties.json', data)
        self.snapshot()
        return data


def group_members(pgid):
    members = []
    for p in Path('/proc').iterdir():
        if p.name.isdigit():
            try:
                stat = (p/'stat').read_text().rsplit(')', 1)[1].split()
                if int(stat[2]) == pgid:
                    status = (p/'status').read_text()
                    match = re.search(r'^VmRSS:\s+(\d+) kB', status, re.M)
                    members.append((int(p.name), int(match[1]) if match else 0))
            except (OSError, ValueError, IndexError):
                pass
    return members


def kill_group(pgid, sig):
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        pass


def execute(argv, out, seconds, memory_kib=6291456, env=None, observer=None,
            sample=2.0, own_group=True):
    """Synthetic-safe subprocess monitor; never invoke this on local real tools."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    receipt = dict(argv=argv, cwd=str(Path.cwd()), state='STARTING', original_exit=None,
                   original_signal=None, watchdog=None, peak_sampled_rss_kib=0,
                   memory_limit_kib=memory_kib, timeout_seconds=seconds,
                   sampling_seconds=sample, verification='NOT_RUN')
    write(out/'process.json', receipt)
    sinks = {k: Bounded(out/(k+'.prefix')) for k in ('stdout', 'stderr')}
    start = time.monotonic()
    proc = None
    signals = []
    previous = {}
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env, start_new_session=own_group)
        def forward(sig, _frame):
            signals.append(sig)
            if own_group:
                receipt['watchdog'] = 'EXTERNAL_SIGNAL_'+str(sig)
            elif proc.poll() is None:
                proc.send_signal(sig)
        previous = {s: signal.signal(s, forward) for s in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
        receipt.update(state='RUNNING', pid=proc.pid, verification='UNKNOWN')
        write(out/'process.json', receipt)
        sel = selectors.DefaultSelector()
        for name, pipe in [('stdout', proc.stdout), ('stderr', proc.stderr)]:
            os.set_blocking(pipe.fileno(), False)
            sel.register(pipe, selectors.EVENT_READ, name)
        sample_at = start
        deadline = start + seconds
        kill_at = None
        rss_file = (out/'rss-kib.jsonl').open('w')
        while sel.get_map() or proc.poll() is None:
            now = time.monotonic()
            if own_group and now >= sample_at:
                members = group_members(proc.pid)
                rss = sum(v for _, v in members)
                receipt['peak_sampled_rss_kib'] = max(receipt['peak_sampled_rss_kib'], rss)
                rss_file.write(json.dumps(dict(seconds=now-start, rss_kib=rss, members=members))+'\n')
                rss_file.flush()
                sample_at = now + sample
                if rss > memory_kib and receipt['watchdog'] is None:
                    receipt['watchdog'] = 'RSS_LIMIT'
                    receipt['rss_overshoot_kib'] = rss-memory_kib
            if now >= deadline and receipt['watchdog'] is None:
                receipt['watchdog'] = 'TIMEOUT'
            if own_group and receipt['watchdog'] is not None and kill_at is None:
                kill_group(proc.pid, signal.SIGTERM)
                kill_at = now+2
                write(out/'process.json', receipt)
            if own_group and kill_at is not None and now >= kill_at:
                kill_group(proc.pid, signal.SIGKILL)
            for key, _ in sel.select(0.05):
                try:
                    block = os.read(key.fileobj.fileno(), 65536)
                except BlockingIOError:
                    continue
                if not block:
                    sel.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                sinks[key.data].feed(block)
                if key.data == 'stdout' and observer:
                    observer.feed(block)
                if not own_group:
                    # Preserve every byte to Kani; retention caps do not affect its parser.
                    dest = sys.stdout.buffer if key.data == 'stdout' else sys.stderr.buffer
                    dest.write(block)
                    dest.flush()
        rss_file.close()
        sel.close()
        code = proc.wait()
        receipt.update(state='FINISHED', original_exit=code if code >= 0 else None,
                       original_signal=-code if code < 0 else None, forwarded_signals=signals)
    except BaseException as exc:
        receipt.update(state='ERROR', exception=repr(exc))
        if proc is not None:
            if own_group:
                kill_group(proc.pid, signal.SIGKILL)
            elif proc.poll() is None:
                proc.kill()
            proc.wait()
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        if own_group and proc is not None:
            kill_group(proc.pid, signal.SIGKILL)
        receipt['elapsed_seconds'] = time.monotonic()-start
        receipt['streams'] = {k: v.close() for k,v in sinks.items()}
        if observer:
            receipt['parser'] = observer.finish()['status']
        write(out/'process.json', receipt)
    return receipt


def case_args(case, binary, input_path):
    _, root, _ = ROOTS[case['root']]
    args = [str(binary), str(input_path), '--harness', root, '--exact', '--keep-temps',
            '-Z', 'uninit-checks',
            '-Z', 'function-contracts', '-Z', 'unstable-options',
            '--output-format=regular', '--verbose']
    if case['mode'] == 'no-slice':
        args.append('--no-slice-formula')
    args += ['--cbmc-args', '--object-bits', str(case['object_bits'])]
    if case['mode'] == 'uf':
        args.append('--arrays-uf-always')
    return args


def validate_backend(argv, case):
    b = str(case['object_bits'])
    if argv.count('--object-bits') != 1 or any(a.startswith('--object-bits=') for a in argv):
        raise ValueError('duplicate/noncanonical object bits')
    idx = argv.index('--object-bits')
    if argv[idx+1] != b:
        raise ValueError('wrong effective object bits')
    if argv.count('--slice-formula') != (0 if case['mode'] == 'no-slice' else 1):
        raise ValueError('wrong slice mode')
    if argv.count('--arrays-uf-always') != (1 if case['mode'] == 'uf' else 0):
        raise ValueError('wrong array mode')
    if '--sat-solver' not in argv or argv[argv.index('--sat-solver')+1] != 'cadical':
        raise ValueError('wrong SAT backend')
    if argv[-3:] != ['--verbosity', '9', '--json-ui']:
        raise ValueError('unexpected Kani backend argv suffix')
    model = Path(argv[-4]).resolve()
    if not model.is_file():
        raise ValueError('actual Kani GOTO input missing')
    expected = ['--no-malloc-may-fail', '--no-undefined-shift-check',
                '--no-signed-overflow-check', '--nan-check',
                '--no-self-loops-to-assumptions', '--no-pointer-primitive-check',
                '--sat-solver', 'cadical']
    if case['mode'] != 'no-slice':
        expected.append('--slice-formula')
    expected += ['--object-bits', b]
    if case['mode'] == 'uf':
        expected.append('--arrays-uf-always')
    expected += [str(argv[-4]), '--verbosity', '9', '--json-ui']
    if argv != expected:
        raise ValueError('source/checks/solver/unwind/property-selection argv drift')
    return model


def cbmc_main():
    out = Path(os.environ['H1_CASE_OUT'])/'cbmc'
    out.mkdir(parents=True, exist_ok=True)
    args = sys.argv[1:]
    real = Path(os.environ['H1_REAL_CBMC']).resolve()
    if args == ['--version']:
        os.execv(str(real), [str(real), *args])
    case = json.loads(os.environ['H1_CASE'])
    try:
        # One exclusive normal invocation per singleton job; neither retry nor replay.
        fd = os.open(out/'normal.lock', os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        model = validate_backend(args, case)
        identity = dict(argv=[str(real), *args], cwd=str(Path.cwd()), case=case,
                        cbmc_path=str(real), cbmc_sha256=sha(real), goto_path=str(model),
                        goto_sha256=sha(model), goto_size=model.stat().st_size,
                        source=SOURCE, source_tree=TREE,
                        emitted_symbol_assigns_write_binding='UNKNOWN; inspect exact GOTO projection',
                        effective_object_bits=case['object_bits'], target_pointer_bits=64,
                        effective_offset_bits=64-case['object_bits'],
                        max_allocation_binding='UNKNOWN; derived expectation in matrix is not actual evidence')
        write(out/'identity.json', identity)
        if model.stat().st_size <= 128*1024**2:
            shutil.copyfile(model, out/'actual-input.goto')
        else:
            write(out/'goto-omitted.json', dict(reason='128MiB cap', **identity))
        receipt = execute([str(real), *args], out, 310, observer=Observer(out), own_group=False)
        if receipt.get('forwarded_signals'):
            sig = receipt['forwarded_signals'][-1]
        else:
            sig = receipt.get('original_signal')
        if sig:
            signal.signal(sig, signal.SIG_DFL)
            os.kill(os.getpid(), sig)
        return receipt['original_exit'] if receipt['original_exit'] is not None else 127
    except (OSError, ValueError, KeyError, IndexError) as exc:
        write(out/'refused.json', dict(error=repr(exc), argv=args, verification='NOT_RUN'))
        return 125


def classify(receipt, cbmc_receipt, inventory, diagnostics):
    if cbmc_receipt is None or (cbmc_receipt.get('state') == 'ERROR' and cbmc_receipt.get('original_exit') is None):
        return 'NOT_RUN'
    if re.search(r'not enough.*object bits|too many.*object|object.*exhaust|maximum number of.*object', '\n'.join(diagnostics), re.I):
        return 'OBJECT_CAPACITY_EXCEEDED/INCONCLUSIVE'
    if re.search(r'unsupported|unknown option|unrecognized option', '\n'.join(diagnostics), re.I):
        return 'MODE_UNQUALIFIED/INCONCLUSIVE'
    if receipt.get('watchdog') or cbmc_receipt.get('original_signal'):
        return 'RESOURCE_CENSORED/INCONCLUSIVE'
    if cbmc_receipt.get('state') != 'FINISHED' or cbmc_receipt.get('original_exit') not in (0, 10):
        return 'BACKEND_ERROR/INCONCLUSIVE'
    if not isinstance(inventory, dict) or inventory.get('complete') is not True:
        return 'INCOMPLETE/UNKNOWN'
    # No source/assigns/callsite oracle is inferred from total failed or var_N.
    return 'COMPLETED/SEMANTIC_BINDING_REQUIRED'


def load_optional(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


class ProjectionObserver:
    def __init__(self, out):
        self.out, self.pending = Path(out), bytearray()
        self.lines = 0
        self.context = []
        self.selected = []
        self.dropped = 0
        self.line_truncated = False
        self.pattern = re.compile(r'MEMORY_INITIALIZATION_STATE|MEM_INIT_STATE|memory_initialization|ARGUMENT_BUFFER|is assignable|__CPROVER_assignable|__CPROVER_max_malloc_size|__CPROVER_OBJECT_BITS|__CPROVER_contracts.*(write_set|assign)|array\[', re.I)

    def feed(self, block):
        # Stream every line, retaining bounded contexts, even beyond the log prefix.
        for ch in block:
            if ch == 10:
                self.lines += 1
                line = self.pending.decode(errors='replace')
                for selected in self.selected[-4:]:
                    if 0 < self.lines-selected['line'] <= 3:
                        selected.setdefault('after', []).append(line[:512])
                if self.pattern.search(line):
                    if len(self.selected) < 200:
                        self.selected.append(dict(line=self.lines, text=line,
                            text_complete=not self.line_truncated, before=list(self.context)))
                    else:
                        self.dropped += 1
                self.context = (self.context + [line[:512]])[-3:]
                self.pending.clear()
                self.line_truncated = False
            elif len(self.pending) < 2048:
                self.pending.append(ch)
            else:
                self.line_truncated = True

    def finish(self):
        data = dict(status='OBSERVATION_ONLY', selected=self.selected, dropped=self.dropped,
                    lines=self.lines, pending_line=bool(self.pending),
                    binding='UNKNOWN; requires actual symbol/assigns/write review',
                    coverage='streamed all complete lines; each line capped at 2048 bytes')
        write(self.out/'selected.json', data)
        return data


def projection(goto_path, tool, out):
    """Read-only GOTO inspection, never a solver replay or proof-input transform."""
    argv = [str(tool), '--show-goto-functions', str(goto_path)]
    execute(argv, out/'projection', 30, memory_kib=1048576,
            observer=ProjectionObserver(out/'projection'))
    execute([str(tool), '--show-symbol-table', str(goto_path)], out/'symbols', 30,
            memory_kib=1048576, observer=ProjectionObserver(out/'symbols'))


def run_case(ident, bundle, out):
    cases = json.loads((HERE/'matrix.json').read_text())
    case = next(c for c in cases if c['id'] == ident)
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    write(out/'outcome.json', dict(case=case, resource='NOT_RUN', semantics='UNKNOWN', source=SOURCE))
    filename, root, expected = ROOTS[case['root']]
    fixture = HERE/'cases'/filename
    if sha(fixture) != expected:
        raise ValueError('fixture identity mismatch')
    # The exact input path/unit is identical across every setting for a root.
    work = Path(os.environ['RUNNER_TEMP'])/'h1-input'
    work.mkdir(exist_ok=True)
    input_path = work/filename
    if input_path.exists():
        raise ValueError('existing case workdir; no retry')
    shutil.copyfile(fixture, input_path)
    bundle = Path(bundle).resolve()
    manifest = json.loads((bundle/'identity.json').read_text())
    if not isinstance(manifest, dict) or manifest.get('source') != SOURCE or manifest.get('tree') != TREE or manifest.get('cbmc_version') != '6.11.0' or manifest.get('target') != 'x86_64-unknown-linux-gnu':
        raise ValueError('source-stage-target bundle mismatch')
    required = {'bin/kani-driver', 'bin/kani-compiler', 'bin/cbmc', 'bin/goto-instrument'}
    if not isinstance(manifest.get('files'), dict) or not required.issubset(manifest['files']):
        raise ValueError('missing/null/wrong-type tool identity inventory')
    for name, expected_hash in manifest['files'].items():
        if sha(bundle/name) != expected_hash:
            raise ValueError('tool/sysroot bundle hash mismatch: '+name)
    driver = bundle/'bin/kani-driver'
    real = bundle/'bin/cbmc'
    shim = out/'shim'
    shim.mkdir()
    (shim/'cbmc').symlink_to(HERE/'runner.py')
    env = os.environ.copy()
    env.pop('CARGO_ENCODED_RUSTFLAGS', None)
    env.update(RUSTFLAGS='--edition 2021 -D warnings', H1_CASE_OUT=str(out), H1_CASE=json.dumps(case), H1_REAL_CBMC=str(real),
               PATH=str(shim)+os.pathsep+str(bundle/'bin')+os.pathsep+env['PATH'])
    args = case_args(case, driver, input_path)
    write(out/'identity.json', dict(source=SOURCE, tree=TREE, ci_head=os.environ.get('GITHUB_SHA'),
        fixture_sha256=sha(input_path), root=root, argv=args, case=case, bundle=manifest,
        rustflags=env['RUSTFLAGS'], jobs='NoMultithreading (default 1); explicit --jobs conflicts with regular',
        model_comparison='Do not normalize proof input; compare unrelated compile signatures separately'))
    previous = Path.cwd()
    os.chdir(work)
    try:
        receipt = execute(['/usr/bin/time', '-v', '-o', str(out/'time-v.txt'), '--', *args],
                          out/'kani', 300, env=env)
    finally:
        os.chdir(previous)
    # Metadata is bounded and source-bound; no arbitrary glob-selected GOTO.
    kept = []
    for path in sorted(work.iterdir()):
        if path.is_file() and path.suffix == '.json' and path.stat().st_size <= 16*1024**2:
            if sum(x['bytes'] for x in kept) + path.stat().st_size <= 32*1024**2:
                (out/'metadata').mkdir(exist_ok=True)
                shutil.copyfile(path, out/'metadata'/path.name)
                kept.append(dict(path=path.name, bytes=path.stat().st_size, sha256=sha(path)))
    write(out/'metadata-index.json', dict(kept=kept, coverage='BOUNDED; missing binding remains UNKNOWN'))
    cbmc = load_optional(out/'cbmc'/'process.json')
    inv = load_optional(out/'cbmc'/'properties.json')
    phase = load_optional(out/'cbmc'/'phase.json') or {}
    identity = load_optional(out/'cbmc'/'identity.json')
    if identity and not str(receipt.get('watchdog', '')).startswith('EXTERNAL_SIGNAL'):
        actual = Path(identity['goto_path'])
        if actual.exists() and sha(actual) == identity['goto_sha256']:
            projection(actual, bundle/'bin/goto-instrument', out)
    time_v = (out/'time-v.txt').read_text(errors='replace') if (out/'time-v.txt').exists() else ''
    maxrss = re.search(r'Maximum resident set size \(kbytes\):\s*(\d+)', time_v)
    command_signal = re.search(r'Command terminated by signal (\d+)', time_v)
    command_exit = re.search(r'Exit status:\s*(\d+)', time_v)
    kani_original_signal = int(command_signal[1]) if command_signal else None
    kani_original_exit = (int(command_exit[1]) if command_exit and not command_signal
                          and not receipt['watchdog'] and 'cannot run ' not in time_v else None)
    resource = classify(receipt, cbmc, inv, phase.get('diagnostics', []))
    write(out/'outcome.json', dict(case=case, resource=resource,
        semantics='UNKNOWN; apply ORACLES.md to full inventory and source/callsite/assigns binding',
        kani_time_exit=receipt['original_exit'], kani_time_signal=receipt['original_signal'],
        kani_original_exit=kani_original_exit, kani_original_signal=kani_original_signal,
        kani_signal_from_time_v=int(command_signal[1]) if command_signal else None,
        kani_exit_status_binding='time exit equals child exit only absent watchdog/signal/launch failure',
        cbmc=cbmc, parser=inv.get('status') if isinstance(inv, dict) else 'UNKNOWN',
        watchdog=receipt['watchdog'], time_v_maxrss_kib=int(maxrss[1]) if maxrss else None,
        sampled_group_peak_rss_kib=receipt['peak_sampled_rss_kib'], source=SOURCE,
        independent_proof_credit=0))
    # Resource kill / semantic failure is retained but never accepted as a successful proof.
    return 0 if resource == 'COMPLETED/SEMANTIC_BINDING_REQUIRED' else 1


def bundle_identity(bundle, source):
    bundle, source = Path(bundle), Path(source)
    actual = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
    tree = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD^{tree}'], text=True).strip()
    diff = subprocess.check_output(['git', '-C', str(source), 'diff', '--name-only'], text=True)
    if actual != SOURCE or tree != TREE or diff:
        raise ValueError('source identity/diff mismatch')
    version_raw = subprocess.check_output([str(bundle/'bin/cbmc'), '--version'], text=True).strip()
    if version_raw not in ('6.11.0', '6.11.0 (cbmc-6.11.0)'):
        raise ValueError('stock CBMC version mismatch')
    version = '6.11.0'
    files = {str(p.relative_to(bundle)): sha(p) for p in sorted(bundle.rglob('*')) if p.is_file()}
    toolchain = subprocess.check_output(['rustc', '-vV'], cwd=source, text=True)
    write(bundle/'identity.json', dict(source=SOURCE, tree=TREE, source_diff=[],
        ci_head=os.environ.get('GITHUB_SHA'), cbmc_version=version, cbmc_version_raw=version_raw, files=files,
        compiler=toolchain, toolchain_file=(source/'rust-toolchain.toml').read_text(),
        kani_dependencies=(source/'kani-dependencies').read_text(), target='x86_64-unknown-linux-gnu',
        solver='cadical bundled in stock CBMC', build_command='cargo bundle -- h1',
        private_marker_binding='SOURCE_ONLY; actual generated assigns/write inventory required',
        step0_counts='UNKNOWN; R1/R6 counts cannot be assigned to 4f64'))


def main():
    if Path(sys.argv[0]).name == 'cbmc':
        return cbmc_main()
    cmd, *args = sys.argv[1:]
    if cmd == 'case':
        return run_case(*args)
    if cmd == 'bundle-identity':
        bundle_identity(*args)
        return 0
    if cmd == 'phase':
        out, seconds, memory, *argv = args
        receipt = execute(argv, out, float(seconds), int(memory))
        return 0 if receipt['state'] == 'FINISHED' and receipt['original_exit'] == 0 and not receipt['watchdog'] else 1
    raise ValueError('unknown command')


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(repr(exc), file=sys.stderr)
        # The workflow initializes NOT_RUN before any setup; never convert this to PASS.
        raise
