#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Bounded byte collector; only callers decide whether a command is admitted."""
import datetime
import ctypes
import hashlib
import json
import os
from pathlib import Path
import selectors
import resource
import re
from collections import deque
import signal
import subprocess
import time

MIB = 1048576


def stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(65536), b''):
            h.update(block)
    return h.hexdigest()


def save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def snapshot(src, dst, limit=64*MIB):
    src, dst = Path(src), Path(dst)
    n = src.stat().st_size
    receipt = dict(source=str(src.resolve()), bytes=n, limit_bytes=limit,
                   complete=False, sha256=None)
    if n > limit:
        save(str(dst)+'.json', receipt)
        raise RuntimeError('snapshot cap: completeness STOP')
    # Exclusive create: a second invocation must never overwrite the first.
    with src.open('rb') as inp, dst.open('xb') as out:
        for block in iter(lambda: inp.read(65536), b''):
            out.write(block)
    receipt.update(complete=True, sha256=digest(dst))
    save(str(dst)+'.json', receipt)
    return receipt


def tree_processes(root):
    """Linux process tree, including sessions created by nested capture wrappers."""
    table = {}
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            fields = path.read_text().rsplit(')', 1)[1].split()
            pid = int(path.parent.name)
            rss = int(fields[21]) * os.sysconf('SC_PAGE_SIZE') // 1024
            table[pid] = (int(fields[1]), int(fields[2]), rss, fields[0])
        except (OSError, ValueError, IndexError):
            continue
    found = {root}
    while True:
        more = {pid for pid, (ppid, _, _, _) in table.items() if ppid in found}
        if more <= found:
            break
        found |= more
    return {pid: table[pid] for pid in found if pid in table}


def kill_groups(groups):
    for pgid in groups:
        if pgid == os.getpgrp():
            raise RuntimeError('refuse collector/runner process group')
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass


class Milestones:
    """First/final matching counters independent of the capped byte prefix."""
    pattern = re.compile(rb'Generated|size of program|VCC|verification conditions|symex|Symex|Runtime|VERIFICATION|FAILURE|ERROR|clauses|variables|Convert|converting|solver')
    def __init__(self):
        self.buffer=bytearray()
        self.long=False
        self.first=[]
        self.last=deque(maxlen=100)
        self.seen=self.lines=self.bytes=self.long_lines=0
    def feed(self, block):
        # Chunk processing is bounded; a long line is discarded until newline.
        for part in block.splitlines(keepends=True):
            self.bytes += len(part)
            ends=part.endswith(b'\n')
            if not self.long:
                if len(self.buffer)+len(part)>4096:
                    self.buffer.clear()
                    self.long=True
                    self.long_lines += 1
                else:
                    self.buffer.extend(part)
            if ends:
                self.lines += 1
                if not self.long and self.pattern.search(self.buffer):
                    self.seen += 1
                    entry=dict(line=self.lines,end_byte=self.bytes,text=self.buffer.decode('utf-8','replace').rstrip('\n'))
                    if len(self.first)<100:
                        self.first.append(entry)
                    else:
                        self.last.append(entry)
                self.buffer.clear()
                self.long=False
    def report(self):
        records=self.first+list(self.last)
        return dict(records=records,limit_records=200,matched_records=self.seen,
                    emitted_records=len(records),dropped_records=self.seen-len(records),
                    emitted_bytes=sum(len(x['text'].encode()) for x in records),
                    truncated=self.seen>len(records),long_lines_skipped=self.long_lines,
                    partial_line=bool(self.buffer) or self.long,
                    coverage='textual milestone matches; absence UNKNOWN; not semantic verdict')


def run(argv, directory, *, cwd=None, env=None, seconds=60, rss_kib=2097152,
        cap=8*MIB, forward=False, as_kib=None):
    """Drain both streams after cap and after EPIPE. No shell, no output rewriting.

    Child has its own session. wait4 ru_maxrss is distinct from sampled RSS and
    from time-v (not used). Return code/signal are those of the immediate child.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    receipt = dict(argv=list(argv), cwd=str(Path(cwd or os.getcwd()).resolve()),
                   started=stamp(), limit_seconds=seconds, limit_rss_kib=rss_kib,
                   rlimit_as_kib=as_kib,
                   accounting_scope='sampled sum of live descendant RSS; shared pages may repeat',
                   sample_interval_seconds=0.05, sampled_max_rss_kib=0,
                   time_v_maxrss_kib=None, wait4_maxrss_kib=None,
                   limiter_reason=None, original_rc=None, original_signal=None,
                   collector_status='RUNNING', verification='NOT_RUN')
    outputs = {}
    milestones = {name: Milestones() for name in ("stdout","stderr")}
    streams = {}
    sel = selectors.DefaultSelector()
    groups = set()
    started = time.monotonic()
    child = None
    subreaper_prior = None
    baseline = set()
    owned = {}
    pending = {1: bytearray(), 2: bytearray()}
    fd_blocking = {}
    interrupted = []
    prior = {}
    def on_signal(sig, _frame):
        interrupted.append(sig)
    for sig in (signal.SIGTERM, signal.SIGINT):
        prior[sig] = signal.signal(sig, on_signal)
    try:
        # Adopt orphaned setsid descendants instead of losing them to PID 1.
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        if libc.prctl(37, ctypes.byref(previous), 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'PR_GET_CHILD_SUBREAPER')
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER')
        subreaper_prior = previous.value
        baseline = set(tree_processes(os.getpid()))
        receipt['cleanup_scope'] = 'owned session descendants plus subreaper-adopted orphan sessions'
        receipt['resolved_executable'] = str(Path(argv[0]).resolve())
        receipt['executable_sha256'] = digest(argv[0])
        def child_limits():
            if as_kib is not None:
                resource.setrlimit(resource.RLIMIT_AS, (as_kib*1024, as_kib*1024))
        child = subprocess.Popen(argv, cwd=cwd, env=env, start_new_session=True,
                                 preexec_fn=child_limits,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        groups.add(child.pid)
        receipt.update(pid=child.pid, pgid=child.pid, session=child.pid)
        save(directory/'spawn.json', receipt)
        if forward:
            for fd in (1, 2):
                fd_blocking[fd] = os.get_blocking(fd)
                os.set_blocking(fd, False)
        for name, stream, fd in [('stdout', child.stdout, 1), ('stderr', child.stderr, 2)]:
            outputs[name] = (directory/(name+'.bin')).open('xb')
            streams[name] = dict(limit_bytes=cap, emitted_bytes=0, dropped_bytes=0,
                                 total_bytes=0, records_newline=0, truncated=False,
                                 forwarding_epipe=False)
            sel.register(stream, selectors.EVENT_READ, (name, fd))
        status = None
        usage = None
        descendants_alive = True
        while sel.get_map() or status is None or any(pending.values()) or descendants_alive:
            if forward:
                for name, fd in [('stdout', 1), ('stderr', 2)]:
                    if pending[fd]:
                        try:
                            n = os.write(fd, pending[fd])
                            del pending[fd][:n]
                        except BlockingIOError:
                            pass
                        except BrokenPipeError:
                            streams[name]['forwarding_epipe'] = True
                            pending[fd].clear()
            live = {pid: value for pid, value in tree_processes(os.getpid()).items()
                    if pid not in baseline}
            owned.update(live)
            descendants_alive = any(v[3] != 'Z' for v in live.values())
            groups.update(pgid for _, pgid, _, _ in live.values() if pgid != os.getpgrp())
            for pid, (_, _, _, state) in live.items():
                if pid != child.pid and state == 'Z':
                    try:
                        os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass
            rss = sum(v[2] for v in live.values())
            receipt['sampled_max_rss_kib'] = max(rss, receipt['sampled_max_rss_kib'])
            reason = ('external_signal' if interrupted else
                      'wall_timeout' if time.monotonic()-started > seconds else
                      'rss_limit' if rss > rss_kib else None)
            if reason and receipt['limiter_reason'] is None:
                receipt.update(limiter_reason=reason, watchdog_sample_rss_kib=rss,
                               watchdog_at=stamp(), received_signals=interrupted[:])
                kill_groups(groups)
                for buffer in pending.values():
                    buffer.clear()
            for key, _ in sel.select(0.05):
                name, fd = key.data
                if forward and len(pending[fd]) >= 131072:
                    continue  # bounded pipe backpressure; watchdog keeps running
                block = os.read(key.fileobj.fileno(), 65536)
                if not block:
                    sel.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                milestones[name].feed(block)
                info = streams[name]
                info['total_bytes'] += len(block)
                info['records_newline'] += block.count(b'\n')
                room = max(0, cap-info['emitted_bytes'])
                kept = block[:room]
                outputs[name].write(kept)
                info['emitted_bytes'] += len(kept)
                info['dropped_bytes'] += len(block)-len(kept)
                info['truncated'] = info['dropped_bytes'] > 0
                if forward and not info['forwarding_epipe']:
                    if not receipt['limiter_reason']:
                        pending[fd].extend(block)
            if status is None:
                pid, value, ru = os.wait4(child.pid, os.WNOHANG)
                if pid:
                    status, usage = value, ru
                    child.returncode = os.waitstatus_to_exitcode(status)
        receipt.update(original_rc=child.returncode if child.returncode >= 0 else None,
                       original_signal=-child.returncode if child.returncode < 0 else None,
                       wait4_maxrss_kib=usage.ru_maxrss,
                       collector_status='COMPLETE', streams=streams)
    except Exception as exc:
        receipt.update(collector_status='ERROR', error=type(exc).__name__+': '+str(exc))
        if child:
            kill_groups(groups)
            rc=child.wait()
            receipt.update(original_rc=rc if rc>=0 else None, original_signal=-rc if rc<0 else None)
    finally:
        if child:
            kill_groups(groups)  # descendants may outlive immediate child
        # Reap only owned adopted children; never wait for unrelated children.
        for pid in owned:
            if child and pid != child.pid:
                try:
                    os.waitpid(pid, os.WNOHANG)
                except ChildProcessError:
                    pass
        if subreaper_prior is not None:
            libc.prctl(36, subreaper_prior, 0, 0, 0)
        for out in outputs.values():
            out.close()
        sel.close()
        for fd, blocking in fd_blocking.items():
            os.set_blocking(fd, blocking)
        for sig, handler in prior.items():
            signal.signal(sig, handler)
        receipt.update(finished=stamp(), elapsed_seconds=time.monotonic()-started)
        receipt['stream_complete'] = (receipt['collector_status']=='COMPLETE'
            and not receipt['limiter_reason']
            and all(not s['truncated'] and not s['forwarding_epipe'] for s in streams.values()))
        save(directory/'milestones.json',{name: value.report() for name,value in milestones.items()})
        save(directory/'receipt.json', receipt)
    return receipt


def exit_code(receipt):
    if receipt['collector_status'] != 'COMPLETE':
        return 125
    if receipt['limiter_reason']:
        return 124
    if receipt['original_signal']:
        return 128+receipt['original_signal']
    return receipt['original_rc']
