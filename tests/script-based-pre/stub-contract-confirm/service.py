# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Collect native process status and bounded diagnostics."""
import hashlib
import os
import re
import signal
import subprocess
import resource
import threading
from pathlib import Path
import time


def regular_inventory(stdout):
    result = {}
    current = None
    prop = None
    for line in stdout.splitlines():
        match = re.fullmatch(r"Checking harness (.+)\.\.\.", line)
        if match:
            current = match[1]
            if current in result:
                return {}
            result[current] = []
            prop = None
        match = re.fullmatch(r"Check (\d+): (.+)", line)
        if current and match:
            prop = {"index": int(match[1]), "id": match[2]}
            result[current].append(prop)
        elif prop:
            match = re.fullmatch(r'\s+- (Status|Description|Location): (.*)', line)
            if match:
                key, value = match.groups()
                if key == "Description" and value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                prop[key.lower()] = value
    return result


STREAM_CAP = 2 * 1024 * 1024
RSS_CAP = 8 * 1024 * 1024 * 1024
BLOCK_CAP = 4096
BLOCK_COUNT = 32


def diagnostics(text):
    starts = list(re.finditer(r'(?m)^error(?:\[[^\]\n]+\])?:[^\n]*', text))
    blocks = []
    complete = len(starts) <= BLOCK_COUNT
    for index, match in enumerate(starts[:BLOCK_COUNT]):
        end = starts[index + 1].start() if index + 1 < len(starts) else len(text)
        block = text[match.start():end].strip()
        raw = block.encode()
        complete &= len(raw) <= BLOCK_CAP
        blocks.append({'header': match[0], 'text': raw[:BLOCK_CAP].decode(errors='replace'),
                       'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                       'complete': len(raw) <= BLOCK_CAP})
    return blocks, complete


def group_rss(pgid):
    total = 0
    for path in Path('/proc').glob('[0-9]*/stat'):
        try:
            # Fields following the command name start with state, ppid and pgrp.
            fields = path.read_text().rsplit(')', 1)[1].split()
            if int(fields[2]) == pgid:
                total += int(fields[21]) * os.sysconf('SC_PAGE_SIZE')
        except (OSError, ValueError, IndexError):
            continue
    return total


def execute(argv, cwd, timeout, env=None):
    started = time.monotonic()
    child_env = os.environ.copy()
    for key, value in (env or {}).items():
        if value is None:
            child_env.pop(key, None)
        else:
            child_env[key] = value
    record = {'argv': argv, 'cwd': str(cwd), 'timeout_seconds': timeout,
              'exit': None, 'signal': None, 'termination': 'NOT_RUN',
              'environment': {key: child_env.get(key) for key in (
                  'PATH', 'RUSTUP_TOOLCHAIN', 'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS',
                  'KANIFLAGS', 'KANI_LOG', 'NO_COLOR', 'RUST_BACKTRACE',
                  'CARGO_TARGET_DIR', 'CARGO_BUILD_TARGET', 'KANI_FAIL_ON_UNEXPECTED_DESCRIPTION')},
              'rss_cap_bytes': RSS_CAP, 'sampled_group_peak_rss_bytes': 0}
    streams = {}
    exceeded = threading.Event()

    def limits():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_AS, (RSS_CAP, RSS_CAP))

    def drain(pipe, label):
        data = bytearray()
        digest = hashlib.sha256()
        size = 0
        with pipe:
            while chunk := pipe.read(65536):
                size += len(chunk)
                digest.update(chunk)
                data.extend(chunk[:max(0, STREAM_CAP - len(data))])
                if size > STREAM_CAP:
                    exceeded.set()
        streams[label] = {'data': bytes(data), 'bytes': size, 'sha256': digest.hexdigest(),
                          'complete': size <= STREAM_CAP}

    threads = []
    try:
        proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, env=child_env, preexec_fn=limits)
        for label, pipe in [('stdout', proc.stdout), ('stderr', proc.stderr)]:
            thread = threading.Thread(target=drain, args=(pipe, label), daemon=True)
            thread.start()
            threads.append(thread)
        reason = 'EXITED'
        while True:
            rss = group_rss(proc.pid)
            record['sampled_group_peak_rss_bytes'] = max(record['sampled_group_peak_rss_bytes'], rss)
            if exceeded.is_set():
                reason = 'OUTPUT_CAP'
            elif rss > RSS_CAP:
                reason = 'RSS_CAP'
            elif time.monotonic() - started > timeout:
                reason = 'TIMEOUT'
            done = proc.poll() is not None
            if reason != 'EXITED' or (done and all(not t.is_alive() for t in threads)):
                break
            time.sleep(.02)
        # Close descendants that retain a pipe after the parent has exited.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        record.update(exit=proc.wait(), termination=reason)
        for thread in threads:
            thread.join(timeout=2)
        if any(t.is_alive() for t in threads):
            record['termination'] = 'INCOMPLETE_STREAM'
    except OSError as error:
        record.update(termination='SPAWN_ERROR', error=str(error))
    record['signal'] = -record['exit'] if type(record['exit']) is int and record['exit'] < 0 else None
    record['streams'] = {}
    record['diagnostics'] = []
    record['diagnostics_complete'] = True
    for label in ('stdout', 'stderr'):
        stream = streams.get(label, {'data': b'', 'bytes': 0, 'sha256': None, 'complete': False})
        raw = stream.pop('data')
        text = raw.decode(errors='replace')
        blocks, complete = diagnostics(text)
        record['diagnostics'] += [dict(block, stream=label) for block in blocks]
        record['diagnostics_complete'] &= complete and stream['complete']
        stream['head'] = [line[:500] for line in text[:4096].splitlines()[:18]]
        stream['tail'] = [line[:500] for line in text[-8192:].splitlines()[-8:]]
        record['streams'][label] = stream
        if label == 'stdout':
            record['property_inventory'] = regular_inventory(text) if stream['complete'] else {}
            record['verification_success'] = text.count('VERIFICATION:- SUCCESSFUL')
        record.setdefault('compiler_process_hints', []).extend(
            re.findall(r'(?m)^.*(?:process didn.t exit successfully|signal: \d+|SIGABRT).{0,500}$', text)[:8])
    record['elapsed_seconds'] = round(time.monotonic() - started, 3)
    return record
