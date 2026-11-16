#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Stream one CI gate and persist only its exit and bounded output tail."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading

TAIL_BYTES = 16384


def run_gate(argv, cwd, out, gate, timeout=6900):
    if not gate or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_' for c in gate):
        raise ValueError('invalid gate ID')
    out.mkdir(parents=True, exist_ok=True)
    receipt = out / f'{gate}.json'
    state = {'gate': gate, 'argv': argv, 'cwd': str(cwd), 'status': 'IN_PROGRESS',
             'exit_code': None, 'tail_limit_bytes': TAIL_BYTES}
    receipt.write_text(json.dumps(state, indent=2) + '\n')
    tail = b''
    timer = None
    timed_out = threading.Event()
    proc = None
    try:
        proc = subprocess.Popen(argv, cwd=cwd, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)

        def expire():
            timed_out.set()
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        timer = threading.Timer(timeout, expire)
        timer.start()
        while chunk := proc.stdout.read1(8192):
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
            tail = (tail + chunk)[-TAIL_BYTES:]
        code = proc.wait()
        state.update(status='TIMEOUT' if timed_out.is_set() else 'COMPLETED',
                     exit_code=code)
        return 124 if timed_out.is_set() else (code if code >= 0 else 128 - code)
    except Exception as exc:
        state.update(status='ERROR', error=f'{type(exc).__name__}: {exc}')
        if proc is not None and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGKILL)
            state['exit_code'] = proc.wait()
        return 1
    finally:
        if timer is not None:
            timer.cancel()
        if proc is not None and proc.stdout is not None:
            proc.stdout.close()
        (out / f'{gate}.tail.txt').write_bytes(tail)
        receipt.write_text(json.dumps(state, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--id', required=True)
    parser.add_argument('--cwd', required=True, type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    argv = args.command[1:] if args.command[:1] == ['--'] else args.command
    return run_gate(argv, args.cwd, Path(os.environ['RUNNER_TEMP']) / 'ch8-pr02-reset-a', args.id)


if __name__ == '__main__':
    raise SystemExit(main())
