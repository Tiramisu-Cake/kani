#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
import os
from pathlib import Path
import signal
import sys

from capture import digest, exit_code, run, save, snapshot


def invoke(tool, args):
    config = json.loads(Path(os.environ['D1P_CONFIG']).read_text())
    spec = config['tools'][tool]
    real = Path(spec['path']).resolve(strict=True)
    if real == Path(sys.argv[0]).resolve() or digest(real) != spec['sha256']:
        raise RuntimeError('tool identity mismatch or PATH recursion')
    root = Path(config['case_dir'])
    # Every actual invocation, including driver version probes, gets a receipt.
    base = root/'invocations'
    base.mkdir(exist_ok=True)
    for number in range(100):
        slot = base/f'{tool}-{number:03d}'
        try:
            slot.mkdir()
            break
        except FileExistsError:
            continue
    else:
        raise RuntimeError('invocation count cap')
    dfcc = tool == 'goto-instrument' and '--dfcc' in args
    version = args == ['--version']
    if dfcc:
        (root/'dfcc-once').mkdir()  # duplicate is an error, never select an arbitrary one
        if len(args) < 3 or not Path(args[-2]).is_file():
            raise RuntimeError('unknown DFCC input/output grammar')
        save(slot/'dfcc.json', dict(root=args[args.index('--dfcc')+1], argv=args,
             modes=[a for a in args if a.startswith('--')],
             input=str(Path(args[-2]).resolve()), output=str(Path(args[-1]).resolve())))
        snapshot(args[-2], slot/'pre-dfcc.goto')
    if tool == 'cbmc' and not version:
        (root/'cbmc-once').mkdir()
        if args.count('--program-only') != 1:
            raise RuntimeError('refuse non-symex invocation')
        prohibited = ['--show-vcc', '--show-byte-ops', '--full-slice', '--property',
                      '--dimacs', '--arrays-uf-always', '--arrays-uf-never',
                      '--write-solver-stats-to']
        if any(a.split('=')[0] in prohibited for a in args):
            raise RuntimeError('unexpected diagnostic/scope option')
        files = [(i, a) for i, a in enumerate(args) if Path(a).is_file()]
        if len(files) != 1:
            raise RuntimeError('ambiguous actual CBMC input')
        index, source = files[0]
        snap = snapshot(source, slot/'actual-cbmc.goto')
        save(root/'actual-input.json', dict(invocation=str(slot), input_index=index,
             source=source, snapshot=str(slot/'actual-cbmc.goto'), model=snap,
             actual_argv=[str(real)]+args, diagnostic_option='--program-only',
             normal_invocation='NOT_RUN', solver='unchanged driver selection; see actual argv',
             property_set='unchanged', checks='unchanged', defaults='stock 6.11.0'))
    # stdout/stderr are forwarded unchanged, outside receipt files. Once only.
    receipt = run([str(real)]+args, slot/'process', seconds=60 if tool=='cbmc' else 300,
                  rss_kib=2097152, forward=True,
                  as_kib=2097152 if tool=='cbmc' and not version else None)
    if dfcc and receipt['original_rc'] == 0 and not receipt['limiter_reason']:
        snapshot(args[-1], slot/'post-dfcc.goto')
    save(slot/'boundary.json', dict(tool=tool, dfcc=dfcc, version_probe=version,
         status='COMPLETE' if exit_code(receipt)==0 and receipt['stream_complete'] else 'INCOMPLETE'))
    if receipt['original_signal'] and not receipt['limiter_reason']:
        signal.signal(receipt['original_signal'], signal.SIG_DFL)
        os.kill(os.getpid(), receipt['original_signal'])
    return exit_code(receipt)


if __name__ == '__main__':
    try:
        raise SystemExit(invoke(Path(sys.argv[0]).name, sys.argv[1:]))
    except Exception as exc:
        # No fabricated backend output: errors go to stderr and a separate receipt.
        try:
            save(Path(os.environ['D1P_CASE_DIR'])/'wrapper-error.json',
                 dict(status='CAPTURE_ERROR', error=type(exc).__name__+': '+str(exc)))
        finally:
            print('D1P capture error: '+str(exc), file=sys.stderr)
        raise SystemExit(125)
