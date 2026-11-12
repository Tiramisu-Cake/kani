#!/usr/bin/env python3
"""CI-only transparent CBMC stdout capture wrapper (install as a `cbmc` PATH shim)."""
from __future__ import annotations

import hashlib
import ctypes
import json
import os
import signal
import subprocess
import sys
import uuid
from pathlib import Path
from typing import BinaryIO

MAX_CAPTURE_BYTES = 64 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
FORWARDED_SIGNAL: int | None = None


def _set_linux_parent_death_signal(parent_pid: int) -> None:
    """Kill the solver if this wrapper dies, including SIGKILL from harness timeout."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
        os._exit(127)
    # Close the race where the wrapper died before prctl was installed.
    if os.getppid() != parent_pid:
        os.kill(os.getpid(), signal.SIGKILL)


def run_capture(argv: list[str], real_binary: str, capture_dir: str, stdout: BinaryIO,
                capture_limit: int = MAX_CAPTURE_BYTES, invoked_as: str = "cbmc") -> tuple[int, Path]:
    """Run CBMC without changing options, forwarding all stdout while retaining a capped prefix."""
    global FORWARDED_SIGNAL
    FORWARDED_SIGNAL = None
    executable = Path(real_binary)
    if not executable.is_absolute() or not executable.is_file():
        raise RuntimeError("D0_REAL_CBMC must name an existing absolute executable")
    if not sys.platform.startswith("linux"):
        raise RuntimeError("capture wrapper requires Linux parent-death signal support")
    root = Path(capture_dir)
    root.mkdir(parents=True, exist_ok=True)
    ident = uuid.uuid4().hex
    stdout_path = root / f"{ident}.json"
    metadata_path = root / f"{ident}.meta.json"
    digest = hashlib.sha256()
    retained = dropped = 0
    child_argv = [invoked_as, *argv]
    metadata = {
        "schema_version": "kani3300-d0-cbmc-capture-v1", "capture_id": ident,
        "argv": child_argv, "child_exit": None, "child_signal": None,
        "wrapper_signal": None, "original_stdout_sha256": None,
        "retained_stdout_file": stdout_path.name, "retained_bytes": 0,
        "dropped_bytes": 0, "capture_limit_bytes": capture_limit,
        "captured_complete": False, "capture_state": "RUNNING",
    }
    tmp = metadata_path.with_suffix(".meta.tmp")
    tmp.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, metadata_path)
    child: subprocess.Popen[bytes] | None = None
    parent_pid = os.getpid()

    def forward_signal(signum: int, _frame: object) -> None:
        global FORWARDED_SIGNAL
        FORWARDED_SIGNAL = signum
        if child is not None and child.poll() is None:
            child.send_signal(signum)

    handled_signals = [signal.SIGTERM, signal.SIGINT, signal.SIGHUP]
    previous_handlers = {sig: signal.signal(sig, forward_signal) for sig in handled_signals}
    with stdout_path.open("xb") as archive:
        child = subprocess.Popen(child_argv, executable=str(executable), stdout=subprocess.PIPE, stderr=None,
                                 bufsize=0, preexec_fn=lambda: _set_linux_parent_death_signal(parent_pid))
        if FORWARDED_SIGNAL is not None:
            child.send_signal(FORWARDED_SIGNAL)
        assert child.stdout is not None
        while True:
            chunk = child.stdout.read(CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            stdout.write(chunk)
            stdout.flush()
            keep = min(len(chunk), max(0, capture_limit - retained))
            if keep:
                archive.write(chunk[:keep])
                retained += keep
            dropped += len(chunk) - keep
        child.stdout.close()
        child_exit = child.wait()
    for sig, handler in previous_handlers.items():
        signal.signal(sig, handler)
    metadata.update({"child_exit": child_exit if child_exit >= 0 else None,
                     "child_signal": -child_exit if child_exit < 0 else None,
                     "wrapper_signal": FORWARDED_SIGNAL,
                     "original_stdout_sha256": digest.hexdigest(),
                     "retained_bytes": retained, "dropped_bytes": dropped,
                     "captured_complete": dropped == 0, "capture_state": "COMPLETE"})
    tmp = metadata_path.with_suffix(".meta.tmp")
    tmp.write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, metadata_path)
    return child_exit, metadata_path


def main() -> int:
    real_binary = os.environ.get("D0_REAL_CBMC", "")
    capture_dir = os.environ.get("D0_CAPTURE_DIR", "")
    if not real_binary or not capture_dir:
        print("capture_cbmc: D0_REAL_CBMC and D0_CAPTURE_DIR are required", file=sys.stderr)
        return 127
    try:
        exit_code, _ = run_capture(sys.argv[1:], real_binary, capture_dir, sys.stdout.buffer,
                                   invoked_as=Path(sys.argv[0]).name)
    except (OSError, RuntimeError) as error:
        print(f"capture_cbmc: {error}", file=sys.stderr)
        return 127
    reraised_signal = FORWARDED_SIGNAL if FORWARDED_SIGNAL is not None else (-exit_code if exit_code < 0 else None)
    if reraised_signal is not None:
        if reraised_signal not in (signal.SIGKILL, signal.SIGSTOP):
            signal.signal(reraised_signal, signal.SIG_DFL)
        os.kill(os.getpid(), reraised_signal)
        return 128 + reraised_signal
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
