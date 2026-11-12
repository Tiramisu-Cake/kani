#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""CI-only launcher beside the built compiler; record the actual child's wait status."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import uuid

from capture_cbmc import _set_linux_parent_death_signal


def main():
    launcher = Path(sys.argv[0]).absolute()
    real = launcher.with_name("kani-compiler.d0-real")
    directory = Path(os.environ["D0_CAPTURE_DIR"]).parent / "compiler-process"
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / (uuid.uuid4().hex + ".json")
    record = {"argv": sys.argv, "state": "RUNNING", "exit": None, "signal": None,
              "is_compile": "--kani-compiler" in sys.argv, "pid": None}
    path.write_text(json.dumps(record))
    parent = os.getpid()
    child = subprocess.Popen([str(launcher), *sys.argv[1:]], executable=str(real),
                             preexec_fn=lambda: _set_linux_parent_death_signal(parent))
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, lambda number, frame: child.send_signal(number))
    code = child.wait()
    record.update(state="COMPLETE", pid=child.pid, exit=code if code >= 0 else None,
                  signal=-code if code < 0 else None)
    path.write_text(json.dumps(record, indent=2) + "\n")
    if code < 0:
        signal.signal(-code, signal.SIG_DFL)
        os.kill(os.getpid(), -code)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
