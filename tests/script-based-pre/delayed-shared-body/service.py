# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Collect native process status and bounded diagnostics."""
import hashlib
import os
import re
import signal
import subprocess
import tempfile
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


def execute(argv, cwd, timeout, env=None):
    started = time.monotonic()
    child_env = os.environ.copy()
    for key, value in (env or {}).items():
        if value is None:
            child_env.pop(key, None)
        else:
            child_env[key] = value
    record = {"argv": argv, "cwd": str(cwd), "timeout_seconds": timeout,
              "exit": None, "termination": "NOT_RUN",
              "environment": {name: child_env.get(name) for name in (
                  "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "KANIFLAGS", "KANI_LOG",
                  "RUST_BACKTRACE", "NO_COLOR", "KANI_FAIL_ON_UNEXPECTED_DESCRIPTION", "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "PATH")}}
    with tempfile.TemporaryFile() as log, tempfile.TemporaryFile() as errors:
        try:
            proc = subprocess.Popen(argv, cwd=cwd, stdout=log, stderr=errors,
                                    start_new_session=True, env=child_env)
            try:
                record["exit"] = proc.wait(timeout=timeout)
                record["termination"] = "EXITED"
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                record["exit"] = proc.wait()
                record["termination"] = "TIMEOUT"
        except OSError as error:
            record["termination"] = "SPAWN_ERROR"
            record["error"] = str(error)
        digest = hashlib.sha256()
        size = 0
        excerpts = []
        for stream, label in ((log, "stdout"), (errors, "stderr")):
            stream.seek(0)
            head, tail, stream_size = b"", b"", 0
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
                size += len(chunk)
                stream_size += len(chunk)
                head = (head + chunk)[:4096]
                tail = (tail + chunk)[-8192:]
            if label == "stderr":
                record["stderr_first_lines"] = [line[:500] for line in head.decode(errors="replace").splitlines()[:18]]
            excerpt = (head if stream_size <= 4096 else
                       head + b"\n[output excerpt]\n" + tail)
            excerpts.append(label + ":\n" + excerpt.decode(errors="replace"))
        record.update(output_bytes=size, output_sha256=digest.hexdigest())
        log.seek(0)
        stdout = log.read(2 * 1024 * 1024 + 1)
        record["stdout_inventory_complete"] = len(stdout) <= 2 * 1024 * 1024
        record["property_inventory"] = regular_inventory(stdout.decode(errors="replace")) if record["stdout_inventory_complete"] else {}
        record["stderr_tail"] = [line[:500] for line in tail.decode(errors="replace").splitlines()[-8:]]
    record["signal"] = -record["exit"] if isinstance(record["exit"], int) and record["exit"] < 0 else None
    record["elapsed_seconds"] = round(time.monotonic() - started, 3)
    record["output_excerpt"] = "\n".join(excerpts)
    return record
