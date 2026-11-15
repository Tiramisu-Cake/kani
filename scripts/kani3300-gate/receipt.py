#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Bounded, source-side observer for the unchanged Kani regression script."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone

MARK = b"\x1eKANI_GATE\0"
OUTPUT_CAP = 256 * 1024 * 1024
METADATA_CAP = 16 * 1024 * 1024
GRACE_SECONDS = 10
FROZEN_SHA = "ad499e41dd2db9ccd432f89721638a1f3a0bbd44"
FROZEN_TREE = "9829702c1aa0ecb73c860fc0ad5451757917d6cb"

STAGES = [
    "cbmc", "kissat", "fmt", "build-dev",
    "unit:cprover_bindings", "unit:kani-compiler", "unit:kani-driver",
    "unit:kani_metadata", "unit:compiletest", "unit:kani-cov",
    "unit:kani", "unit:kani_macros", "compiletest-config", "build-cov",
    "suite:kani", "suite:expected", "suite:ui", "suite:std-checks",
    "suite:firecracker", "suite:prusti", "suite:smack", "suite:cargo-kani",
    "suite:cargo-ui", "suite:script-based-pre", "suite:coverage",
    "suite:cargo-coverage", "suite:kani-docs", "suite:kani-fixme",
    "suite:json-handler", "firecracker-codegen", "cargo-smoke", "cargo-clean",
    "warnings-build",
]
UNIT_PACKAGES = [x.split(":", 1)[1] for x in STAGES if x.startswith("unit:")]
SUITES = [x.split(":", 1)[1] for x in STAGES if x.startswith("suite:")]

HOOK = r'''__kani_gate_pid=${BASHPID:-$$}
# Bash 3.2 (macOS) reports $0 as "bash" while reading BASH_ENV, so the top-level shell is
# identified only by the owner variable: the observer starts the regression shell directly.
if [[ -z ${KANI_GATE_OWNER_PID-} ]]; then
  export KANI_GATE_OWNER_PID=$__kani_gate_pid
  trap 'printf '\''\036KANI_GATE\000%s\000%s\000%s\000%s\000%s\000%s\000%s\000%s\000%s\000'\'' DEBUG "$?" "${BASH_SOURCE[0]}" "$LINENO" "$BASH_COMMAND" "${suite-}" "${mode-}" "$SECONDS" "${BASHPID:-$$}"' DEBUG
  trap 'printf '\''\036KANI_GATE\000%s\000%s\000%s\000%s\000%s\000%s\000%s\000%s\000%s\000'\'' EXIT "$?" "${BASH_SOURCE[0]}" "$LINENO" "$BASH_COMMAND" "${suite-}" "${mode-}" "$SECONDS" "${BASHPID:-$$}"' EXIT
fi
'''


def utc_now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_json_bounded(path, limit=METADATA_CAP):
    size = os.path.getsize(path)
    if size > limit:
        raise ValueError("metadata exceeds 16 MiB cap")
    with open(path, "rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("metadata exceeds 16 MiB cap")
    return json.loads(raw.decode("utf-8"))


def validate_observer_binding(binding):
    """Validate only the observer contract; lifecycle owns source preflight."""
    if not isinstance(binding, dict):
        raise ValueError("binding must be a JSON object")
    for key in ("export_sha", "export_tree"):
        if not isinstance(binding.get(key), str) or not re.fullmatch(r"[0-9a-f]{40}", binding[key]):
            raise ValueError("invalid " + key)
    if binding["export_sha"] != FROZEN_SHA or binding["export_tree"] != FROZEN_TREE:
        raise ValueError("binding does not identify the frozen C2 export")
    if binding.get("schema") != "kani3300-gate-binding-v2" or binding.get("state") != "C2_FROZEN":
        raise ValueError("binding schema/state is not C2_FROZEN v2")
    for key in ("files", "subtrees", "submodule_pins"):
        if key in binding and not isinstance(binding[key], dict):
            raise ValueError("invalid " + key)
    for value in binding.get("files", {}).values():
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("invalid file SHA-256")
    for key in ("subtrees", "submodule_pins"):
        for value in binding.get(key, {}).values():
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
                raise ValueError("invalid " + key + " identity")
    stages = binding.get("stages")
    if not isinstance(stages, list) or len(stages) != 33:
        raise ValueError("binding must contain exactly 33 ordered stages")
    ids = []
    for stage in stages:
        if not isinstance(stage, dict) or not isinstance(stage.get("id"), str):
            raise ValueError("invalid stage entry")
        if not isinstance(stage.get("line"), int) or stage["line"] <= 0:
            raise ValueError("invalid stage line: " + stage.get("id", "?"))
        if not isinstance(stage.get("command"), str) or not isinstance(stage.get("mode"), str):
            raise ValueError("invalid stage command/mode: " + stage.get("id", "?"))
        if not isinstance(stage.get("counts_required"), bool):
            raise ValueError("invalid counts_required: " + stage.get("id", "?"))
        ids.append(stage["id"])
    if ids != STAGES:
        raise ValueError("binding stage ids/order do not match frozen 33-stage contract")
    return binding


def identify(command, suite, mode):
    cmd = " ".join(command.split())
    if "check-cbmc-version.py" in cmd:
        return "cbmc"
    if "check_kissat_version.sh" in cmd:
        return "kissat"
    if "kani-fmt.sh" in cmd:
        return "fmt"
    if cmd.startswith("cargo build-dev"):
        return "build-dev"
    if "cargo test -p " in cmd:
        package = cmd.split("cargo test -p ", 1)[1].split()[0]
        return "unit:" + package
    if "cargo run -p compiletest" in cmd:
        if "--dry-run" in cmd:
            return "compiletest-config"
        return "suite:" + suite if suite else None
    if cmd == "cargo build -p kani-cov":
        return "build-cov"
    if "codegen-firecracker.sh" in cmd:
        return "firecracker-codegen"
    if cmd.startswith("cargo kani --manifest-path"):
        return "cargo-smoke"
    if cmd.startswith("cargo clean --manifest-path"):
        return "cargo-clean"
    if 'RUSTFLAGS="-D warnings" cargo build' in cmd:
        return "warnings-build"
    return None


def _summary_counts(output):
    lines = re.findall(r"(?m)^.*test result:.*$", output)
    result = []
    overflow = len(lines) > 20 or any(len(line.encode("utf-8", "replace")) > 4096 for line in lines)
    for line in lines[:20]:
        bounded = line.encode("utf-8", "replace")[:4096].decode("utf-8", "replace")
        counts = {key: None for key in ("passed", "failed", "ignored", "filtered")}
        for number, label in re.findall(r"(\d+) (passed|failed|ignored|measured|filtered out)", line):
            if label == "measured":
                continue
            counts["filtered" if label == "filtered out" else label] = int(number)
        result.append({"line": bounded, "counts": counts})
    return result, overflow


def summarize(data, returncode, termination=None, truncated=False, binding=None):
    rows = {name: {"status": "NOT_RUN", "exit": None, "counts": []} for name in STAGES}
    problems, seen, pending = [], [], None
    event_count = 0
    exit_events = []
    event_pids = set()
    after_exit = False
    pos = 0
    while True:
        start = data.find(MARK, pos)
        if start < 0:
            break
        fields, cursor = [], start + len(MARK)
        for _ in range(9):
            end = data.find(b"\0", cursor)
            if end < 0:
                problems.append("partial-event")
                break
            fields.append(data[cursor:end].decode("utf-8", "replace"))
            cursor = end + 1
        if len(fields) != 9:
            break
        event_count += 1
        kind, rc_text, source, line, command, suite, mode, elapsed, event_pid = fields
        is_top = source == "scripts/kani-regression.sh" or source.endswith("/scripts/kani-regression.sh")
        if not is_top:
            pos = cursor
            continue
        if event_pid.isdecimal():
            event_pids.add(int(event_pid))
        else:
            problems.append("invalid-event-pid")
        if kind not in ("DEBUG", "EXIT") or not re.fullmatch(r"-?[0-9]+", rc_text):
            problems.append("invalid-event")
            pos = cursor
            continue
        rc = int(rc_text)
        if after_exit:
            problems.append("event-after-exit")
        if kind == "EXIT":
            exit_events.append({"rc": rc, "source": source, "line": line,
                                "command": command, "elapsed_seconds": int(elapsed) if elapsed.isdecimal() else None,
                                "pid": int(event_pid) if event_pid.isdecimal() else None})
            after_exit = True
        if pending:
            name, output_start = pending
            text_out = data[output_start:start].decode("utf-8", "replace")
            counts, overflow = _summary_counts(text_out)
            stage_binding = next((x for x in (binding or {}).get("stages", []) if x.get("id") == name), {})
            rows[name].update(status="EXIT_ZERO" if rc == 0 else "FAILED", exit=rc, counts=counts)
            rows[name]["ended_offset_seconds"] = int(elapsed) if elapsed.isdecimal() else None
            started = rows[name].get("started_offset_seconds")
            if started is not None and elapsed.isdecimal():
                rows[name]["duration_seconds"] = max(0, int(elapsed) - started)
            rows[name]["counts_required"] = stage_binding.get("counts_required", name.startswith(("suite:", "unit:")))
            if stage_binding:
                expected_command = " ".join(stage_binding["command"].split())
                observed_command = " ".join(rows[name].get("command", "").split())
                if observed_command.startswith("time "):
                    observed_command = observed_command[5:]
                if observed_command != expected_command:
                    problems.append(name + ":command-mismatch")
                if rows[name].get("source_line") != stage_binding["line"]:
                    problems.append(name + ":source-line-mismatch")
                if name.startswith("suite:") and rows[name].get("mode", "") != stage_binding["mode"]:
                    problems.append(name + ":mode-mismatch")
            if overflow:
                problems.append(name + ":summary-overflow")
            if rows[name]["counts_required"] and not counts:
                problems.append(name + ":counts-missing")
            if rows[name]["counts_required"] and counts:
                for item in counts:
                    if any(item["counts"][key] is None for key in ("passed", "failed", "ignored", "filtered")):
                        problems.append(name + ":counts-incomplete")
            if any((item["counts"].get("failed") or 0) > 0 or "FAILED" in item["line"] for item in counts):
                problems.append(name + ":failed-count")
            if any((item["counts"].get("filtered") or 0) > 0 for item in counts):
                problems.append(name + ":filtered-count-nonzero")
            if rc != 0:
                rows[name]["failure_kind"] = "UNEXPECTED_TEST_OR_ORACLE_FAILURE" if counts else "UNCLASSIFIED_TEST_OR_INFRA_FAILURE"
                rows[name]["bounded_failure_tail"] = text_out[-4096:].splitlines()[-12:]
            pending = None
        if kind == "DEBUG":
            name = identify(command, suite, mode)
            if name:
                if name not in rows or name in seen:
                    problems.append("unexpected-or-duplicate-stage:" + name)
                else:
                    seen.append(name)
                    rows[name].update(status="INCOMPLETE", command=command[:4096], source_line=int(line) if line.isdecimal() else None,
                                      mode=mode if name.startswith("suite:") else "",
                                      observed_mode=mode)
                    rows[name]["started_offset_seconds"] = int(elapsed) if elapsed.isdecimal() else None
                    pending = (name, cursor)
        pos = cursor
    if pending:
        rows[pending[0]]["status"] = "INCOMPLETE"
    if seen != STAGES:
        problems.append("stage-order-or-presence")
    if len(exit_events) != 1:
        problems.append("exit-trace-count")
    elif exit_events[0]["rc"] != returncode:
        problems.append("exit-trace-status-mismatch")
    elif not after_exit:
        problems.append("exit-trace-missing")
    if not exit_events:
        problems.append("exit-trace-missing")
    if len(event_pids) != 1:
        problems.append("event-pid-inconsistent")
    if truncated:
        problems.append("output-cap-truncated")
    if termination:
        problems.append("process-terminated:" + str(termination.get("kind", "UNKNOWN")))
    if returncode != 0:
        problems.append("script-exit-nonzero")
    complete = (returncode == 0 and not termination and not truncated and not problems
                and all(row["status"] == "EXIT_ZERO" for row in rows.values()))
    exit_signal = -returncode if isinstance(returncode, int) and returncode < 0 else None
    try:
        exit_signal_name = signal.Signals(exit_signal).name if exit_signal is not None else None
    except ValueError:
        exit_signal_name = "SIG" + str(exit_signal) if exit_signal is not None else None
    return {
        "schema": "kani3300-gatea-observer-v1",
        "status": "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW" if complete else "INCOMPLETE_OR_FAILED",
        "formal_proof_credit": "NOT_ESTABLISHED",
        "script_exit": returncode,
        "script_exit_kind": "SIGNAL" if exit_signal is not None else "EXIT",
        "script_exit_signal": exit_signal,
        "script_exit_signal_name": exit_signal_name,
        "termination": termination,
        "problems": problems,
        "stage_order_seen": seen,
        "event_count": event_count,
        "exit_trace": exit_events,
        "event_complete": not truncated and "partial-event" not in problems and len(exit_events) == 1 and len(event_pids) == 1 and not any(p in problems for p in ("event-after-exit", "exit-trace-status-mismatch", "event-pid-inconsistent")),
        "stages": rows,
    }


def _kill_group(proc, sig):
    try:
        os.killpg(proc.pid, sig)
    except (AttributeError, ProcessLookupError, PermissionError):
        try:
            proc.send_signal(sig)
        except ProcessLookupError:
            pass


def _group_exists(proc):
    try:
        os.killpg(proc.pid, 0)
        return True
    except (AttributeError, ProcessLookupError, PermissionError):
        return False


def _stop_process(proc, kind, signum=None, grace_seconds=GRACE_SECONDS):
    _kill_group(proc, signal.SIGTERM)
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        proc.poll()
        if not _group_exists(proc):
            break
        time.sleep(0.05)
    if _group_exists(proc):
        _kill_group(proc, signal.SIGKILL)
    proc.wait()
    info = {"kind": kind}
    if signum is not None:
        info["signal"] = signum
        try:
            info["signal_name"] = signal.Signals(signum).name
        except ValueError:
            info["signal_name"] = "SIG" + str(signum)
    return info


def capture_process(argv, cwd, env, timeout_seconds, raw_path, output_cap=OUTPUT_CAP,
                    install_signal_handlers=False, grace_seconds=GRACE_SECONDS):
    """Run an isolated process group and retain only bounded combined output."""
    raw_path = Path(raw_path)
    raw_path.touch(exist_ok=False)
    overflow = threading.Event()
    bytes_written = [0]
    reader_errors = []

    def drain(pipe):
        try:
            with raw_path.open("ab") as stream:
                while True:
                    chunk = pipe.read(65536)
                    if not chunk:
                        break
                    room = output_cap - bytes_written[0]
                    if room > 0:
                        part = chunk[:room]
                        stream.write(part)
                        bytes_written[0] += len(part)
                        stream.flush()
                    if len(chunk) > room:
                        overflow.set()
        except Exception as exc:
            reader_errors.append(type(exc).__name__ + ": " + str(exc))

    child = subprocess.Popen(argv, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             env=env, start_new_session=True, bufsize=0)
    reader = threading.Thread(target=drain, args=(child.stdout,), daemon=True)
    reader.start()
    requested_signal = []
    old_handlers = {}
    if install_signal_handlers:
        for sig in (signal.SIGTERM, signal.SIGINT):
            old_handlers[sig] = signal.signal(sig, lambda s, _f: requested_signal.append(s))
    deadline = time.monotonic() + timeout_seconds
    termination = None
    try:
        while child.poll() is None or reader.is_alive():
            if requested_signal:
                termination = _stop_process(child, "PARENT_SIGNAL", requested_signal[0], grace_seconds)
                break
            if overflow.is_set():
                termination = _stop_process(child, "OUTPUT_CAP", grace_seconds=grace_seconds)
                break
            if time.monotonic() >= deadline:
                termination = _stop_process(child, "TIMEOUT", grace_seconds=grace_seconds)
                break
            time.sleep(0.025)
        if child.poll() is None:
            child.wait()
        reader.join(timeout=grace_seconds + 2)
        if reader.is_alive():
            termination = termination or {"kind": "OBSERVER_READER_STUCK"}
            _kill_group(child, signal.SIGKILL)
            child.stdout.close()
            reader.join(timeout=1)
        elif child.stdout:
            child.stdout.close()
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    size = os.path.getsize(raw_path)
    truncated = overflow.is_set() or size > output_cap
    return {"process": child, "returncode": child.returncode, "termination": termination,
            "bytes": size, "truncated": truncated, "reader_errors": reader_errors,
            "raw_path": raw_path}


def run_child(binding_path, output_dir, timeout_seconds):
    start = utc_now()
    monotonic_start = time.monotonic()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = output_dir / "receipt.json"
    report = {"schema": "kani3300-gatea-observer-v1", "status": "INCOMPLETE_OBSERVER_STARTING",
              "formal_proof_credit": "NOT_ESTABLISHED", "script_exit": None,
              "termination": None, "problems": ["observer-process-not-yet-started"], "timestamps": {"started_utc": start},
              "timeout_seconds": timeout_seconds, "output_cap_bytes": OUTPUT_CAP,
              "metadata_cap_bytes": METADATA_CAP, "argv": ["bash", "scripts/kani-regression.sh"],
              "combined_output_file": "regression.events.log",
              "effective_environment_policy": {
                  "KANI_REGRESSION_KEEP_GOING": "forced empty string",
                  "KANI_REGRESSION_TEST_TIMEOUT": "forced 2400 seconds",
                  "RUST_TEST_THREADS": "unset; inherited value rejected",
                  "external_overrides_rejected": ["RUSTFLAGS", "KANI_FLAGS", "CBMC_FLAGS", "EXTRA_X_PY_BUILD_ARGS", "BASH_ENV", "SHELLOPTS", "BASHOPTS", "KANI_GATE_OWNER_PID", "KANI_REGRESSION_TEST_TIMEOUT", "RUST_TEST_THREADS", "nonempty KANI_REGRESSION_KEEP_GOING"],
                  "RUSTFLAGS": "frozen script-scoped assignments only",
              },
              "full_verifier_argv": "UNKNOWN_NOT_OBSERVED"}
    try:
        _reserve_report(receipt_path, report)
    except FileExistsError:
        print("observer error: receipt already exists; preserving prior partial receipt", file=sys.stderr)
        return 2
    child = None
    try:
        if timeout_seconds <= 0 or timeout_seconds > 20400:
            raise ValueError("timeout must be in 1..20400 seconds")
        binding = validate_observer_binding(read_json_bounded(binding_path))
        report["binding_identity"] = {"export_sha": binding["export_sha"], "export_tree": binding["export_tree"]}
        if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_REPOSITORY") != "Tiramisu-Cake/kani":
            raise ValueError("regression execution is allowed only in the canonical GitHub Actions repository")
        forbidden = [key for key in ("RUSTFLAGS", "KANI_FLAGS", "CBMC_FLAGS", "EXTRA_X_PY_BUILD_ARGS",
                                     "BASH_ENV", "SHELLOPTS", "BASHOPTS", "KANI_GATE_OWNER_PID",
                                     "KANI_REGRESSION_TEST_TIMEOUT") if os.environ.get(key)]
        if "RUST_TEST_THREADS" in os.environ:
            forbidden.append("RUST_TEST_THREADS")
        if os.environ.get("KANI_REGRESSION_KEEP_GOING"):
            forbidden.append("KANI_REGRESSION_KEEP_GOING")
        if forbidden:
            raise ValueError("unexpected environment override(s): " + ", ".join(forbidden))
        hook = output_dir / "observe.bash"
        hook.write_text(HOOK, encoding="utf-8")
        hook.chmod(0o600)
        env = dict(os.environ)
        env.pop("RUST_TEST_THREADS", None)
        env.update({"BASH_ENV": str(hook), "KANI_REGRESSION_KEEP_GOING": "", "KANI_REGRESSION_TEST_TIMEOUT": "2400"})
        raw_path = output_dir / "regression.events.log"
        captured = capture_process(["bash", "scripts/kani-regression.sh"], Path.cwd(), env,
                                   timeout_seconds, raw_path, OUTPUT_CAP, True)
        child = captured["process"]
        termination = captured["termination"]
        reader_errors = captured["reader_errors"]
        raw_size = captured["bytes"]
        truncated = captured["truncated"]
        with raw_path.open("rb") as stream:
            data = stream.read(OUTPUT_CAP + 1)
        if len(data) > OUTPUT_CAP:
            data = data[:OUTPUT_CAP]
            truncated = True
        result = summarize(data, child.returncode, termination, truncated, binding)
        result.update({"binding_identity": report["binding_identity"], "argv": report["argv"],
                       "timeout_seconds": timeout_seconds, "output_cap_bytes": OUTPUT_CAP,
                       "metadata_cap_bytes": METADATA_CAP, "combined_output_file": raw_path.name,
                       "timestamps": {"started_utc": start, "ended_utc": utc_now()},
                       "event_stream": {"bytes": raw_size, "sha256": _hash_file(raw_path),
                                        "complete": result["event_complete"], "truncated": truncated},
                       "observer_errors": reader_errors})
        result["effective_environment_policy"] = report["effective_environment_policy"]
        result["full_verifier_argv"] = report["full_verifier_argv"]
        result["duration_seconds"] = time.monotonic() - monotonic_start
        if reader_errors:
            result["status"] = "INCOMPLETE_OR_FAILED"
            result["problems"].append("observer-reader-error")
        report = result
        return child.returncode if child.returncode not in (None, 0) else (0 if result["status"] == "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW" else 1)
    except Exception as exc:
        report.update(status="NOT_RUN" if child is None else "INCOMPLETE_OR_FAILED",
                      error=type(exc).__name__ + ": " + str(exc),
                      script_exit=child.returncode if child is not None else None,
                      timestamps={"started_utc": start, "ended_utc": utc_now()})
        report["duration_seconds"] = time.monotonic() - monotonic_start
        return 2
    finally:
        report.setdefault("timestamps", {})["ended_utc"] = report.get("timestamps", {}).get("ended_utc", utc_now())
        _write_json_bounded(receipt_path, report)


def _hash_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_bounded(path, value):
    data = _serialize_bounded(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("wb") as stream:
        stream.write(data)
    os.replace(str(tmp), str(path))


def _serialize_bounded(value):
    data = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(data) > METADATA_CAP:
        fallback = {"schema": "kani3300-gatea-observer-v1", "status": "INCOMPLETE_OR_FAILED",
                    "formal_proof_credit": "NOT_ESTABLISHED", "error": "receipt metadata exceeded 16 MiB"}
        data = (json.dumps(fallback, indent=2) + "\n").encode("utf-8")

    return data


def _reserve_report(path, value):
    """Install a valid non-success receipt exclusively and flush it to disk."""
    data = _serialize_bounded(value)
    descriptor, temp_name = tempfile.mkstemp(prefix=path.name + ".reserve-", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # A hard link installs the fully written file atomically and fails if a
        # prior partial receipt already occupies the destination.
        os.link(temp_name, str(path))
        try:
            directory_fd = os.open(str(path.parent), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def self_test():
    """Exercise the real BASH_ENV event hook against a synthetic shell only."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="kani-gatea-selftest-") as temp:
        root = Path(temp)
        (root / "scripts").mkdir()
        script = root / "scripts/kani-regression.sh"
        script.write_text("#!/usr/bin/env bash\nif [[ ${1-} == child ]]; then printf 'child body\\n'; exit 0; fi\nset -e\nprintf 'synthetic start\\n'\nbash scripts/kani-regression.sh child\nfalse_stage() { return 7; }\nif [[ ${SELFTEST_FAIL-} == 1 ]]; then false_stage; fi\nprintf 'test result: ok. 2 passed; 0 failed; 0 ignored; 0 filtered out\\n'\n", encoding="utf-8")
        hook = root / "observe.bash"
        hook.write_text(HOOK, encoding="utf-8")
        env = dict(os.environ, BASH_ENV=str(hook))
        success = subprocess.run(["bash", "scripts/kani-regression.sh"], cwd=str(root), env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        if success.returncode != 0:
            raise RuntimeError("synthetic success shell failed")
        event_list = _decode_events(success.stdout)
        if len(event_list) < 3 or b"child body" not in success.stdout:
            raise RuntimeError("synthetic success/child shell event observation failed")
        failure_env = dict(env, SELFTEST_FAIL="1")
        failure = subprocess.run(["bash", "scripts/kani-regression.sh"], cwd=str(root), env=failure_env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        failure_events = _decode_events(failure.stdout)
        if failure.returncode != 7 or not failure_events or failure_events[-1][0] != "EXIT" or int(failure_events[-1][1]) != 7:
            raise RuntimeError("synthetic original failure status/EXIT observation failed")
        exits = [item for item in event_list if item[0] == "EXIT"]
        if len(exits) != 1 or exits[0][1] != "0":
            raise RuntimeError("synthetic success EXIT status missing/mismatched")
        command_events = [item for item in event_list if item[4] == "printf 'synthetic start\\n'"]
        if len(command_events) != 1 or command_events[0][2] != "scripts/kani-regression.sh" or command_events[0][3] != "4":
            raise RuntimeError("synthetic source/line/BASH_COMMAND capture failed")
        nested_invokes = [item for item in event_list if item[4] == "bash scripts/kani-regression.sh child"]
        event_pids = {item[8] for item in event_list}
        if len(nested_invokes) != 1 or len(event_pids) != 1:
            raise RuntimeError("nested shell unexpectedly emitted observer events")
        ordered = [m.start() for m in re.finditer(re.escape(MARK), success.stdout)]
        if ordered != sorted(ordered) or success.stdout.rfind(MARK) < 0:
            raise RuntimeError("synthetic event ordering failed")
    return {"status": "PASS", "coverage": ["success", "failure", "EXIT", "order", "child-not-instrumented"]}


def _decode_events(data):
    events = []
    pos = 0
    while True:
        start = data.find(MARK, pos)
        if start < 0:
            return events
        fields = []
        cursor = start + len(MARK)
        for _ in range(9):
            end = data.find(b"\0", cursor)
            if end < 0:
                return events
            fields.append(data[cursor:end].decode("utf-8", "replace"))
            cursor = end + 1
        events.append(fields)
        pos = cursor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    run = sub.add_parser("run")
    run.add_argument("--binding", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--timeout", required=True, type=int)
    parse = sub.add_parser("parse")
    parse.add_argument("--binding", required=True)
    parse.add_argument("--events", required=True)
    parse.add_argument("--output", required=True)
    parse.add_argument("--script-exit", required=True, type=int)
    parse.add_argument("--termination-kind")
    parse.add_argument("--truncated", action="store_true")
    sub.add_parser("self-test")
    args = parser.parse_args()
    if args.action == "run":
        return run_child(args.binding, args.output, args.timeout)
    if args.action == "self-test":
        print(json.dumps(self_test(), sort_keys=True))
        return 0
    binding = validate_observer_binding(read_json_bounded(args.binding))
    event_path = Path(args.events)
    if event_path.stat().st_size > OUTPUT_CAP:
        raise ValueError("event stream exceeds 256 MiB cap")
    data = event_path.read_bytes()
    termination = {"kind": args.termination_kind} if args.termination_kind else None
    result = summarize(data, args.script_exit, termination, args.truncated, binding)
    result["event_stream"] = {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                              "complete": result["event_complete"], "truncated": args.truncated}
    _write_json_bounded(Path(args.output), result)
    return 0 if result["status"] == "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        print("observer error: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        sys.exit(2)
