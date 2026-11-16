#!/usr/bin/env python3
"""Offline, bounded CI runner for the frozen Challenge 8 C controls request.

Receipts are observations only. They never grant proof credit. This module is
also deliberately usable with synthetic fixtures; it does not install tools.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Any

HERE = Path(__file__).resolve().parent
REQUEST_PATH = HERE / "CI-REQUEST.json"
STD_SHA = "597e54c5cb503955f9483edc6acc9d4752d57713"
STD_TREE = "b3bd6d8c939e08b13fc7a4c6c9da694cc8a2aa97"
TOOL_SHA = "0aac16ef62da9e9d5645782d458593e5d78143ba"
TOOL_TREE = "9d8bc9312bf955ef126d32b819b3cd0ed105ed2b"
MAX_ROW_SECONDS = 600
PHASE_SECONDS = 6720
PHASE_CLEANUP_MARGIN = 10
STD_COMPILE_SECONDS = 900
RUN_STEP_SECONDS = 6720
JOB_SECONDS = 9000
RSS_CAP_KIB = 6 * 1024 * 1024
STDOUT_CAP_BYTES = 1024 * 1024
STDERR_CAP_BYTES = 1024 * 1024
EXPORT_CAP_BYTES = 8 * 1024 * 1024
ARTIFACT_CAP_BYTES = 256 * 1024 * 1024
UNSTABLE = ("function-contracts", "mem-predicates", "float-lib", "c-ffi",
            "loop-contracts", "quantifiers", "stubbing")


class RunnerError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def git(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=True, text=True)
    return p.stdout.strip()


def load_request(path: Path = REQUEST_PATH) -> dict[str, Any]:
    try:
        request = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot read CI request: {exc}") from exc
    expected = {
        "status": "READY", "std_sha": STD_SHA, "std_tree": STD_TREE,
        "tool_sha": TOOL_SHA, "tool_tree": TOOL_TREE,
    }
    for key, value in expected.items():
        if request.get(key) != value:
            raise RunnerError(f"request binding mismatch: {key}")
    rows = request.get("rows")
    if not isinstance(rows, list) or not rows:
        raise RunnerError("request rows must be a non-empty array")
    seen_ids: set[str] = set()
    seen_selectors: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise RunnerError("row is not an object")
        rid, selector = row.get("id"), row.get("selector")
        if not isinstance(rid, str) or not rid or rid in seen_ids:
            raise RunnerError("missing or duplicate row id")
        if not isinstance(selector, str) or not selector:
            raise RunnerError("missing exact selector")
        if selector in seen_selectors:
            raise RunnerError("duplicate row selector")
        seen_ids.add(rid)
        seen_selectors.add(selector)
        if row.get("mode") not in ("PFC", "Original"):
            raise RunnerError(f"invalid mode for {rid}")
        if row.get("variant") not in ("production",):
            raise RunnerError(f"invalid variant for {rid}")
        if not isinstance(row.get("unwind"), int) or row["unwind"] < 1:
            raise RunnerError(f"invalid unwind for {rid}")
        if row.get("expected") not in ("SUCCESS", "DETECTED", "ALIAS_GAP"):
            raise RunnerError(f"invalid expected result for {rid}")
        if row.get("variant") != "production":
            raise RunnerError(f"C controls require production source for {rid}")
        if not isinstance(row.get("target"), str) or not row["target"]:
            raise RunnerError(f"missing exact target for {rid}")
        cover_descriptions = row.get("required_cover_descriptions")
        if not isinstance(cover_descriptions, list) or any(not isinstance(x, str) or not x for x in cover_descriptions):
            raise RunnerError(f"invalid required cover description list for {rid}")
        if not isinstance(row.get("required_cover_count"), int) or row["required_cover_count"] < 0:
            raise RunnerError(f"invalid cover count for {rid}")
        timeout = row.get("timeout_seconds")
        if not isinstance(timeout, int) or not 1 <= timeout <= MAX_ROW_SECONDS:
            raise RunnerError(f"timeout outside 1..{MAX_ROW_SECONDS} for {rid}")
        if row["expected"] == "DETECTED":
            match = row.get("failure_match")
            if not isinstance(match, dict) or match.get("class") != "assigns":
                raise RunnerError(f"negative row requires the exact assigns class: {rid}")
            if not isinstance(match.get("description_regex"), str) or not match["description_regex"]:
                raise RunnerError(f"negative row lacks failure description matcher: {rid}")
            try:
                re.compile(match["description_regex"])
            except re.error as exc:
                raise RunnerError(f"invalid failure description matcher for {rid}: {exc}") from exc
            locations = match.get("locations")
            if not isinstance(locations, list) or not locations or any(
                    not isinstance(loc, dict) or not isinstance(loc.get("file"), str) or
                    not isinstance(loc.get("line"), str) or not loc["line"].isdigit() for loc in locations):
                raise RunnerError(f"negative row lacks exact source locations: {rid}")
    for key in ("changed_file_sha256", "variants"):
        if not isinstance(request.get(key), dict):
            raise RunnerError(f"missing request {key} object")
    flags = request.get("flags")
    if flags != {"cli": ["--no-assert-contracts", "--jobs=1", "--cbmc-args", "--object-bits", "12"],
                 "unstable_features": [*UNSTABLE, "export-json"],
                 "cfg": ["kani_smallsort_controls"], "sorting_cfg": False,
                 "assert_contracts": False, "uninit_checks": False,
                 "valid_value_checks": False, "jobs": 1, "attempt": 1,
                 "max_root_seconds": MAX_ROW_SECONDS}:
        raise RunnerError("organizer flag binding mismatch")
    budgets = request.get("budgets")
    if not isinstance(budgets, dict) or any(budgets.get(key) != val for key, val in {
            "phase_seconds": PHASE_SECONDS, "setup_seconds": 1800, "reserve_seconds": 300,
            "job_seconds": JOB_SECONDS, "run_step_seconds": RUN_STEP_SECONDS,
            "group_seconds": 2100,
            "rss_kib": RSS_CAP_KIB,
            "stdout_bytes": STDOUT_CAP_BYTES, "stderr_bytes": STDERR_CAP_BYTES,
            "export_bytes": EXPORT_CAP_BYTES, "artifact_bytes": ARTIFACT_CAP_BYTES,
            "row_seconds": MAX_ROW_SECONDS}.items()):
        raise RunnerError("request budget mismatch")
    expected_group_seconds = sum(sum(row["timeout_seconds"] for row in group) + STD_COMPILE_SECONDS
                                 for group in _group_rows(rows))
    if (expected_group_seconds != budgets["group_seconds"] or
            budgets["run_step_seconds"] < expected_group_seconds or
            budgets["setup_seconds"] + budgets["phase_seconds"] + budgets["reserve_seconds"] >
            budgets["job_seconds"]):
        raise RunnerError("request scheduling envelope does not cover the frozen batch groups")
    return request


def _source_root(std: Path, tool: Path) -> None:
    std, tool = std.resolve(), tool.resolve()
    if std == tool or std.parent != tool.parent:
        raise RunnerError("std and tool source checkouts must be sibling directories")
    control = HERE.resolve()
    if std == control or tool == control or control in std.parents or control in tool.parents:
        raise RunnerError("source checkout must remain outside CI control workspace")


def verify_source(std: Path, tool: Path, request: dict[str, Any]) -> dict[str, Any]:
    _source_root(std, tool)
    bindings = ((std, STD_SHA, STD_TREE, "std"), (tool, TOOL_SHA, TOOL_TREE, "tool"))
    for repo, wanted_sha, wanted_tree, label in bindings:
        if git(repo, "rev-parse", "HEAD") != wanted_sha:
            raise RunnerError(f"{label} HEAD drift")
        if git(repo, "rev-parse", "HEAD^{tree}") != wanted_tree:
            raise RunnerError(f"{label} tree drift")
        if git(repo, "cat-file", "-t", wanted_sha) != "commit":
            raise RunnerError(f"{label} pinned commit unavailable")
    for repo, label in ((std, "std"), (tool, "tool")):
        if git(repo, "status", "--porcelain=v1"):
            raise RunnerError(f"{label} production checkout is not clean")
    for rel, digest in request["changed_file_sha256"].items():
        if not isinstance(rel, str) or not isinstance(digest, str):
            raise RunnerError("changed_file_sha256 entries must be path/hash strings")
        path = (std / rel).resolve()
        if std.resolve() not in path.parents or not path.is_file() or sha256(path) != digest:
            raise RunnerError(f"std changed-file SHA drift: {rel}")
    if request.get("stage") == "C-02":
        _verify_c02_source(std, request)
    # Variants may describe test overlays; their path/hash are checked when selected.
    return {"std_sha": STD_SHA, "std_tree": STD_TREE, "tool_sha": TOOL_SHA,
            "tool_tree": TOOL_TREE, "changed_file_sha256": request["changed_file_sha256"]}


def _target_tokens(value: Any) -> tuple[str, ...] | None:
    """Frozen C-02 nongeneric Rust path; never join identifier fragments."""
    if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*(?:\s*::\s*[A-Za-z_][A-Za-z0-9_]*)*", value.strip()):
        return None
    return tuple(re.split(r"\s*::\s*", value.strip()))


def _verify_c02_source(std: Path, request: dict[str, Any]) -> None:
    """Check the exact pinned harness attributes and explicit parent import."""
    rel = "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs"
    source = (std / rel).read_text()
    if "use super::super::{bidirectional_merge, insert_tail, insertion_sort_shift_left};" not in source:
        raise RunnerError("C-02 parent helper import mismatch")
    for row in request["rows"]:
        pattern = (r"#\[kani::proof_for_contract\(([^)]+)\)\]\s*"
                   r"#\[kani::unwind\((\d+)\)\]\s*fn " + re.escape(row["id"]) + r"\(\)")
        matches = list(re.finditer(pattern, source))
        if len(matches) != 1:
            raise RunnerError("C-02 source harness attribute mismatch")
        match = matches[0]
        line = source[:match.end()].count("\n") + 1
        if (row.get("source_harness_file") != rel or row.get("source_harness_line") != line or
                _target_tokens(match[1]) != ("bidirectional_merge",) or
                _target_tokens(row.get("source_target_syntax")) != ("bidirectional_merge",) or
                row["target"] != "slice::sort::shared::smallsort::bidirectional_merge" or
                int(match[2]) != row["unwind"] or row["unwind"] != 17):
            raise RunnerError("C-02 source stage target/unwind mismatch")


def _variant_info(request: dict[str, Any], name: str) -> tuple[Path, str, dict[str, str]]:
    item = request["variants"].get(name)
    if not isinstance(item, dict):
        raise RunnerError(f"missing variant binding {name}")
    patch = item.get("patch")
    patch_sha = item.get("sha256")
    files = item.get("changed_file_sha256")
    if not isinstance(patch, str) or not isinstance(patch_sha, str) or not isinstance(files, dict):
        raise RunnerError(f"malformed variant binding {name}")
    path = (REQUEST_PATH.parent / patch).resolve()
    if REQUEST_PATH.parent.resolve() not in path.parents or not path.is_file() or sha256(path) != patch_sha:
        raise RunnerError(f"variant patch path/hash mismatch: {name}")
    return path, patch_sha, files


def build_argv(std: Path, tool: Path, selectors: str | list[str], unwind: int, export: Path,
               harness_timeout_seconds: int = MAX_ROW_SECONDS) -> list[str]:
    if isinstance(selectors, str):
        selectors = [selectors]
    if not selectors or len(set(selectors)) != len(selectors):
        raise RunnerError("batch selectors must be non-empty and unique")
    argv = [str((tool.resolve() / "scripts/kani")), "verify-std", "-Z", "unstable-options"]
    for feature in UNSTABLE:
        argv += ["-Z", feature]
    argv += ["--no-assert-contracts", "--jobs=1"]
    for selector in selectors:
        argv += ["--harness", selector]
    if not 1 <= harness_timeout_seconds <= MAX_ROW_SECONDS:
        raise RunnerError("harness timeout outside frozen row limit")
    argv += ["--exact", "--default-unwind", str(unwind), "--harness-timeout", f"{harness_timeout_seconds}s",
             "-Z", "export-json",
             "--export-json", str(export.resolve()), "--output-format=terse", str((std.resolve() / "library")),
             "--cbmc-args", "--object-bits", "12"]
    return argv


def ci_env() -> dict[str, str]:
    env = os.environ.copy()
    fixed = "--cfg=kani_smallsort_controls"
    inherited = env.get("RUSTFLAGS", "").strip()
    if inherited and inherited != fixed:
        raise RunnerError("refusing inherited RUSTFLAGS outside the frozen controls-only cfg")
    env["RUSTFLAGS"] = fixed
    return env


def _read_pipe(pipe, target: Path, tail_target: Path, cap: int,
               state: dict[str, Any], lock: threading.Lock, key: str) -> None:
    tail = bytearray()
    with target.open("wb") as output:
        while True:
            data = pipe.read(65536)
            if not data:
                break
            with lock:
                tail.extend(data)
                if len(tail) > 4096:
                    del tail[:-4096]
                state[key + "_tail"] = bytes(tail)
                room = max(0, cap - state[key + "_kept"])
                if len(data) > room:
                    state[key + "_cap"] = True
                state[key + "_kept"] += min(room, len(data))
                state[key + "_bytes"] += len(data)
                if room:
                    output.write(data[:room])
    pipe.close()
    tail_target.write_bytes(tail)


def _group_rss_kib(pgid: int) -> int:
    total = 0
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            tail = stat[stat.rfind(")") + 2:].split()
            if int(tail[2]) != pgid:
                continue
            for line in (entry / "status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    total += int(line.split()[1]); break
        except (OSError, ValueError, IndexError):
            continue
    return total


def _group_has_live_members(pgid: int) -> bool:
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            tail = stat[stat.rfind(")") + 2:].split()
            if int(tail[2]) == pgid and tail[0] != "Z":
                return True
        except (OSError, ValueError, IndexError):
            continue
    return False


def _kill_group(pgid: int, grace: float = 5.0) -> None:
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    end = time.monotonic() + grace
    while time.monotonic() < end:
        if not _group_has_live_members(pgid):
            return
        time.sleep(0.05)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def _force_kill_and_reap(proc: subprocess.Popen, grace: float = 5.0) -> tuple[int | None, list[str]]:
    """Emergency cleanup that does not depend on process-table sampling."""
    errors = []
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except Exception as exc:  # cleanup must continue even if group signaling fails
        errors.append(f"SIGTERM process group failed: {type(exc).__name__}: {exc}")
    try:
        code = proc.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception as exc:
            errors.append(f"SIGKILL process group failed: {type(exc).__name__}: {exc}")
        try:
            code = proc.wait()
        except Exception as exc:
            errors.append(f"child reap failed: {type(exc).__name__}: {exc}")
            code = proc.returncode
    except Exception as exc:
        errors.append(f"child wait failed: {type(exc).__name__}: {exc}")
        try:
            proc.kill()
            code = proc.wait()
        except Exception as reap_exc:
            errors.append(f"fallback child reap failed: {type(reap_exc).__name__}: {reap_exc}")
            code = proc.returncode
    # Kill remaining descendants that may have outlived the process-group leader.
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except Exception as exc:
        errors.append(f"final process-group kill failed: {type(exc).__name__}: {exc}")
    return code, errors


def _snapshot_compile_output(out: Path, state: dict[str, Any], lock: threading.Lock) -> dict[str, Any]:
    snapshots = {}
    with lock:
        for stream in ("stdout", "stderr"):
            head_path = out / f"{stream}.log"
            head = head_path.read_bytes()[:4096] if head_path.exists() else b""
            tail = state.get(stream + "_tail", b"")
            if not isinstance(tail, bytes):
                tail = bytes(tail)
            head_snapshot = out / f"compile-{stream}.head.log"
            tail_snapshot = out / f"compile-{stream}.tail.log"
            head_snapshot.write_bytes(head)
            tail_snapshot.write_bytes(tail[-4096:])
            snapshots[stream] = {"head_path": str(head_snapshot), "head_bytes": len(head),
                                 "tail_path": str(tail_snapshot), "tail_bytes": min(len(tail), 4096)}
    return snapshots


def execute(argv: list[str], cwd: Path, out: Path, timeout: int,
            rss_cap_kib: int = RSS_CAP_KIB, stdout_cap: int = STDOUT_CAP_BYTES,
            stderr_cap: int = STDERR_CAP_BYTES, export_path: Path | None = None,
            export_cap: int = EXPORT_CAP_BYTES, env: dict[str, str] | None = None,
            compile_marker: Path | None = None, compile_timeout: int = STD_COMPILE_SECONDS,
            compile_selectors: list[str] | None = None) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    info: dict[str, Any] = {"original_exit_code": None, "signal": None, "timed_out": False,
                            "rss_peak_kib": 0, "rss_status": "SAMPLED_PROCESS_GROUP",
                            "output_truncated": False, "output_bytes": 0}
    state: dict[str, Any] = {"stdout_cap": False, "stderr_cap": False,
                             "stdout_kept": 0, "stderr_kept": 0,
                             "stdout_bytes": 0, "stderr_bytes": 0,
                             "compile_complete": compile_marker is None}
    compile_started = started
    lock = threading.Lock()
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, bufsize=0)
    except OSError as exc:
        info.update(runner_error=f"exec failed: {exc}", elapsed_seconds=time.monotonic() - started)
        return info
    threads: list[threading.Thread] = []
    started_threads: list[threading.Thread] = []
    deadline = started + timeout
    killed_for = None
    external_signal: list[int] = []
    previous_handlers = {}
    cleanup_errors: list[str] = []
    monitor_error = None
    code = None

    def handle_external(signum, _frame):
        external_signal.append(signum)
        _kill_group(proc.pid)

    try:
        threads = [threading.Thread(target=_read_pipe, args=(proc.stdout, out / "stdout.log", out / "stdout.tail.log", stdout_cap,
                                                             state, lock, "stdout"), daemon=True),
                   threading.Thread(target=_read_pipe, args=(proc.stderr, out / "stderr.log", out / "stderr.tail.log", stderr_cap,
                                                             state, lock, "stderr"), daemon=True)]
        for thread in threads:
            thread.start()
            started_threads.append(thread)
        for sig in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[sig] = signal.getsignal(sig)
            signal.signal(sig, handle_external)
        try:
            while proc.poll() is None or any(thread.is_alive() for thread in started_threads):
                if compile_marker is not None and not state["compile_complete"]:
                    marker = _valid_compile_marker(compile_marker, compile_selectors or [])
                    if marker:
                        marker_sha = sha256(compile_marker)
                        snapshots = _snapshot_compile_output(out, state, lock)
                        state["compile_complete"] = True
                        info["std_compile_seconds"] = round(time.monotonic() - compile_started, 3)
                        info["std_compile_boundary"] = "PINNED_KANI_INCOMPLETE_EXPORT_MARKER"
                        state["compile_receipt"] = {"status": "COMPLETE", "cap_seconds": compile_timeout,
                            "elapsed_seconds": info["std_compile_seconds"],
                            "boundary": info["std_compile_boundary"],
                            "export_marker_sha256": marker_sha, "output_snapshots": snapshots}
                        _write_json(out / "compile-receipt.json", state["compile_receipt"])
                    elif time.monotonic() - compile_started >= compile_timeout:
                        killed_for = "std_compile_timeout"
                rss = _group_rss_kib(proc.pid)
                info["rss_peak_kib"] = max(info["rss_peak_kib"], rss)
                if rss > rss_cap_kib:
                    killed_for = "rss_cap"; break
                with lock:
                    if state["stdout_cap"] or state["stderr_cap"]:
                        killed_for = "stdout_cap" if state["stdout_cap"] else "stderr_cap"
                if export_path is not None:
                    try:
                        if export_path.exists() and export_path.stat().st_size > export_cap:
                            killed_for = "export_cap"
                    except OSError:
                        pass
                if killed_for:
                    break
                if time.monotonic() >= deadline:
                    killed_for = "timeout"; info["timed_out"] = True; break
                time.sleep(0.05)
        except Exception as exc:
            monitor_error = f"{type(exc).__name__}: {exc}"
            info["monitor_error"] = monitor_error
            info["termination_reason"] = "monitor_exception"
            code, cleanup = _force_kill_and_reap(proc)
            cleanup_errors.extend(cleanup)
        if monitor_error is None:
            if killed_for:
                info["termination_reason"] = killed_for
                _kill_group(proc.pid)
            try:
                code = proc.wait(timeout=7)
            except subprocess.TimeoutExpired:
                cleanup_code, cleanup = _force_kill_and_reap(proc, grace=0)
                cleanup_errors.extend(cleanup)
                code = cleanup_code
    except Exception as exc:
        monitor_error = monitor_error or f"{type(exc).__name__}: {exc}"
        info["monitor_error"] = monitor_error
        info["termination_reason"] = "monitor_exception"
        code, cleanup = _force_kill_and_reap(proc)
        cleanup_errors.extend(cleanup)
    finally:
        for sig, handler in previous_handlers.items():
            try:
                signal.signal(sig, handler)
            except Exception as exc:
                cleanup_errors.append(f"restore signal handler {sig} failed: {type(exc).__name__}: {exc}")
        if proc.poll() is None:
            cleanup_code, cleanup = _force_kill_and_reap(proc)
            cleanup_errors.extend(cleanup)
            if code is None:
                code = cleanup_code
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as exc:
                cleanup_errors.append(f"final process-group kill failed: {type(exc).__name__}: {exc}")
            code = proc.returncode
        for thread in started_threads:
            try:
                thread.join(timeout=2)
                if thread.is_alive():
                    cleanup_errors.append(f"pipe reader did not exit: {thread.name}")
            except Exception as exc:
                cleanup_errors.append(f"pipe reader join failed: {type(exc).__name__}: {exc}")
    if cleanup_errors:
        info["cleanup_errors"] = cleanup_errors
        info["termination_reason"] = info.get("termination_reason") or "process_group_cleanup_error"
    if compile_marker is not None and not state["compile_complete"]:
        info.setdefault("std_compile_seconds", round(time.monotonic() - compile_started, 3))
        info["std_compile_boundary"] = "NOT_REACHED"
        state["compile_receipt"] = {"status": "INCOMPLETE", "cap_seconds": compile_timeout,
            "elapsed_seconds": info["std_compile_seconds"], "boundary": "NOT_REACHED"}
    info["compile_receipt"] = state.get("compile_receipt", {
        "status": "COMPLETE", "cap_seconds": compile_timeout,
        "elapsed_seconds": None, "boundary": None})
    if compile_marker is not None:
        _write_json(out / "compile-receipt.json", info["compile_receipt"])
    info["original_exit_code"] = code
    if code is not None and code < 0:
        info["signal"] = -code
    if external_signal:
        info["interrupted_by_signal"] = external_signal[-1]
        if monitor_error is None:
            info["termination_reason"] = "external_signal"
    info["output_bytes"] = state["stdout_bytes"] + state["stderr_bytes"]
    info["stdout_truncated"] = state["stdout_cap"]
    info["stderr_truncated"] = state["stderr_cap"]
    info["rss_peak_gib"] = info["rss_peak_kib"] / 1048576
    info["rss_sample_period_seconds"] = 0.05
    if state["stdout_cap"] and not info.get("termination_reason"):
        info["termination_reason"] = "stdout_cap"
    elif state["stderr_cap"] and not info.get("termination_reason"):
        info["termination_reason"] = "stderr_cap"
    if export_path is not None and export_path.exists() and export_path.stat().st_size > export_cap:
        info["termination_reason"] = "export_cap"
    info["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return info


def _valid_compile_marker(path: Path, selectors: list[str]) -> bool:
    """The pinned tool creates this atomic marker after std compilation and target discovery."""
    try:
        if path.stat().st_size > EXPORT_CAP_BYTES:
            return False
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    selection = value.get("harness_selection") if isinstance(value, dict) else None
    timeout_s = value.get("harness_timeout_s") if isinstance(value, dict) else None
    return (isinstance(value, dict) and value.get("schema_version") == "0.1.0" and
            value.get("run_state") == "INCOMPLETE" and value.get("kani_commit") == TOOL_SHA and
            value.get("kani_commit_dirty") is False and value.get("target") == "x86_64-unknown-linux-gnu" and
            not isinstance(timeout_s, bool) and isinstance(timeout_s, (int, float)) and
            timeout_s == MAX_ROW_SECONDS and isinstance(selection, dict) and
            selection.get("requested_filters") == selectors and selection.get("exact") is True and
            selection.get("unmatched_filters") == [] and type(selection.get("matched_count")) is int and
            selection.get("matched_count") == len(selectors))


def parse_export(path: Path, row: dict[str, Any], max_bytes: int = EXPORT_CAP_BYTES,
                 expected_source_targets: dict[str, str] | None = None) -> dict[str, Any]:
    if not path.is_file():
        return {"state": "MISSING", "outcome": "UNKNOWN"}
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return {"state": "OVERSIZE", "size_bytes": size, "outcome": "UNKNOWN"}
        if size == 0:
            return {"state": "EMPTY", "outcome": "UNKNOWN"}
        data = path.read_bytes()
        value = json.loads(data)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {"state": "INVALID_OR_PARTIAL", "error": str(exc), "outcome": "UNKNOWN"}
    return _parse_export_document(value, row, expected_source_targets)


def _parse_export_document(value: Any, row: dict[str, Any],
                           expected_source_targets: dict[str, str] | None = None) -> dict[str, Any]:
    if value is None:
        return {"state": "NULL", "outcome": "UNKNOWN"}
    if not isinstance(value, dict):
        return {"state": "WRONG_TOP_LEVEL_TYPE", "outcome": "UNKNOWN"}
    if (value.get("schema_version") != "0.1.0" or value.get("run_state") != "COMPLETE" or
            value.get("outcome") != {"kind": "COMPLETED"}):
        return {"state": "INCOMPLETE_OR_SCHEMA_DRIFT", "outcome": "UNKNOWN"}
    if value.get("target") != "x86_64-unknown-linux-gnu":
        return {"state": "WRONG_TARGET_BINDING", "outcome": "UNKNOWN",
                "reported_target": value.get("target")}
    timeout_s = value.get("harness_timeout_s")
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or timeout_s != MAX_ROW_SECONDS:
        return {"state": "WRONG_HARNESS_TIMEOUT", "outcome": "UNKNOWN",
                "reported_harness_timeout_s": timeout_s}
    if value.get("kani_commit") != TOOL_SHA or value.get("kani_commit_dirty") is not False:
        return {"state": "WRONG_TOOL_BINDING", "outcome": "UNKNOWN"}
    selection = value.get("harness_selection")
    if (not isinstance(selection, dict) or selection.get("requested_filters") != [row["selector"]] or
            selection.get("exact") is not True or selection.get("unmatched_filters") != [] or
            type(selection.get("matched_count")) is not int or selection.get("matched_count") != 1):
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    harnesses = value.get("harnesses")
    if not isinstance(harnesses, list) or len(harnesses) != 1:
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    harness = harnesses[0]
    if not isinstance(harness, dict) or harness.get("name") != row["selector"]:
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    if "source_harness_file" in row:
        reported_file = harness.get("file")
        if (not isinstance(reported_file, str) or
                not (reported_file == row["source_harness_file"] or
                     reported_file.endswith("/" + row["source_harness_file"])) or
                type(harness.get("line")) is not int or
                harness["line"] != row["source_harness_line"]):
            return {"state": "SOURCE_STAGE_TARGET_MISMATCH", "outcome": "UNKNOWN"}
    attrs = harness.get("attributes")
    kind = attrs.get("kind") if isinstance(attrs, dict) else None
    contract = harness.get("contract")
    reported_contract_function = None
    if row["mode"] == "PFC":
        if (not isinstance(kind, dict) or len(kind) != 1 or "ProofForContract" not in kind or
                not isinstance(kind["ProofForContract"], dict) or not isinstance(contract, dict)):
            return {"state": "WRONG_MODE", "outcome": "UNKNOWN"}
        exported_target = kind["ProofForContract"].get("target_fn")
        reported_contract_function = contract.get("contracted_function_name")
        tracker = contract.get("recursion_tracker")
        expected_target = (expected_source_targets or {}).get(row["selector"], row["target"])
        if (set(contract) != {"contracted_function_name", "recursion_tracker"} or
                expected_target != row["target"] or
                _target_tokens(exported_target) is None or
                _target_tokens(exported_target) != _target_tokens(row.get("source_target_syntax", row["target"])) or
                not isinstance(reported_contract_function, str) or not reported_contract_function.strip() or
                (tracker is not None and (not isinstance(tracker, str) or not tracker.strip()))):
            return {"state": "CONTRACT_TARGET_BINDING_MISMATCH", "outcome": "UNKNOWN",
                    "expected_source_target": expected_target, "exported_target": exported_target,
                    "contracted_function_name": reported_contract_function}
    elif kind != "Proof":
        return {"state": "WRONG_MODE", "outcome": "UNKNOWN"}
    elif row["target"] != row["selector"]:
        return {"state": "REQUEST_TARGET_BINDING_MISMATCH", "outcome": "UNKNOWN"}
    if row["mode"] == "Original" and contract is not None:
        return {"state": "WRONG_MODE", "outcome": "UNKNOWN"}
    generated = harness.get("is_automatically_generated")
    if type(generated) is not bool:
        return {"state": "WRONG_EXPORT_SHAPE", "outcome": "UNKNOWN"}
    if generated is not False:
        return {"state": "WRONG_HARNESS_GENERATION", "outcome": "UNKNOWN",
                "is_automatically_generated": generated}
    if harness.get("crate_name") != "core":
        return {"state": "WRONG_CRATE_BINDING", "outcome": "UNKNOWN",
                "reported_crate_name": harness.get("crate_name")}
    config = value.get("configuration")
    required_checks = {"memory_safety": True, "overflow": True, "unwinding": True,
                       "undefined_function": True, "assertion_reach_checks": True,
                       "ignore_global_asm": False, "extra_pointer_checks": False,
                       "assert_contracts": False, "prove_safety_only": False}
    checks_config = config.get("checks") if isinstance(config, dict) else None
    if (not isinstance(config, dict) or not isinstance(checks_config, dict) or
            set(checks_config) != set(required_checks) or
            any(type(checks_config[key]) is not bool for key in required_checks) or
            checks_config != required_checks or
            config.get("coverage_enabled") is not False or
            config.get("cbmc_args") != ["--object-bits", "12"]):
        return {"state": "WRONG_CONFIGURATION", "outcome": "UNKNOWN"}
    enabled_features = value.get("enabled_unstable_features")
    required_features = set(UNSTABLE) | {"export-json", "unstable-options"}
    if (not isinstance(enabled_features, list) or any(not isinstance(feature, str) for feature in enabled_features) or
            len(enabled_features) != len(set(enabled_features)) or set(enabled_features) != required_features):
        return {"state": "WRONG_UNSTABLE_FEATURE_SET", "outcome": "UNKNOWN"}
    resolved_unwind = harness.get("resolved_unwind")
    if (type(resolved_unwind) is not int or resolved_unwind < 1 or
            type(row["unwind"]) is not int or row["unwind"] < 1 or
            resolved_unwind != row["unwind"]):
        return {"state": "WRONG_UNWIND", "outcome": "UNKNOWN"}
    reported_tools = value.get("tools")
    if not isinstance(reported_tools, dict) or any(not isinstance(reported_tools.get(k), str) or not reported_tools[k]
                                                   for k in ("kani", "rustc", "cbmc")):
        return {"state": "MISSING_TOOL_VERSION", "outcome": "UNKNOWN"}
    checks, covers = harness.get("checks"), harness.get("covers")
    if not isinstance(checks, dict) or not isinstance(covers, dict):
        return {"state": "WRONG_EXPORT_SHAPE", "outcome": "UNKNOWN"}
    failures = checks.get("failure")
    unsupported = harness.get("unsupported_constructs")
    if (not isinstance(failures, list) or any(not isinstance(prop_id, str) or not prop_id for prop_id in failures) or
            len(set(failures)) != len(failures) or not isinstance(unsupported, list)):
        return {"state": "WRONG_EXPORT_SHAPE", "outcome": "UNKNOWN"}
    bad_fields = ("unreachable", "undetermined", "error", "unknown")
    count_values = (checks.get("total"), checks.get("success"), covers.get("total"),
                    harness.get("n_properties"), harness.get("n_failed"))
    valid_counts = all(type(count) is int and count >= 0 for count in count_values)
    incomplete = (any(checks.get(key) != [] for key in bad_fields) or
                  checks.get("other") != [] or not valid_counts or
                  harness.get("n_properties") != checks["total"] + covers["total"])
    if unsupported or incomplete or checks["total"] == 0:
        return {"state": "INCOMPLETE_CHECK_INVENTORY", "outcome": "UNKNOWN",
                "failures": failures, "unsupported_constructs": unsupported,
                "checks": checks}
    satisfied = covers.get("satisfied")
    cover_bad = any(covers.get(key) != [] for key in
                    ("unsatisfiable", "unreachable", "undetermined", "error", "unknown", "other"))
    if (not isinstance(satisfied, list) or any(not isinstance(x, str) for x in satisfied) or
            len(set(satisfied)) != len(satisfied) or len(satisfied) != covers["total"] or
            cover_bad or len(satisfied) < row["required_cover_count"]):
        return {"state": "COVERAGE_INCOMPLETE", "outcome": "UNKNOWN", "covers": covers}
    outcome = harness.get("outcome")
    is_success = isinstance(outcome, dict) and outcome.get("kind") == "COMPLETED" and outcome.get("verdict") == "SUCCESS"
    is_failure = isinstance(outcome, dict) and outcome.get("kind") == "COMPLETED" and outcome.get("verdict") == "FAILURE"
    named = harness.get("failed_properties")
    if not isinstance(named, list):
        return {"state": "WRONG_EXPORT_SHAPE", "outcome": "UNKNOWN"}
    valid_statuses = {"FAILURE", "COVERED", "SATISFIED", "SUCCESS", "UNDETERMINED",
                      "UNKNOWN", "UNREACHABLE", "UNCOVERED", "UNSATISFIABLE", "ERROR"}
    named_shape_ok = all(isinstance(prop, dict) and isinstance(prop.get("id"), str) and prop["id"] and
        isinstance(prop.get("description"), str) and isinstance(prop.get("class"), str) and
        (prop.get("file") is None or isinstance(prop.get("file"), str)) and
        (prop.get("line") is None or isinstance(prop.get("line"), str)) and
        type(prop.get("trace_available")) is bool and prop.get("status") in valid_statuses
        for prop in named)
    failed_ids = [prop["id"] for prop in named if isinstance(prop, dict) and isinstance(prop.get("id"), str)]
    if (not named_shape_ok or len(failed_ids) != len(named) or len(set(failed_ids)) != len(failed_ids) or
            any(prop.get("status") != "FAILURE" for prop in named if isinstance(prop, dict)) or
            harness.get("n_failed") != len(failures) or len(failed_ids) != len(failures) or
            set(failed_ids) != set(failures) or checks.get("success") + len(failures) != checks.get("total")):
        return {"state": "INCONSISTENT_PROPERTY_COUNTS", "outcome": "UNKNOWN",
                "failures": failures, "failed_properties": named, "checks": checks}
    if not (is_success or is_failure):
        kind_name = outcome.get("kind") if isinstance(outcome, dict) else "MISSING"
        state_name = {"TIMEOUT": "HARNESS_TIMEOUT", "OUT_OF_MEMORY": "HARNESS_OUT_OF_MEMORY",
                      "CRASHED": "HARNESS_CRASHED"}.get(kind_name, "UNKNOWN_HARNESS_OUTCOME")
        return {"state": state_name, "outcome": "UNKNOWN", "harness_outcome": outcome,
                "checks": checks, "covers": covers, "failures": failures,
                "failed_properties": named, "is_automatically_generated": generated,
                "contract": contract}
    if row["expected"] in ("SUCCESS", "ALIAS_GAP"):
        accepted = is_success and not failures and harness.get("n_failed") == 0
        observed_outcome = ("ALIAS_GAP" if accepted and row["expected"] == "ALIAS_GAP" else
                            "EXPECTED" if accepted else "UNEXPECTED")
    else:
        matcher = row["failure_match"]
        locations = {(loc["file"], loc["line"]) for loc in matcher["locations"]}
        qualified = []
        for prop in named:
            if not isinstance(prop, dict):
                continue
            prop_class = prop.get("class")
            prop_file = prop.get("file")
            prop_line = prop.get("line")
            desc = prop.get("description")
            if (isinstance(prop_class, str) and prop_class == matcher["class"] and
                    isinstance(desc, str) and re.fullmatch(matcher["description_regex"], desc) is not None and
                    isinstance(prop_file, str) and isinstance(prop_line, str) and
                    any(prop_file.endswith(file) and prop_line == line for file, line in locations)):

                qualified.append(prop)
        # Any unmatched failure (including pointer, unwind, setup, or assertion failures)
        # is UNKNOWN. Multiple frame checks are allowed only when each binds to a declared
        # volatile-write source location and the PFC target binding above has already matched.
        if failures and not (is_failure and len(qualified) >= 1 and
                             set(failures) == {p.get("id") for p in qualified} and
                             harness.get("n_failed") == len(qualified)):
            return {"state": "INCONCLUSIVE_FAILURE_BINDING", "outcome": "UNKNOWN",
                    "failures": failures, "failed_properties": named,
                    "qualified_frame_properties": [p.get("id") for p in qualified],
                    "proof_credit": "PENDING_REVIEW"}
        accepted = (is_failure and len(qualified) >= 1 and
                    set(failures) == {p.get("id") for p in qualified} and
                    harness.get("n_failed") == len(qualified))
        observed_outcome = "EXPECTED" if accepted else "UNEXPECTED"
    classification = ("FRAME_WRITE_OUTSIDE_TARGET_SET" if row["expected"] == "DETECTED" and accepted else
                       "ALIAS_GAP" if row["expected"] == "ALIAS_GAP" and accepted else
                       "EXPECTED_SUCCESS" if accepted else "UNEXPECTED")
    return {"state": "VALIDATED_OBSERVATION", "outcome": observed_outcome,
            "classification": classification,
            "expected": row["expected"], "failures": failures, "failed_properties": named,
            "checks": checks, "covers": covers, "checks_success": checks.get("success"),
            "checks_total": checks.get("total"), "satisfied_cover_ids": satisfied,
            "required_cover_descriptions": row.get("required_cover_descriptions", []),
            "cover_description_to_id_binding": "PENDING_INDEPENDENT_REVIEW_EXPORT_HAS_IDS_ONLY",
            "selected_root": harness.get("name"), "selected_mode": kind,
            "is_automatically_generated": generated, "contract": contract,
            "harness_outcome": outcome,
            "expected_source_target": row["target"],
            "target_binding_source": "FROZEN_REQUEST_VS_GROUP_EXPORT",
            "reported_contracted_function_name": reported_contract_function,
            "contract_wrapper_correlation": "PENDING_REVIEW",
            "required_success_messages": row.get("required_success_messages", []),
            "success_message_binding": "PENDING_INDEPENDENT_REVIEW_EXPORT_HAS_NO_NAMED_SUCCESS_CHECKS",
            "proof_credit": "PENDING_REVIEW"}


def parse_group_export(path: Path, rows: list[dict[str, Any]], max_bytes: int = EXPORT_CAP_BYTES,
                       expected_source_targets: dict[str, str] | None = None) -> dict[str, dict[str, Any]]:
    """Validate a single export inventory, then independently bind each returned harness."""
    if not path.is_file():
        state = "MISSING"
        return {row["selector"]: {"state": state, "outcome": "UNKNOWN"} for row in rows}
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return {row["selector"]: {"state": "OVERSIZE", "size_bytes": size, "outcome": "UNKNOWN"}
                    for row in rows}
        if size == 0:
            return {row["selector"]: {"state": "EMPTY", "outcome": "UNKNOWN"} for row in rows}
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {row["selector"]: {"state": "INVALID_OR_PARTIAL", "error": str(exc), "outcome": "UNKNOWN"}
                for row in rows}
    selectors = [row["selector"] for row in rows]
    generic = {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    if not isinstance(value, dict):
        state = "NULL" if value is None else "WRONG_TOP_LEVEL_TYPE"
        return {selector: {"state": state, "outcome": "UNKNOWN"} for selector in selectors}
    if (value.get("schema_version") != "0.1.0" or value.get("run_state") not in ("COMPLETE", "PARTIAL") or
            value.get("outcome") != {"kind": "COMPLETED"}):
        state = "INCOMPLETE_OR_SCHEMA_DRIFT"
        return {selector: {"state": state, "outcome": "UNKNOWN"} for selector in selectors}
    if value.get("target") != "x86_64-unknown-linux-gnu":
        return {selector: {"state": "WRONG_TARGET_BINDING", "outcome": "UNKNOWN"} for selector in selectors}
    timeout_s = value.get("harness_timeout_s")
    if isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float)) or timeout_s != MAX_ROW_SECONDS:
        return {selector: {"state": "WRONG_HARNESS_TIMEOUT", "outcome": "UNKNOWN"} for selector in selectors}
    if value.get("kani_commit") != TOOL_SHA or value.get("kani_commit_dirty") is not False:
        state = "WRONG_TOOL_BINDING"
        return {selector: {"state": state, "outcome": "UNKNOWN"} for selector in selectors}
    selection = value.get("harness_selection")
    if (not isinstance(selection, dict) or selection.get("requested_filters") != selectors or
            selection.get("exact") is not True or selection.get("unmatched_filters") != [] or
            type(selection.get("matched_count")) is not int or selection.get("matched_count") != len(selectors)):
        return {selector: generic.copy() for selector in selectors}
    harnesses = value.get("harnesses")
    if not isinstance(harnesses, list):
        return {selector: {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"} for selector in selectors}
    by_name: dict[str, dict[str, Any]] = {}
    bad_shape = False
    for harness in harnesses:
        if not isinstance(harness, dict) or not isinstance(harness.get("name"), str):
            bad_shape = True
            continue
        name = harness["name"]
        if name not in selectors or name in by_name:
            bad_shape = True
        else:
            by_name[name] = harness
    if bad_shape:
        return {selector: generic.copy() for selector in selectors}
    if value.get("run_state") == "COMPLETE" and len(by_name) != len(selectors):
        return {selector: generic.copy() for selector in selectors}
    results = {}
    for row in rows:
        selector = row["selector"]
        harness = by_name.get(selector)
        if harness is None:
            results[selector] = {"state": "MISSING_HARNESS_IN_PARTIAL_EXPORT", "outcome": "UNKNOWN"}
            continue
        single = dict(value)
        single["run_state"] = "COMPLETE"
        single["harness_selection"] = {"requested_filters": [selector], "exact": True,
                                       "unmatched_filters": [], "matched_count": 1}
        single["harnesses"] = [harness]
        results[selector] = _parse_export_document(single, row, expected_source_targets)
    return results


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def binary_fingerprints(tool: Path, export: dict[str, Any]) -> dict[str, Any]:
    candidates = {"kani_driver": tool / "target/kani/bin/kani-driver",
                  "kani_compiler": tool / "target/kani/bin/kani-compiler"}
    cbmc = shutil.which("cbmc")
    if cbmc:
        candidates["cbmc"] = Path(cbmc)
    tools = export.get("tools") if isinstance(export, dict) else None
    fingerprints = {}
    for name, path in candidates.items():
        fingerprints[name] = {"path": str(path), "sha256": sha256(path) if path.is_file() else None}
    required = all(fingerprints.get(key, {}).get("sha256") for key in ("kani_driver", "kani_compiler", "cbmc"))
    return {"binaries": fingerprints, "required_hashes_present": required,
            "reported_versions": tools if isinstance(tools, dict) else None}


def seed_inventory(std: Path, tool: Path, out: Path, request: dict[str, Any]) -> None:
    """Freeze selectors and expected targets from the request without invoking Kani."""
    identities = verify_source(std, tool, request)
    out.mkdir(parents=True, exist_ok=True)
    phase_started = time.time()
    groups = []
    group_for_row: dict[str, int] = {}
    for index, group_rows in enumerate(_group_rows(request["rows"]), 1):
        for row in group_rows:
            group_for_row[row["id"]] = index
        groups.append({"group": index, "row_ids": [r["id"] for r in group_rows],
                       "selectors": [r["selector"] for r in group_rows],
                       "unwind": group_rows[0]["unwind"],
                       "group_timeout_seconds": sum(r["timeout_seconds"] for r in group_rows) + STD_COMPILE_SECONDS,
                       "compile_cap_seconds": STD_COMPILE_SECONDS,
                       "argv": build_argv(std, tool, [r["selector"] for r in group_rows],
                                           group_rows[0]["unwind"],
                                           out / "groups" / f"group-{index:02d}" / "export.json",
                                           group_rows[0]["timeout_seconds"]),
                       "status": "NOT_RUN"})
    expected_targets = {row["selector"]: row["target"] for row in request["rows"]}
    inventory_rows = [{"id": row["id"], "selector": row["selector"], "mode": row["mode"],
                       "variant": row["variant"], "group": group_for_row[row["id"]],
                       "expected_source_target": row["target"], "status": "NOT_RUN", "outcome": "UNKNOWN"}
                      for row in sorted(request["rows"], key=lambda r: (r["id"], r["selector"]))]
    _write_json(out / "inventory.json", {"state": "INVENTORY_FROZEN_NOT_RUN",
        "inventory_source": "FROZEN_CI_REQUEST_ROWS_NOT_KANI_LIST",
        "phase_started_unix": phase_started, "request_sha256": sha256(REQUEST_PATH),
        "source_identities": identities, "expected_source_targets": expected_targets,
        "rows": inventory_rows, "groups": groups})

def _run_variant(std: Path, name: str, request: dict[str, Any]) -> tuple[Path | None, dict[str, str]]:
    if name == "production":
        return None, request["changed_file_sha256"]
    patch, _, changed = _variant_info(request, name)
    subprocess.run(["git", "-C", str(std), "apply", "--check", str(patch)], check=True)
    subprocess.run(["git", "-C", str(std), "apply", str(patch)], check=True)
    try:
        status = git(std, "status", "--porcelain=v1", "-z")
        changed_paths = {item[3:] for item in status.split("\0") if item}
        if changed_paths != set(changed):
            raise RunnerError(f"variant changed unexpected paths ({name}): {sorted(changed_paths ^ set(changed))}")
        for rel, digest in changed.items():
            path = (std / rel).resolve()
            if std.resolve() not in path.parents or not path.is_file() or sha256(path) != digest:
                raise RunnerError(f"variant changed-file SHA mismatch ({name}): {rel}")
    except Exception:
        subprocess.run(["git", "-C", str(std), "apply", "--reverse", "--check", str(patch)], check=True)
        subprocess.run(["git", "-C", str(std), "apply", "--reverse", str(patch)], check=True)
        raise
    return patch, changed


def _row_base(row: dict[str, Any], status: str = "NOT_RUN") -> dict[str, Any]:
    return {"id": row["id"], "selector": row["selector"], "mode": row["mode"],
            "variant": row["variant"], "status": status, "outcome": "UNKNOWN",
            "original_exit": None, "signal": None}


def _artifact_size(out: Path) -> int:
    total = 0
    for path in out.rglob("*"):
        if path.is_file():
            try:
                total += path.stat().st_size
            except OSError:
                pass
    return total


def _group_rows(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Stable groups with identical invocation flags; unwind and timeout are CLI-wide."""
    groups: list[list[dict[str, Any]]] = []
    by_key: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in rows:
        key = (row["variant"], row["unwind"], row["timeout_seconds"],
               "--no-assert-contracts", "--jobs=1", "--cfg=kani_smallsort_controls",
               tuple(UNSTABLE), ("--object-bits", "12"))
        if key not in by_key:
            by_key[key] = []
            groups.append(by_key[key])
        by_key[key].append(row)
    return groups


def _group_rss_limit_kib() -> int:
    available_kib = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                available_kib = int(line.split()[1])
                break
    except (OSError, ValueError, IndexError):
        pass
    if available_kib is None:
        return 0
    return max(0, min(12 * 1024 * 1024, available_kib - 2 * 1024 * 1024))


def _require_fresh_export(path: Path) -> None:
    if path.exists():
        raise RunnerError(f"refusing pre-existing group export path: {path}")


def _expected_group_exit(export_path: Path, selectors: list[str]) -> int | None:
    """Derive expected process exit from each selected harness's terminal outcome."""
    try:
        if export_path.stat().st_size > EXPORT_CAP_BYTES:
            return None
        value = json.loads(export_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    selection = value.get("harness_selection") if isinstance(value, dict) else None
    timeout_s = value.get("harness_timeout_s") if isinstance(value, dict) else None
    if (not isinstance(value, dict) or value.get("schema_version") != "0.1.0" or
            value.get("outcome") != {"kind": "COMPLETED"} or
            value.get("kani_commit") != TOOL_SHA or value.get("kani_commit_dirty") is not False or
            value.get("target") != "x86_64-unknown-linux-gnu" or isinstance(timeout_s, bool) or
            not isinstance(timeout_s, (int, float)) or timeout_s != MAX_ROW_SECONDS or
            value.get("run_state") != "COMPLETE" or
            not isinstance(selection, dict) or selection.get("requested_filters") != selectors or
            selection.get("exact") is not True or selection.get("unmatched_filters") != [] or
            type(selection.get("matched_count")) is not int or selection.get("matched_count") != len(selectors)):
        return None
    harnesses = value.get("harnesses")
    if not isinstance(harnesses, list) or len(harnesses) != len(selectors):
        return None
    by_name = {}
    for harness in harnesses:
        if not isinstance(harness, dict) or harness.get("name") not in selectors or harness["name"] in by_name:
            return None
        by_name[harness["name"]] = harness
    if set(by_name) != set(selectors):
        return None
    has_non_success = False
    for selector in selectors:
        outcome = by_name[selector].get("outcome")
        if not isinstance(outcome, dict):
            return None
        kind = outcome.get("kind")
        verdict = outcome.get("verdict")
        if kind == "COMPLETED" and verdict == "SUCCESS":
            continue
        if kind == "COMPLETED" and verdict == "FAILURE":
            has_non_success = True
            continue
        if kind in ("TIMEOUT", "OUT_OF_MEMORY", "CRASHED"):
            has_non_success = True
            continue
        return None
    return 1 if has_non_success else 0


def _group_execution_status(invocation: dict[str, Any] | None, export_path: Path,
                            selectors: list[str]) -> tuple[bool, str, int | None]:
    expected_exit = _expected_group_exit(export_path, selectors)
    if invocation is None:
        return False, "NOT_RUN", expected_exit
    if (invocation.get("termination_reason") is not None or invocation.get("timed_out") or
            invocation.get("signal") is not None or invocation.get("original_exit_code") is None):
        return False, "PARTIAL", expected_exit
    if expected_exit is None:
        return False, "PARTIAL", None
    if invocation.get("original_exit_code") != expected_exit:
        return False, "EXIT_MISMATCH", expected_exit
    return True, "COMPLETE", expected_exit


def run_rows(std: Path, tool: Path, out: Path, request: dict[str, Any]) -> int:
    out.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    fatal: str | None = None
    try:
        verify_source(std, tool, request)
        inventory = json.loads((out / "inventory.json").read_text(encoding="utf-8"))
        if (inventory.get("state") != "INVENTORY_FROZEN_NOT_RUN" or
                inventory.get("inventory_source") != "FROZEN_CI_REQUEST_ROWS_NOT_KANI_LIST"):
            raise RunnerError("missing frozen request inventory")
        if inventory.get("request_sha256") != sha256(REQUEST_PATH):
            raise RunnerError("frozen request inventory drift")
        expected_source_targets = {row["selector"]: row["target"] for row in request["rows"]}
        if inventory.get("expected_source_targets") != expected_source_targets:
            raise RunnerError("frozen expected source target inventory drift")
        expected_groups = [[r["id"] for r in g] for g in _group_rows(request["rows"])]
        actual_groups = inventory.get("groups")
        if (not isinstance(actual_groups, list) or
                [[*g.get("row_ids", [])] if isinstance(g, dict) else None for g in actual_groups] != expected_groups):
            raise RunnerError("frozen group inventory drift")
        phase_started = inventory.get("phase_started_unix")
        if not isinstance(phase_started, (int, float)):
            raise RunnerError("frozen inventory lacks shared phase start")
    except Exception as exc:
        fatal = f"preflight: {type(exc).__name__}: {exc}"
        phase_started = time.time()
    try:
        child_env = ci_env()
    except Exception as exc:
        child_env = None
        fatal = f"environment: {type(exc).__name__}: {exc}"

    group_receipts = []
    row_results: dict[str, dict[str, Any]] = {}
    for group_index, group_rows in enumerate(_group_rows(request["rows"]), 1):
        group_dir = out / "groups" / f"group-{group_index:02d}"
        group_dir.mkdir(parents=True, exist_ok=True)
        selectors = [row["selector"] for row in group_rows]
        export_path = (group_dir / "export.json").resolve()
        group_result: dict[str, Any] = {"group": group_index, "row_ids": [r["id"] for r in group_rows],
            "selectors": selectors, "unwind": group_rows[0]["unwind"],
            "compile_cap_seconds": STD_COMPILE_SECONDS,
            "group_timeout_seconds": sum(r["timeout_seconds"] for r in group_rows) + STD_COMPILE_SECONDS,
            "rss_scope": "GROUP_ONLY_PER_ROOT_UNKNOWN", "status": "NOT_RUN"}
        if fatal:
            group_result["reason"] = fatal
            parsed_by_selector = {selector: {"state": "NOT_RUN", "outcome": "UNKNOWN"} for selector in selectors}
            invocation = None
        else:
            patch: Path | None = None
            invocation = None
            try:
                source_before = verify_source(std, tool, request)
                tool_before = binary_fingerprints(tool, {})
                patch, variant_files = _run_variant(std, group_rows[0]["variant"], request)
                group_result.update(source_before=source_before, tool_fingerprints_before=tool_before,
                    source_under_test={"base_std_sha": request["base_std_sha"],
                    "variant": group_rows[0]["variant"],
                    "file_sha256": {**request["changed_file_sha256"], **variant_files},
                    "patch_sha256": sha256(patch) if patch is not None else None})
                argv = build_argv(std, tool, selectors, group_rows[0]["unwind"], export_path,
                                  group_rows[0]["timeout_seconds"])
                group_result["argv"] = argv
                _require_fresh_export(export_path)
                rss_cap = _group_rss_limit_kib()
                group_result["rss_cap_kib"] = rss_cap
                if rss_cap <= 0:
                    raise RunnerError("cannot establish positive group RSS cap from MemAvailable")
                invocation = execute(argv, std.resolve(), group_dir,
                    group_result["group_timeout_seconds"], rss_cap_kib=rss_cap,
                    stdout_cap=STDOUT_CAP_BYTES, stderr_cap=STDERR_CAP_BYTES,
                    export_path=export_path, export_cap=EXPORT_CAP_BYTES, env=child_env,
                    compile_marker=export_path, compile_timeout=STD_COMPILE_SECONDS,
                    compile_selectors=selectors)
                group_result["execution"] = invocation
                group_result["rss_peak_kib"] = invocation.get("rss_peak_kib")
                group_result["rss_peak_gib"] = invocation.get("rss_peak_gib")
                parsed_by_selector = parse_group_export(export_path, group_rows,
                    max_bytes=EXPORT_CAP_BYTES, expected_source_targets=expected_source_targets)
                if export_path.is_file() and export_path.stat().st_size <= EXPORT_CAP_BYTES:
                    try:
                        raw_export = json.loads(export_path.read_text(encoding="utf-8"))
                        if isinstance(raw_export, dict):
                            fingerprints = binary_fingerprints(tool, raw_export)
                            group_result["tool_fingerprints"] = fingerprints
                            before_hashes = {k: v.get("sha256") for k, v in tool_before["binaries"].items()}
                            after_hashes = {k: v.get("sha256") for k, v in fingerprints["binaries"].items()}
                            if (not fingerprints["required_hashes_present"] or before_hashes != after_hashes):
                                for parsed in parsed_by_selector.values():
                                    parsed["outcome"] = "UNKNOWN"
                                    parsed["fingerprint_state"] = ("MISSING_REQUIRED_BINARY_HASH" if
                                        not fingerprints["required_hashes_present"] else "TOOL_BINARY_DRIFT")
                                if before_hashes != after_hashes:
                                    fatal = "tool_binary_drift"
                    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                        pass
                group_result["original_exit_code"] = invocation.get("original_exit_code")
                group_result["signal"] = invocation.get("signal")
                group_complete, group_status, expected_exit = _group_execution_status(invocation, export_path, selectors)
                group_result["complete"] = group_complete
                group_result["status"] = group_status
                group_result["expected_exit_code"] = expected_exit
                if not group_complete:
                    group_result["stop_reason"] = (invocation.get("termination_reason") or
                        ("child_signal" if invocation.get("signal") else
                         "group_exit_mismatch" if group_status == "EXIT_MISMATCH" else
                         "missing_or_incomplete_group_export"))
            except Exception as exc:
                group_result.update(status="RUNNER_ERROR", reason=f"{type(exc).__name__}: {exc}")
                parsed_by_selector = {selector: {"state": "RUNNER_ERROR", "outcome": "UNKNOWN"}
                                      for selector in selectors}
                fatal = fatal or "fatal_source_or_variant_drift"
            finally:
                if patch is not None:
                    try:
                        subprocess.run(["git", "-C", str(std), "apply", "--reverse", "--check", str(patch)], check=True)
                        subprocess.run(["git", "-C", str(std), "apply", "--reverse", str(patch)], check=True)
                    except Exception as exc:
                        group_result["variant_cleanup_error"] = str(exc)
                        fatal = "variant_cleanup_failed"
            try:
                source_after = verify_source(std, tool, request)
                group_result["source_after"] = source_after
                if source_after != group_result.get("source_before"):
                    fatal = "source_identity_drift"
            except Exception as exc:
                group_result["post_run_source_drift"] = str(exc)
                fatal = "source_drift"
            if _artifact_size(out) > ARTIFACT_CAP_BYTES:
                fatal = "artifact_bytes_cap"
        for row in group_rows:
            row_out = out / row["id"]
            row_out.mkdir(parents=True, exist_ok=True)
            parsed = parsed_by_selector.get(row["selector"], {"state": "MISSING", "outcome": "UNKNOWN"})
            row_status = ("OBSERVED" if parsed.get("state") == "VALIDATED_OBSERVATION" else
                          "NOT_RUN" if parsed.get("state") == "NOT_RUN" else "PARTIAL")
            result = _row_base(row, row_status)
            result.update(group=group_index, export=parsed, outcome=parsed.get("outcome", "UNKNOWN"),
                          group_rss_peak_kib=group_result.get("rss_peak_kib"),
                          complete=group_result.get("complete", False),
                          root_rss_kib="UNKNOWN", reviewer_binding="PENDING; no automatic proof credit")
            result["group_status"] = group_result.get("status")
            if group_result.get("reason"):
                result["group_reason"] = group_result["reason"]
            if invocation is not None:
                result["group_exit_code"] = invocation.get("original_exit_code")
                result["group_termination_reason"] = invocation.get("termination_reason")
            if fatal:
                result["stop_reason"] = fatal
                result["outcome"] = "UNKNOWN"
            row_results[row["id"]] = result
            _write_json(row_out / "receipt.json", result)
        group_receipts.append(group_result)
        _write_json(group_dir / "receipt.json", group_result)
        _write_json(out / "receipt.json", {"state": "STOPPED" if fatal else "IN_PROGRESS",
            "stop_reason": fatal, "proof_credit": "PENDING_REVIEW", "groups": group_receipts})
        if fatal:
            break

    for row in request["rows"]:
        if row["id"] in row_results:
            results.append(row_results[row["id"]])
        else:
            result = _row_base(row)
            result["reason"] = fatal or "not reached"
            row_results[row["id"]] = result
            _write_json(out / row["id"] / "receipt.json", result)
            results.append(result)
    unknown = any(result.get("outcome") not in ("EXPECTED", "ALIAS_GAP") for result in results)
    batch_complete = (not fatal and len(group_receipts) == len(_group_rows(request["rows"])) and
                      all(group.get("complete") is True for group in group_receipts))
    final_state = ("STOPPED" if fatal else "PARTIAL" if not batch_complete else
                   "COMPLETE" if not unknown else "COMPLETE_WITH_UNKNOWN")
    _write_json(out / "receipt.json", {"state": final_state, "stop_reason": fatal,
                 "complete": batch_complete, "proof_credit": "PENDING_REVIEW", "std_sha": STD_SHA, "std_tree": STD_TREE,
                 "tool_sha": TOOL_SHA, "tool_tree": TOOL_TREE,
                 "phase_elapsed_seconds": round(max(0, time.time() - phase_started), 3),
                 "groups": group_receipts, "rows": results})
    return 1 if fatal or unknown or not batch_complete else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("check-source", "inventory", "run"):
        p = sub.add_parser(command)
        p.add_argument("--std", required=True, type=Path)
        p.add_argument("--tool", required=True, type=Path)
        if command != "check-source": p.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        request = load_request()
        if args.command == "check-source":
            print(json.dumps(verify_source(args.std, args.tool, request), sort_keys=True))
        elif args.command == "inventory":
            seed_inventory(args.std, args.tool, args.out, request)
        else:
            return run_rows(args.std, args.tool, args.out, request)
    except Exception as exc:
        print(f"runner: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
