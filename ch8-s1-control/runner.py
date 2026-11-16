#!/usr/bin/env python3
"""Offline, bounded CI runner for the frozen Challenge 8 S1 request.

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
STD_SHA = "f22f84f316ad8ef6f3fccce86424bad927b09f78"
STD_TREE = "e0dc89592926571e823797f8618cd6b4a7e11ff6"
TOOL_SHA = "0aac16ef62da9e9d5645782d458593e5d78143ba"
TOOL_TREE = "9d8bc9312bf955ef126d32b819b3cd0ed105ed2b"
MAX_ROW_SECONDS = 600
COMPILE_SECONDS = 900
GROUP_RSS_MAX_KIB = 12 * 1024 * 1024
MEMORY_RESERVE_KIB = 2 * 1024 * 1024
PHASE_SECONDS = 4500
PHASE_CLEANUP_MARGIN = 10
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
    for row in rows:
        if not isinstance(row, dict):
            raise RunnerError("row is not an object")
        rid, selector = row.get("id"), row.get("selector")
        if not isinstance(rid, str) or not rid or rid in seen_ids:
            raise RunnerError("missing or duplicate row id")
        if not isinstance(selector, str) or not selector:
            raise RunnerError("missing exact selector")
        seen_ids.add(rid)
        if row.get("mode") not in ("PFC", "Original"):
            raise RunnerError(f"invalid mode for {rid}")
        if row.get("variant") not in ("production", "activation-default", "activation-override"):
            raise RunnerError(f"invalid variant for {rid}")
        if not isinstance(row.get("unwind"), int) or row["unwind"] < 1:
            raise RunnerError(f"invalid unwind for {rid}")
        if row.get("expected") not in ("SUCCESS", "DETECTED"):
            raise RunnerError(f"invalid expected result for {rid}")
        if not isinstance(row.get("required_cover_count"), int) or row["required_cover_count"] < 0:
            raise RunnerError(f"invalid cover count for {rid}")
        timeout = row.get("timeout_seconds")
        if type(timeout) is not int or timeout != MAX_ROW_SECONDS:
            raise RunnerError(f"timeout outside 1..{MAX_ROW_SECONDS} for {rid}")
        if row["expected"] == "DETECTED" and not isinstance(row.get("failure_description"), str):
            raise RunnerError(f"negative row lacks named failure description: {rid}")
    for key in ("changed_file_sha256", "variants"):
        if not isinstance(request.get(key), dict):
            raise RunnerError(f"missing request {key} object")
    budgets = request.get("budgets")
    if not isinstance(budgets, dict) or any(budgets.get(key) != val for key, val in {
            "phase_seconds": PHASE_SECONDS, "rss_kib": RSS_CAP_KIB,
            "stdout_bytes": STDOUT_CAP_BYTES, "stderr_bytes": STDERR_CAP_BYTES,
            "export_bytes": EXPORT_CAP_BYTES, "artifact_bytes": ARTIFACT_CAP_BYTES,
            "row_seconds": MAX_ROW_SECONDS, "compile_seconds": COMPILE_SECONDS,
            "group_rss_max_kib": GROUP_RSS_MAX_KIB,
            "memory_reserve_kib": MEMORY_RESERVE_KIB}.items()):
        raise RunnerError("request budget mismatch")
    bindings = request.get("source_bindings")
    if not isinstance(bindings, dict) or set(bindings) != seen_ids:
        raise RunnerError("source binding row inventory mismatch")
    for row in rows:
        binding = bindings[row["id"]]
        if (not isinstance(binding, dict) or binding.get("selector") != row["selector"] or
                binding.get("mode") != row["mode"] or binding.get("crate") != "core" or
                not isinstance(binding.get("file"), str) or
                not isinstance(binding.get("locations"), list) or not binding["locations"] or
                any(not isinstance(loc, dict) or type(loc.get("line")) is not int or
                    loc["line"] < 1 or not isinstance(loc.get("source"), str)
                    for loc in binding["locations"]) or
                (row["mode"] == "PFC" and not isinstance(binding.get("target"), str)) or
                (row["mode"] == "Original" and binding.get("target") is not None)):
            raise RunnerError(f"invalid source binding: {row['id']}")
    smoke_ids = {"stable_default_cell", "stable_freeze_u8", "unstable_default_cell",
                 "unstable_freeze_u8", "freeze_default_noncopy", "freeze_copy_u8"}
    if not smoke_ids.issubset(bindings) or len({bindings[k]["target"] for k in smoke_ids}) != 6:
        raise RunnerError("six distinct PFC source targets required")
    for diagnostic, positive in (("activation-default", "stable_default_cell"),
                                 ("activation-override", "stable_freeze_u8")):
        if bindings.get(diagnostic, {}).get("target") != bindings[positive]["target"]:
            raise RunnerError("activation source target mismatch")
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
    for binding in request.get("source_bindings", {}).values():
        path = (std / binding["file"]).resolve()
        if (std.resolve() not in path.parents or not path.is_file() or
                sha256(path) != binding["sha256"]):
            raise RunnerError("harness source binding SHA drift")
        lines = path.read_text(encoding="utf-8").splitlines()
        for loc in binding["locations"]:
            if loc["line"] > len(lines) or lines[loc["line"]-1] != loc["source"]:
                raise RunnerError("harness source location anchor drift")
    # Variants may describe test overlays; their path/hash are checked when selected.
    return {"std_sha": STD_SHA, "std_tree": STD_TREE, "tool_sha": TOOL_SHA,
            "tool_tree": TOOL_TREE, "changed_file_sha256": request["changed_file_sha256"]}


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


def group_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, int], dict[str, Any]] = {}
    seen: set[tuple[str, int, str]] = set()
    for row in rows:
        key = (row["variant"], row["unwind"])
        identity = (*key, row["selector"])
        if identity in seen:
            raise RunnerError("duplicate selector in invocation group")
        seen.add(identity)
        group = groups.setdefault(key, {"id": f"{key[0]}-u{key[1]}",
                                        "variant": key[0], "unwind": key[1], "rows": []})
        group["rows"].append(row)
    return list(groups.values())


def build_argv(std: Path, tool: Path, selectors: list[str], unwind: int, export: Path) -> list[str]:
    if not selectors or len(set(selectors)) != len(selectors):
        raise RunnerError("nonempty unique exact group selectors required")
    argv = [str((tool.resolve() / "scripts/kani")), "verify-std", "-Z", "unstable-options"]
    for feature in UNSTABLE:
        argv += ["-Z", feature]
    argv += ["--no-assert-contracts", "--jobs=1", "--harness-timeout", "600s"]
    for selector in selectors:
        argv += ["--harness", selector]
    argv += ["--exact", "--default-unwind", str(unwind), "-Z", "export-json",
             "--export-json", str(export.resolve()), "--output-format=terse", str((std.resolve() / "library")),
             "--cbmc-args", "--object-bits", "12"]
    return argv


def ci_env(std: Path | None = None) -> dict[str, str]:
    env = os.environ.copy()
    fixed = "--cfg=kani_smallsort_sorting --cfg=kani_smallsort_controls"
    inherited = env.get("RUSTFLAGS", "").strip()
    if inherited and inherited != fixed:
        raise RunnerError("refusing inherited RUSTFLAGS outside the frozen sorting+controls cfg")
    env["RUSTFLAGS"] = fixed
    if std is not None:
        # std_project deletes its dummy crate on every invocation, including its
        # default target directory. Keep this job-local cache outside that tree.
        env["CARGO_TARGET_DIR"] = str(std.resolve() / "target/ch8-s1-cargo")
    return env


def _read_pipe(pipe, target: Path, cap: int, state: dict[str, Any], lock: threading.Lock, key: str,
               capture_tail: bool = False) -> None:
    head_cap = cap // 2 if capture_tail else cap
    tail_cap = cap - head_cap if capture_tail else 0
    head_kept = 0
    tail = bytearray()
    with target.open("wb") as output:
        while True:
            data = pipe.read(65536)
            if not data:
                break
            with lock:
                room = max(0, cap - state[key + "_kept"])
                if len(data) > room:
                    state[key + "_cap"] = True
                state[key + "_kept"] += min(room, len(data))
                state[key + "_bytes"] += len(data)
                head = state.setdefault(key + "_preview_head", bytearray())
                head.extend(data[:max(0, 2048-len(head))])
                tail_preview = state.setdefault(key + "_preview_tail", bytearray())
                tail_preview.extend(data)
                del tail_preview[:-2048]
            head = min(len(data), head_cap - head_kept)
            output.seek(head_kept)
            output.write(data[:head])
            head_kept += head
            if tail_cap:
                tail.extend(data[head:])
                del tail[:-tail_cap]
                # Keep the latest bounded tail durable for a SIGKILL fallback.
                output.seek(head_kept)
                output.write(tail)
                output.truncate()
                output.flush()
        output.seek(head_kept)
        output.write(tail)
    pipe.close()


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


def _stream_preview(state: dict[str, Any], stream: str) -> dict[str, Any]:
    return {"head": bytes(state.get(stream + "_preview_head", b"")).decode("utf-8", errors="replace"),
            "tail": bytes(state.get(stream + "_preview_tail", b"")).decode("utf-8", errors="replace"),
            "observed_bytes": state.get(stream + "_bytes", 0),
            "scope": "PIPE_BYTES_OBSERVED_AT_SNAPSHOT_NOT_PER_HARNESS"}


class CompileMonitor:
    """The stock initial export marker is written after std_project, before verification."""
    def __init__(self, receipt_path: Path, export: Path, selectors: list[str],
                 seconds: float = COMPILE_SECONDS):
        self.path, self.export, self.selectors, self.seconds = receipt_path, export, selectors, seconds
        self.receipt: dict[str, Any] = {
            "schema": "ch8-s1-compile-receipt-v1", "state": "IN_PROGRESS",
            "limit_seconds": seconds, "std_sha": STD_SHA, "tool_sha": TOOL_SHA,
            "request_sha256": sha256(REQUEST_PATH), "selectors": selectors,
            "scope": "STD_PROJECT_COMPILATION_AND_LINK_UNTIL_INITIAL_EXPORT",
            "proof_credit": "NONE", "elapsed_upper_bound_seconds": None}
        _write_json(self.path, self.receipt)

    def poll(self, elapsed: float, state: dict[str, Any]) -> bool:
        if self.receipt["state"] != "IN_PROGRESS":
            return False
        if elapsed >= self.seconds:
            return True
        try:
            if self.export.stat().st_size > EXPORT_CAP_BYTES:
                return False
            data = self.export.read_bytes()
            value = json.loads(data)
        except (OSError, UnicodeError, ValueError):
            return False
        if not _selection_matches(value, self.selectors, marker=True):
            return False
        self.receipt.update(state="COMPLETE", boundary="STOCK_INITIAL_EXPORT_OBSERVED",
                            observed_run_state=value["run_state"],
                            elapsed_upper_bound_seconds=round(elapsed, 3),
                            marker_sha256=hashlib.sha256(data).hexdigest())
        for name in ("stdout", "stderr"):
            self.receipt[name] = _stream_preview(state, name)
        _write_json(self.path, self.receipt)
        return False

    def finish(self, execution: dict[str, Any], state: dict[str, Any]) -> None:
        if self.receipt["state"] == "IN_PROGRESS":
            # A very fast child may have exited between polling iterations.
            elapsed = execution.get("elapsed_seconds", self.seconds)
            self.poll(elapsed, state)
        if self.receipt["state"] == "IN_PROGRESS":
            self.receipt.update(state="FAILED", reason=execution.get("termination_reason") or
                                execution.get("runner_error") or "NO_VALID_INITIAL_EXPORT_BOUNDARY")
            for name in ("stdout", "stderr"):
                self.receipt[name] = _stream_preview(state, name)
        self.receipt["group_execution"] = execution
        _write_json(self.path, self.receipt)


def group_memory_budget(meminfo: Path = Path("/proc/meminfo"),
                        cgroup: Path = Path("/sys/fs/cgroup")) -> dict[str, Any]:
    values = {}
    for line in meminfo.read_text().splitlines():
        if line.startswith("MemAvailable:"):
            values["mem_available_kib"] = int(line.split()[1])
    available = values.get("mem_available_kib")
    if not isinstance(available, int):
        raise RunnerError("cannot establish available memory for group cap")
    # A cgroup can have less headroom than the host's MemAvailable.
    limit = cgroup / "memory.max"
    current = cgroup / "memory.current"
    if limit.is_file() and current.is_file():
        value = limit.read_text().strip()
        if value != "max":
            headroom = max(0, (int(value)-int(current.read_text().strip())) // 1024)
            values["cgroup_headroom_kib"] = headroom
            available = min(available, headroom)
    cap = min(GROUP_RSS_MAX_KIB, available-MEMORY_RESERVE_KIB)
    if cap <= 0:
        raise RunnerError("less than 2 GiB memory reserve available")
    return {**values, "available_kib": available, "reserve_kib": MEMORY_RESERVE_KIB,
            "group_cap_kib": cap, "per_root_cap_kib": RSS_CAP_KIB,
            "per_root_rss_status": "UNKNOWN_NO_EXACT_HARNESS_ATTRIBUTION"}


def execute(argv: list[str], cwd: Path, out: Path, timeout: int,
            rss_cap_kib: int = RSS_CAP_KIB, stdout_cap: int = STDOUT_CAP_BYTES,
            stderr_cap: int = STDERR_CAP_BYTES, export_path: Path | None = None,
            export_cap: int = EXPORT_CAP_BYTES, env: dict[str, str] | None = None,
            capture_tail: bool = False, compile_monitor: CompileMonitor | None = None) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    info: dict[str, Any] = {"original_exit_code": None, "signal": None, "timed_out": False,
                            "rss_peak_kib": 0, "rss_status": "SAMPLED_PROCESS_GROUP",
                            "output_truncated": False, "output_bytes": 0}
    state: dict[str, Any] = {"stdout_cap": False, "stderr_cap": False,
                             "stdout_kept": 0, "stderr_kept": 0,
                             "stdout_bytes": 0, "stderr_bytes": 0}
    lock = threading.Lock()
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, bufsize=0)
    except OSError as exc:
        info.update(runner_error=f"exec failed: {exc}", elapsed_seconds=time.monotonic() - started)
        if compile_monitor is not None:
            compile_monitor.finish(info, state)
        return info
    threads = [threading.Thread(target=_read_pipe, args=(proc.stdout, out / "stdout.log", stdout_cap,
                                                         state, lock, "stdout", capture_tail), daemon=True),
               threading.Thread(target=_read_pipe, args=(proc.stderr, out / "stderr.log", stderr_cap,
                                                         state, lock, "stderr", capture_tail), daemon=True)]
    for thread in threads: thread.start()
    deadline = started + timeout
    killed_for = None
    external_signal: list[int] = []
    previous_handlers = {}
    def handle_external(signum, _frame):
        external_signal.append(signum)
        _kill_group(proc.pid)
    for sig in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[sig] = signal.getsignal(sig)
        signal.signal(sig, handle_external)
    try:
        while proc.poll() is None or any(thread.is_alive() for thread in threads):
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
            if compile_monitor is not None:
                with lock:
                    compile_expired = compile_monitor.poll(time.monotonic()-started, state)
                if compile_expired:
                    killed_for = "compile_timeout"; info["timed_out"] = True
            if killed_for:
                break
            if time.monotonic() >= deadline:
                killed_for = "timeout"; info["timed_out"] = True; break
            time.sleep(0.05)
    finally:
        for sig, handler in previous_handlers.items():
            signal.signal(sig, handler)
    if killed_for:
        info["termination_reason"] = killed_for
        _kill_group(proc.pid)
    try:
        code = proc.wait(timeout=7)
    except subprocess.TimeoutExpired:
        _kill_group(proc.pid, 0)
        code = proc.wait()
    for thread in threads: thread.join(timeout=2)
    info["original_exit_code"] = code
    if code < 0:
        info["signal"] = -code
    if external_signal:
        info["interrupted_by_signal"] = external_signal[-1]
        info["termination_reason"] = "external_signal"
    info["output_bytes"] = state["stdout_bytes"] + state["stderr_bytes"]
    info["stdout_bytes"] = state["stdout_bytes"]
    info["stderr_bytes"] = state["stderr_bytes"]
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
    if compile_monitor is not None:
        compile_monitor.finish(info, state)
    return info


def _target_tokens(value: Any) -> list[str] | None:
    """Compare the frozen ASCII Rust path syntax without merging identifiers."""
    if not isinstance(value, str):
        return None
    tokens = re.findall(r"::|[A-Za-z_][A-Za-z_0-9]*|[<>]", value)
    if not tokens or "".join(tokens) != "".join(value.split()):
        return None
    return tokens


def _selection_matches(value: Any, selectors: list[str], *, marker: bool = False) -> bool:
    if (not isinstance(value, dict) or value.get("schema_version") != "0.1.0" or
            value.get("kani_commit") != TOOL_SHA or value.get("kani_commit_dirty") is not False or
            value.get("run_state") not in (("INCOMPLETE", "COMPLETE") if marker else ("COMPLETE",)) or
            type(value.get("harness_timeout_s")) not in (int, float) or
            value["harness_timeout_s"] != MAX_ROW_SECONDS):
        return False
    selection = value.get("harness_selection")
    return (isinstance(selection, dict) and selection.get("requested_filters") == selectors and
            selection.get("exact") is True and selection.get("unmatched_filters") == [] and
            type(selection.get("matched_count")) is int and selection["matched_count"] == len(selectors))


def parse_export(path: Path, row: dict[str, Any], max_bytes: int = EXPORT_CAP_BYTES,
                 source_binding: dict[str, Any] | None = None, std: Path | None = None,
                 group_selectors: list[str] | None = None) -> dict[str, Any]:
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
    if value is None:
        return {"state": "NULL", "outcome": "UNKNOWN"}
    if not isinstance(value, dict):
        return {"state": "WRONG_TOP_LEVEL_TYPE", "outcome": "UNKNOWN"}
    if value.get("schema_version") != "0.1.0" or value.get("run_state") != "COMPLETE":
        return {"state": "INCOMPLETE_OR_SCHEMA_DRIFT", "outcome": "UNKNOWN"}
    if value.get("kani_commit") != TOOL_SHA or value.get("kani_commit_dirty") is not False:
        return {"state": "WRONG_TOOL_BINDING", "outcome": "UNKNOWN"}
    selectors = group_selectors or [row["selector"]]
    if not _selection_matches(value, selectors) or row["selector"] not in selectors:
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    harnesses = value.get("harnesses")
    if (not isinstance(harnesses, list) or len(harnesses) != len(selectors) or
            any(not isinstance(h, dict) or not isinstance(h.get("name"), str) for h in harnesses)):
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    names = [h["name"] for h in harnesses]
    if len(set(names)) != len(names) or set(names) != set(selectors):
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    harness = next(h for h in harnesses if h["name"] == row["selector"])
    binding = source_binding or {}
    file = harness.get("file")
    if (harness.get("is_automatically_generated") is not False or
            harness.get("crate_name") != binding.get("crate") or
            binding.get("selector") != row["selector"] or binding.get("mode") != row["mode"] or
            not isinstance(file, str) or std is None or
            (std / file).resolve() != (std / binding.get("file", "")).resolve() or
            type(harness.get("line")) is not int or
            harness["line"] not in [loc["line"] for loc in binding.get("locations", [])]):
        return {"state": "WRONG_SOURCE_BINDING", "outcome": "UNKNOWN"}
    attrs = harness.get("attributes")
    kind = attrs.get("kind") if isinstance(attrs, dict) else None
    contract = harness.get("contract")
    reported_contract_function = None
    if row["mode"] == "PFC":
        if (not isinstance(kind, dict) or len(kind) != 1 or "ProofForContract" not in kind or
                not isinstance(kind["ProofForContract"], dict) or not isinstance(contract, dict)):
            return {"state": "WRONG_MODE", "outcome": "UNKNOWN"}
        exported_target = kind["ProofForContract"].get("target_fn")
        expected_target = binding.get("target")
        reported_contract_function = contract.get("contracted_function_name")
        # stringify!(TokenStream) changes whitespace, not token boundaries.
        if (not isinstance(exported_target, str) or not isinstance(expected_target, str) or
                _target_tokens(exported_target) is None or
                _target_tokens(exported_target) != _target_tokens(expected_target) or
                not isinstance(reported_contract_function, str) or not reported_contract_function.strip()):
            return {"state": "CONTRACT_TARGET_BINDING_MISMATCH", "outcome": "UNKNOWN",
                    "expected_target": expected_target, "exported_target": exported_target,
                    "contracted_function_name": reported_contract_function}
    elif kind != "Proof" or "contract" not in harness or contract is not None:
        return {"state": "WRONG_MODE", "outcome": "UNKNOWN"}
    config = value.get("configuration")
    if (not isinstance(config, dict) or not isinstance(config.get("checks"), dict) or
            config["checks"].get("assert_contracts") is not False or
            any(config["checks"].get(k) is not True for k in
                ("memory_safety", "overflow", "unwinding", "undefined_function")) or
            config.get("cbmc_args") != ["--object-bits", "12"]):
        return {"state": "WRONG_CONFIGURATION", "outcome": "UNKNOWN"}
    enabled_features = value.get("enabled_unstable_features")
    required_features = set(UNSTABLE) | {"export-json"}
    if (not isinstance(enabled_features, list) or not required_features.issubset(set(enabled_features)) or
            any(feature in enabled_features for feature in ("uninit-checks", "valid-value-checks"))):
        return {"state": "WRONG_UNSTABLE_FEATURE_SET", "outcome": "UNKNOWN"}
    if harness.get("resolved_unwind") != row["unwind"]:
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
    if not isinstance(failures, list) or not isinstance(unsupported, list):
        return {"state": "WRONG_EXPORT_SHAPE", "outcome": "UNKNOWN"}
    bad_fields = ("unreachable", "undetermined", "error", "unknown")
    incomplete = (any(checks.get(key) != [] for key in bad_fields) or
                  checks.get("other") != [] or not isinstance(checks.get("total"), int) or
                  not isinstance(checks.get("success"), int) or
                  not isinstance(covers.get("total"), int) or
                  not isinstance(harness.get("n_properties"), int) or
                  harness.get("n_properties") != checks["total"] + covers["total"])
    if unsupported or incomplete:
        return {"state": "INCOMPLETE_CHECK_INVENTORY", "outcome": "UNKNOWN",
                "failures": failures, "unsupported_constructs": unsupported,
                "checks": checks}
    satisfied = covers.get("satisfied")
    cover_bad = any(covers.get(key) != [] for key in
                    ("unsatisfiable", "unreachable", "undetermined", "error", "unknown", "other"))
    required_covers = row.get("required_covers", [])
    if (not isinstance(satisfied, list) or cover_bad or len(satisfied) < row["required_cover_count"] or
            not set(required_covers).issubset(set(satisfied))):
        return {"state": "COVERAGE_INCOMPLETE", "outcome": "UNKNOWN", "covers": covers}
    outcome = harness.get("outcome")
    is_success = isinstance(outcome, dict) and outcome.get("kind") == "COMPLETED" and outcome.get("verdict") == "SUCCESS"
    is_failure = isinstance(outcome, dict) and outcome.get("kind") == "COMPLETED" and outcome.get("verdict") == "FAILURE"
    if not is_success and not is_failure:
        return {"state": "NOT_COMPLETED", "outcome": "UNKNOWN"}
    named = harness.get("failed_properties")
    if not isinstance(named, list):
        return {"state": "WRONG_EXPORT_SHAPE", "outcome": "UNKNOWN"}
    failed_ids = [prop.get("id") for prop in named if isinstance(prop, dict)]
    if (harness.get("n_failed") != len(failures) or len(failed_ids) != len(failures) or
            set(failed_ids) != set(failures) or checks.get("success") + len(failures) != checks.get("total")):
        return {"state": "INCONSISTENT_PROPERTY_COUNTS", "outcome": "UNKNOWN",
                "failures": failures, "failed_properties": named, "checks": checks}
    named_matches = []
    for prop in named:
        if isinstance(prop, dict):
            label = " ".join(str(prop.get(k, "")) for k in ("id", "description"))
            needle = row.get("failure_description", "")
            if needle and (label == needle or needle in label): named_matches.append(prop)
    if row["expected"] == "SUCCESS":
        accepted = is_success and not failures and harness.get("n_failed") == 0
    else:
        needle = row["failure_description"]
        accepted = (is_failure and len(failures) == 1 and len(named_matches) == 1 and
                    any(needle == label or needle in label for label in
                        (named_matches[0].get("id", ""), named_matches[0].get("description", ""))) and
                    harness.get("n_failed") == 1)
    return {"state": "VALIDATED_OBSERVATION", "outcome": "EXPECTED" if accepted else "UNEXPECTED",
            "expected": row["expected"], "failures": failures, "failed_properties": named,
            "checks": checks, "covers": covers, "checks_success": checks.get("success"),
            "checks_total": checks.get("total"), "satisfied_cover_ids": satisfied,
            "selected_root": harness.get("name"), "selected_mode": kind,
            "expected_target_fn": binding.get("target"),
            "source_binding": binding,
            "reported_contracted_function_name": reported_contract_function,
            "contract_wrapper_correlation": "PENDING_REVIEW",
            "required_success_messages": row.get("required_success_messages", []),
            "success_message_binding": "REVIEW_REQUIRED_SCHEMA_HAS_NO_NAMED_SUCCESS_CHECKS",
            "proof_credit": "PENDING_REVIEW"}


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


def _bounded_log(path: Path, total_bytes: int | None) -> dict[str, Any]:
    """Inline bounded head/tail of the bounded capture, including omissions."""
    if not path.is_file():
        return {"path": path.name, "state": "MISSING", "original_bytes": total_bytes,
                "head": "", "tail": ""}
    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(min(size, 2048))
        stream.seek(max(len(head), size - 2048))
        tail = stream.read(2048)
    return {"path": path.name, "state": "CAPTURED", "original_bytes": total_bytes,
            "captured_bytes": size, "capture_layout": "HEAD_THEN_TAIL",
            "head": head.decode("utf-8", errors="replace"),
            "tail": tail.decode("utf-8", errors="replace"),
            "preview_omitted_bytes": max(0, size - len(head) - len(tail)),
            "capture_omitted_bytes": max(0, total_bytes - size) if total_bytes is not None else None,
            "sha256": sha256(path)}


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


def _run_group(std: Path, tool: Path, out: Path, request: dict[str, Any],
               group: dict[str, Any], phase_deadline: float) -> tuple[list[dict[str, Any]], str | None]:
    dest = out / "groups" / group["id"]
    dest.mkdir(parents=True, exist_ok=True)
    selectors = [row["selector"] for row in group["rows"]]
    export = (dest / "export.json").resolve()
    argv = build_argv(std, tool, selectors, group["unwind"], export)
    results = [{**_row_base(row, "IN_PROGRESS"), "group": group["id"],
                "per_root_rss_kib": None, "per_root_rss_status": "UNKNOWN_NO_EXACT_HARNESS_ATTRIBUTION",
                "proof_credit": "NONE"} for row in group["rows"]]
    receipt = {"schema": "ch8-s1-group-v1", "state": "IN_PROGRESS", "group": group["id"],
               "argv": argv, "selectors": selectors, "variant": group["variant"],
               "unwind": group["unwind"], "proof_credit": "NONE",
               "compile_limit_seconds": COMPILE_SECONDS,
               "group_budget_seconds": COMPILE_SECONDS + sum(r["timeout_seconds"] for r in group["rows"]),
               "std_sha": STD_SHA, "tool_sha": TOOL_SHA,
               "request_sha256": sha256(REQUEST_PATH)}
    patch = None
    fatal = None
    monitor = CompileMonitor(dest / "compile/receipt.json", export, selectors)
    try:
        _write_json(dest / "receipt.json", receipt)
        for result in results:
            _write_json(out / result["id"] / "receipt.json", result)
        source_before = verify_source(std, tool, request)
        before = binary_fingerprints(tool, {})
        if not before["required_hashes_present"]:
            raise RunnerError("missing required tool binary hash")
        memory = group_memory_budget()
        patch, variant_files = _run_variant(std, group["variant"], request)
        receipt.update(source_before=source_before, tool_fingerprints_before=before,
                       memory=memory, source_under_test={"base_std_sha": STD_SHA,
                       "variant": group["variant"], "file_sha256": {**request["changed_file_sha256"], **variant_files},
                       "patch_sha256": sha256(patch) if patch is not None else None})
        child_env = ci_env(std)
        receipt["cargo_target_dir"] = child_env["CARGO_TARGET_DIR"]
        remaining = phase_deadline-time.monotonic()-PHASE_CLEANUP_MARGIN
        if remaining <= 0:
            raise RunnerError("phase_seconds_cap_before_group")
        # Group envelope is compile + all row budgets; the separate phase deadline is authoritative.
        timeout = min(receipt["group_budget_seconds"], remaining)
        receipt.update(timeout_seconds=timeout, phase_limited=timeout < receipt["group_budget_seconds"])
        export.unlink(missing_ok=True)
        for stream in ("stdout", "stderr"):
            (dest / (stream+".log")).write_bytes(b"")
        _write_json(dest / "receipt.json", receipt)
        invocation = execute(argv, std.resolve(), dest, timeout,
                             rss_cap_kib=memory["group_cap_kib"], stdout_cap=STDOUT_CAP_BYTES,
                             stderr_cap=STDERR_CAP_BYTES, export_path=export, export_cap=EXPORT_CAP_BYTES,
                             env=child_env, capture_tail=True, compile_monitor=monitor)
        receipt["execution"] = invocation
        # Synthetic execution substitutes must also supply a bound compile receipt.
        if monitor.receipt["state"] != "COMPLETE":
            raise RunnerError("compilation_not_complete")
        if (invocation.get("termination_reason") or invocation.get("timed_out") or
                invocation.get("signal") or invocation.get("stdout_truncated") or invocation.get("stderr_truncated")):
            raise RunnerError("group_execution_interrupted_or_capped")
        raw = json.loads(export.read_text()) if export.is_file() and export.stat().st_size <= EXPORT_CAP_BYTES else None
        if not _selection_matches(raw, selectors):
            raise RunnerError("invalid_group_export")
        harnesses = raw.get("harnesses")
        if (not isinstance(harnesses, list) or len(harnesses) != len(selectors) or
                any(not isinstance(h, dict) or not isinstance(h.get("name"), str) for h in harnesses) or
                len({h["name"] for h in harnesses}) != len(selectors) or
                {h["name"] for h in harnesses} != set(selectors)):
            raise RunnerError("invalid_group_harness_inventory")
        all_success = all(h.get("outcome") == {"kind": "COMPLETED", "verdict": "SUCCESS"} for h in harnesses)
        if invocation.get("original_exit_code") != (0 if all_success else 1):
            raise RunnerError("group_exit_export_mismatch")
        after = binary_fingerprints(tool, raw)
        receipt["tool_fingerprints_after"] = after
        if (not after["required_hashes_present"] or
                {k:v.get("sha256") for k,v in before["binaries"].items()} !=
                {k:v.get("sha256") for k,v in after["binaries"].items()}):
            raise RunnerError("tool_binary_drift")
        receipt["export_sha256"] = sha256(export)
        for row, result in zip(group["rows"], results):
            parsed = parse_export(export, row, source_binding=request["source_bindings"][row["id"]],
                                  std=std.resolve(), group_selectors=selectors)
            result.update(status="OBSERVED", outcome=parsed["outcome"], export=parsed,
                          group_export_sha256=receipt["export_sha256"],
                          group_original_exit=invocation.get("original_exit_code"),
                          original_exit=None, original_exit_scope="PER_ROOT_DRIVER_EXIT_UNAVAILABLE_IN_BATCH",
                          signal=invocation.get("signal"), group_rss_peak_kib=invocation.get("rss_peak_kib"),
                          group_rss_cap_kib=memory["group_cap_kib"],
                          root_timeout_seconds=MAX_ROW_SECONDS,
                          timeout_scope="STOCK_KANI_CBMC_TIMEOUT_NOT_FULL_INSTRUMENTATION_WALL",
                          diagnostics=f"groups/{group['id']}")
    except BaseException as exc:
        fatal = f"{type(exc).__name__}: {exc}"
        receipt.update(state="FAILED", reason=fatal)
        for result in results:
            result.update(status="UNKNOWN", outcome="UNKNOWN", reason=fatal)
    finally:
        if patch is not None:
            try:
                subprocess.run(["git", "-C", str(std), "apply", "--reverse", "--check", str(patch)], check=True)
                subprocess.run(["git", "-C", str(std), "apply", "--reverse", str(patch)], check=True)
            except Exception as exc:
                fatal = f"variant_cleanup_failed: {exc}"
        try:
            source_after = verify_source(std, tool, request)
            receipt["source_after"] = source_after
            if source_after != receipt.get("source_before"):
                raise RunnerError("source_identity_drift")
        except Exception as exc:
            fatal = f"source_drift: {exc}"
        if fatal:
            receipt.update(state="FAILED", reason=fatal)
            for result in results:
                result.update(outcome="UNKNOWN", reason=fatal)
        else:
            receipt["state"] = "COMPLETE"
        execution = receipt.get("execution", {})
        if monitor.receipt["state"] == "IN_PROGRESS":
            monitor.finish({**execution, "runner_error": fatal or "NO_COMPLETION"}, {})
        for stream in ("stdout", "stderr"):
            receipt[stream] = _bounded_log(dest / (stream+".log"), execution.get(stream+"_bytes"))
        receipt["compilation"] = "compile/receipt.json"
        for result in results:
            result.update(group_original_exit=execution.get("original_exit_code"), signal=execution.get("signal"),
                          group_rss_peak_kib=execution.get("rss_peak_kib"),
                          stdout=receipt["stdout"], stderr=receipt["stderr"],
                          diagnostic_scope="SHARED_GROUP_CAPTURE_NOT_PER_ROOT")
            _write_json(out / result["id"] / "receipt.json", result)
        _write_json(dest / "receipt.json", receipt)
    if _artifact_size(out) > ARTIFACT_CAP_BYTES:
        fatal = "artifact_bytes_cap"
        receipt.update(state="FAILED", reason=fatal)
        for result in results:
            result.update(outcome="UNKNOWN", reason=fatal)
            _write_json(out / result["id"] / "receipt.json", result)
        _write_json(dest / "receipt.json", receipt)
    return results, fatal


def run_rows(std: Path, tool: Path, out: Path, request: dict[str, Any]) -> int:
    out.mkdir(parents=True, exist_ok=True)
    phase_started = time.monotonic()
    deadline = phase_started+PHASE_SECONDS
    groups = group_rows(request["rows"])
    results: dict[str, dict[str, Any]] = {}
    fatal = None
    for group in groups:
        if _artifact_size(out) > ARTIFACT_CAP_BYTES:
            fatal = "artifact_bytes_cap"
        if deadline-time.monotonic() <= PHASE_CLEANUP_MARGIN:
            fatal = fatal or "phase_seconds_cap_before_group"
        if not fatal:
            observed, fatal = _run_group(std, tool, out, request, group, deadline)
            results.update((r["id"], r) for r in observed)
        else:
            for row in group["rows"]:
                result = {**_row_base(row), "reason": fatal, "group": group["id"], "proof_credit": "NONE"}
                results[row["id"]] = result
                _write_json(out / row["id"] / "receipt.json", result)
        _write_json(out / "receipt.json", {"state": "STOPPED" if fatal else "IN_PROGRESS",
                    "stop_reason": fatal, "proof_credit": "NONE", "rows": list(results.values())})
    ordered = [results[row["id"]] for row in request["rows"]]
    unknown = any(r.get("outcome") != "EXPECTED" for r in ordered)
    _write_json(out / "receipt.json", {"state": "STOPPED" if fatal else "COMPLETE_WITH_UNKNOWN" if unknown else "COMPLETE",
                "stop_reason": fatal, "std_sha": STD_SHA, "tool_sha": TOOL_SHA,
                "phase_elapsed_seconds": round(time.monotonic()-phase_started, 3),
                "proof_credit": "NONE", "per_root_rss_status": "UNKNOWN_NO_EXACT_HARNESS_ATTRIBUTION", "rows": ordered})
    return 1 if fatal or unknown else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("check-source", "run"):
        p = sub.add_parser(command)
        p.add_argument("--std", required=True, type=Path)
        p.add_argument("--tool", required=True, type=Path)
        if command != "check-source": p.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        request = load_request()
        if args.command == "check-source":
            print(json.dumps(verify_source(args.std, args.tool, request), sort_keys=True))
        else:
            return run_rows(args.std, args.tool, args.out, request)
    except Exception as exc:
        print(f"runner: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
