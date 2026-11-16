# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
#!/usr/bin/env python3
"""Offline, bounded CI runner for the frozen Challenge 8 Profiles OFF request.

Receipts are observations only. They never grant proof credit. This module is
also deliberately usable with synthetic fixtures; it does not install tools.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import threading
import time
import tomllib
from typing import Any

HERE = Path(__file__).resolve().parent
REQUEST_PATH = HERE / "CI-REQUEST.json"
STD_SHA = "9fa2f7f97760584f38738909625c064006d8a936"
STD_TREE = "2faa473adeb0172e0f5a5e75fa2d759b20902e6d"
TOOL_SHA = "0aac16ef62da9e9d5645782d458593e5d78143ba"
TOOL_TREE = "9d8bc9312bf955ef126d32b819b3cd0ed105ed2b"
TARGET = "x86_64-unknown-linux-gnu"
MAX_ROW_SECONDS = 600
COMPILE_SECONDS = 900
GROUP_RSS_MAX_KIB = 12 * 1024 * 1024
COMPILE_LOG_BYTES = 65536
PHASE_SECONDS = 8400
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
        if not isinstance(rid, str) or not rid or rid in seen_ids or "/" in rid or rid in (".", ".."):
            raise RunnerError("missing, unsafe or duplicate row id")
        if not isinstance(selector, str) or not selector:
            raise RunnerError("missing exact selector")
        mode = row.get("mode")
        if not isinstance(mode, str) or not (mode == "Original" or mode.startswith(("PFC:", "Replace:"))):
            raise RunnerError(f"invalid mode for {rid}")
        if row.get("cfg") not in ([], ["kani_smallsort_controls"]):
            raise RunnerError(f"invalid cfg for {rid}")
        if row.get("unwind") is not None and (type(row["unwind"]) is not int or row["unwind"] < 1):
            raise RunnerError(f"invalid unwind for {rid}")
        if row.get("expected") not in ("SUCCESS", "DETECTED"):
            raise RunnerError(f"invalid expected result for {rid}")
        if row.get("timeout_seconds") != MAX_ROW_SECONDS:
            raise RunnerError(f"timeout outside fixed cap for {rid}")
        descriptions = row.get("allowed_failure_descriptions")
        if not isinstance(descriptions, list) or any(not isinstance(d, str) or not d for d in descriptions):
            raise RunnerError(f"invalid failure descriptions for {rid}")
        if (row["expected"] == "DETECTED") != bool(descriptions):
            raise RunnerError(f"negative row lacks named failure descriptions: {rid}")
        if mode.startswith("Replace:") and row.get("leaf_companion") not in seen_ids:
            raise RunnerError(f"consumer precedes matching leaf: {rid}")
        seen_ids.add(rid)
        row["profile_mode"] = mode
        row["mode"] = "PFC" if mode.startswith("PFC:") else "Original"
        row["variant"] = "production"
        row["required_cover_count"] = 0  # every emitted cover, count bound below
    if len(rows) != 62:
        raise RunnerError("fixed manifest must contain 62 rows")
    manifest = path.parent / "manifest.json"
    if sha256(manifest) != request.get("manifest_sha256"):
        raise RunnerError("manifest SHA drift")
    original = json.loads(manifest.read_text())
    if not isinstance(original, list) or len(original) != len(rows):
        raise RunnerError("manifest length drift")
    for raw, normalized in zip(original, rows):
        expected_row = {k: v for k, v in normalized.items() if k not in
                        ("profile_mode", "variant", "required_cover_count")}
        expected_row["mode"] = normalized["profile_mode"]
        if raw != expected_row:
            raise RunnerError("manifest row drift")
    for key in ("changed_file_sha256", "variants"):
        if not isinstance(request.get(key), dict):
            raise RunnerError(f"missing request {key} object")
    budgets = request.get("budgets")
    if not isinstance(budgets, dict) or any(budgets.get(key) != val for key, val in {
            "phase_seconds": PHASE_SECONDS, "rss_kib": RSS_CAP_KIB,
            "stdout_bytes": STDOUT_CAP_BYTES, "stderr_bytes": STDERR_CAP_BYTES,
            "export_bytes": EXPORT_CAP_BYTES, "artifact_bytes": ARTIFACT_CAP_BYTES,
            "row_seconds": MAX_ROW_SECONDS}.items()):
        raise RunnerError("request budget mismatch")
    return request


def _source_root(std: Path, tool: Path) -> None:
    std, tool = std.resolve(), tool.resolve()
    if std == tool or std.parent != tool.parent:
        raise RunnerError("std and tool source checkouts must be sibling directories")
    control = HERE.resolve().parent
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
    # Variants may describe test overlays; their path/hash are checked when selected.
    return {"std_sha": STD_SHA, "std_tree": STD_TREE, "tool_sha": TOOL_SHA,
            "tool_tree": TOOL_TREE, "changed_file_sha256": request["changed_file_sha256"]}


def build_argv(std: Path, tool: Path, selectors: list[str] | str, unwind: int | None, export: Path) -> list[str]:
    # Source attributes own unwind. Never inject a default/unwind override.
    argv = [str((tool.resolve() / "scripts/kani")), "verify-std", "-Z", "unstable-options",
            str(std.resolve() / "library")]
    for feature in UNSTABLE + ("export-json",):
        argv += ["-Z", feature]
    if isinstance(selectors, str):
        selectors = [selectors]
    for selector in selectors:
        argv += ["--harness", selector]
    argv += ["--no-assert-contracts", "--exact", "--jobs", "1",
             "--harness-timeout", "600s", "--target-dir", str(export.resolve().parent / "target"),
             "--export-json", str(export.resolve()), "--output-format=regular",
             "--cbmc-args", "--object-bits", "12"]
    return argv


def ci_env(row: dict[str, Any] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    if env.get("RUSTFLAGS", "").strip() or env.get("CARGO_ENCODED_RUSTFLAGS", "").strip():
        raise RunnerError("refusing inherited RUSTFLAGS outside frozen per-row cfg")
    cfg = (row or {}).get("cfg", [])
    if cfg not in ([], ["kani_smallsort_controls"]):
        raise RunnerError("invalid row cfg")
    env["RUSTFLAGS"] = " ".join("--cfg " + flag for flag in cfg)
    env["KANI_TOML_FILE"] = str(HERE / "kani-version.toml")
    return env


def _read_pipe(pipe, target: Path, cap: int, state: dict[str, Any], lock: threading.Lock, key: str) -> None:
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
            if room:
                output.write(data[:room])
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


class BatchCapture:
    """Bound streams by harness markers; markers never establish proof binding.

    Compilation includes linking/instrumentation before the first harness marker,
    so its separate deadline conservatively covers more than cargo compilation.
    stderr uses the latest stdout marker; exact per-row stderr/RSS attribution is
    UNKNOWN (pipes may be drained at different times). Caps remain enforced.
    """
    def __init__(self, group_out: Path, root: Path, rows: list[dict[str, Any]]):
        self.out, self.root = group_out, root
        self.selectors = {r["selector"]: r["id"] for r in rows}
        self.current = None
        self.first_harness_at = None
        self.started = time.monotonic()
        self.lock = threading.Lock()
        self.pending = b""
        self.counts: dict[str, dict[str, int]] = {}
        self.compile = {k: {"head": b"", "tail": b"", "bytes": 0} for k in ("stdout", "stderr")}
        self.reason = None
        self.order: list[str] = []

    def _write(self, key: str, data: bytes) -> None:
        if self.current is None:
            item = self.compile[key]
            item["bytes"] += len(data)
            room = COMPILE_LOG_BYTES // 2 - len(item["head"])
            item["head"] += data[:max(0, room)]
            item["tail"] = (item["tail"] + data)[-COMPILE_LOG_BYTES // 2:]
            return
        counts = self.counts.setdefault(self.current, {"stdout": 0, "stderr": 0})
        cap = STDOUT_CAP_BYTES if key == "stdout" else STDERR_CAP_BYTES
        room = max(0, cap - counts[key])
        counts[key] += len(data)
        if len(data) > room:
            self.reason = "row_" + key + "_cap"
        dest = self.root / self.current / (key + ".log")
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("ab") as f:
            f.write(data[:room])

    def feed(self, key: str, data: bytes) -> None:
        with self.lock:
            if key == "stderr":
                self._write(key, data)
                return
            self.pending += data
            while b"\n" in self.pending or len(self.pending) > 8192:
                n = self.pending.find(b"\n") + 1
                if n == 0:
                    n = 8192
                line, self.pending = self.pending[:n], self.pending[n:]
                if line.startswith(b"Checking harness ") and line.rstrip().endswith(b"..."):
                    name = line.strip()[len(b"Checking harness "):-3].decode("utf-8", errors="replace")
                    rid = self.selectors.get(name)
                    if rid is None or rid in self.order:
                        self.reason = "unexpected_or_duplicate_harness_marker"
                    else:
                        self.current = rid
                        self.order.append(rid)
                        if self.first_harness_at is None:
                            self.first_harness_at = time.monotonic()
                self._write(key, line)

    def poll(self) -> tuple[str | None, bool]:
        with self.lock:
            return self.reason, self.first_harness_at is not None

    def finish(self) -> dict[str, Any]:
        with self.lock:
            if self.pending:
                self._write("stdout", self.pending)
                self.pending = b""
            logs = {}
            for key, item in self.compile.items():
                path = self.out / ("compile-" + key + ".log")
                # Deliberate bounded head/tail, with original byte count in receipt.
                path.write_bytes(item["head"] + b"\n[bounded tail; may overlap head]\n" + item["tail"])
                logs[key] = {"bytes": item["bytes"], "path": path.name, "sha256": sha256(path),
                             "retention": "BOUNDED_HEAD_AND_TAIL", "retained_limit": COMPILE_LOG_BYTES + 64}
            return {"state": "PRE_HARNESS_COMPLETE" if self.first_harness_at is not None else "UNKNOWN",
                    "elapsed_seconds": round((self.first_harness_at or time.monotonic()) - self.started, 3),
                    "limit_seconds": COMPILE_SECONDS, "logs": logs,
                    "boundary": "FIRST_CHECKING_HARNESS_AFTER_STD_BUILD_LINK_AND_INSTRUMENTATION",
                    "boundary_assurance": "SOURCE_REPORTED_MARKER_NOT_PROOF",
                    "harness_marker_order": self.order, "row_output_bytes": self.counts,
                    "stderr_attribution": "LATEST_STDOUT_MARKER_EXACT_PER_ROW_UNKNOWN"}


def _read_batch_pipe(pipe, capture: BatchCapture, key: str) -> None:
    try:
        for data in iter(lambda: pipe.read(65536), b""):
            capture.feed(key, data)
    except Exception as exc:
        with capture.lock:
            capture.reason = f"capture_error: {type(exc).__name__}: {exc}"
    finally:
        pipe.close()


def _cbmc_rss_kib(pgid: int) -> int:
    """Sum active CBMC RSS in the invocation (jobs=1); no guessed row identity."""
    total = 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            tail = stat[stat.rfind(")") + 2:].split()
            if int(tail[2]) != pgid or (entry / "comm").read_text().strip() != "cbmc":
                continue
            for line in (entry / "status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    total += int(line.split()[1]); break
        except (OSError, ValueError, IndexError):
            continue
    return total


def group_rss_cap() -> int:
    values = [int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines()
              if line.startswith("MemAvailable:")]
    if not values:
        raise RunnerError("available memory unknown")
    available = values[0]
    # Also respect the runner's cgroup, including ancestor limits.
    try:
        rel = next(line.split("::", 1)[1] for line in Path("/proc/self/cgroup").read_text().splitlines()
                   if line.startswith("0::"))
        base = Path("/sys/fs/cgroup")
        node = base / rel.lstrip("/")
        while node == base or base in node.parents:
            limit = node / "memory.max"
            current = node / "memory.current"
            if limit.is_file() and current.is_file() and limit.read_text().strip() != "max":
                available = min(available, (int(limit.read_text()) - int(current.read_text())) // 1024)
            if node == base:
                break
            node = node.parent
    except (OSError, ValueError, StopIteration) as exc:
        raise RunnerError(f"cgroup memory availability unknown: {exc}") from exc
    cap = min(GROUP_RSS_MAX_KIB, available - 2 * 1024 * 1024)
    if cap <= 0:
        raise RunnerError("insufficient available memory with 2 GiB reserve")
    return cap


def execute(argv: list[str], cwd: Path, out: Path, timeout: int,
            rss_cap_kib: int = RSS_CAP_KIB, stdout_cap: int = STDOUT_CAP_BYTES,
            stderr_cap: int = STDERR_CAP_BYTES, export_path: Path | None = None,
            export_cap: int = EXPORT_CAP_BYTES, env: dict[str, str] | None = None,
            batch_rows: list[dict[str, Any]] | None = None,
            receipt_root: Path | None = None) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    info: dict[str, Any] = {"original_exit_code": None, "signal": None, "timed_out": False,
                            "rss_peak_kib": 0, "rss_status": "SAMPLED_PROCESS_GROUP",
                            "output_truncated": False, "output_bytes": 0}
    state: dict[str, Any] = {"stdout_cap": False, "stderr_cap": False,
                             "stdout_kept": 0, "stderr_kept": 0,
                             "stdout_bytes": 0, "stderr_bytes": 0}
    lock = threading.Lock()
    capture = BatchCapture(out, receipt_root, batch_rows) if batch_rows and receipt_root else None
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                start_new_session=True, bufsize=0)
    except OSError as exc:
        info.update(runner_error=f"exec failed: {exc}", elapsed_seconds=time.monotonic() - started)
        if capture is not None:
            info["compilation"] = capture.finish()
            _write_json(out / "compile-receipt.json", info["compilation"])
        return info
    threads = [threading.Thread(target=_read_pipe, args=(proc.stdout, out / "stdout.log", stdout_cap,
                                                         state, lock, "stdout"), daemon=True),
               threading.Thread(target=_read_pipe, args=(proc.stderr, out / "stderr.log", stderr_cap,
                                                         state, lock, "stderr"), daemon=True)]
    if capture is not None:
        threads = [threading.Thread(target=_read_batch_pipe, args=(proc.stdout, capture, "stdout"), daemon=True),
                   threading.Thread(target=_read_batch_pipe, args=(proc.stderr, capture, "stderr"), daemon=True)]
    info["cbmc_rss_peak_kib"] = 0
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
            if capture is not None:
                cbmc_rss = _cbmc_rss_kib(proc.pid)
                info["cbmc_rss_peak_kib"] = max(info["cbmc_rss_peak_kib"], cbmc_rss)
                if cbmc_rss > RSS_CAP_KIB:
                    killed_for = "cbmc_rss_cap"; break
                reason, compiled = capture.poll()
                if reason:
                    killed_for = reason; break
                if not compiled and time.monotonic() - started >= COMPILE_SECONDS:
                    killed_for = "compile_timeout"; break
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
    if capture is not None:
        compile_receipt = capture.finish()
        if capture.reason and not info.get("termination_reason"):
            info["termination_reason"] = capture.reason
        if compile_receipt["elapsed_seconds"] > COMPILE_SECONDS:
            info["termination_reason"] = info.get("termination_reason") or "compile_timeout"
        info["output_bytes"] = (sum(stream["bytes"] for stream in compile_receipt["logs"].values()) +
                                sum(sum(counts.values()) for counts in compile_receipt["row_output_bytes"].values()))
        info["stdout_truncated"] = any(counts["stdout"] > STDOUT_CAP_BYTES
                                       for counts in compile_receipt["row_output_bytes"].values())
        info["stderr_truncated"] = any(counts["stderr"] > STDERR_CAP_BYTES
                                       for counts in compile_receipt["row_output_bytes"].values())
        info["output_truncated"] = info["stdout_truncated"] or info["stderr_truncated"]
        info["compilation"] = compile_receipt
        _write_json(out / "compile-receipt.json", compile_receipt)
        info["per_row_rss"] = "UNKNOWN"
        info["cbmc_rss_cap_kib"] = RSS_CAP_KIB
        info["group_rss_cap_kib"] = rss_cap_kib
    info["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return info


def _parse_export(path: Path, row: dict[str, Any], max_bytes: int = EXPORT_CAP_BYTES,
                 contract_binding: dict[str, str] | None = None,
                 group_rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
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
    if value.get("run_state") == "NOT_RUN":
        return {"state": "NOT_RUN", "outcome": "UNKNOWN"}
    if value.get("schema_version") != "0.1.0" or value.get("run_state") != "COMPLETE":
        return {"state": "INCOMPLETE_OR_SCHEMA_DRIFT", "outcome": "UNKNOWN"}
    if value.get("kani_commit") != TOOL_SHA or value.get("kani_commit_dirty") is not False:
        return {"state": "WRONG_TOOL_BINDING", "outcome": "UNKNOWN"}
    if value.get("target") != TARGET:
        return {"state": "WRONG_TARGET", "outcome": "UNKNOWN"}
    if value.get("harness_timeout_s") != MAX_ROW_SECONDS:
        return {"state": "WRONG_HARNESS_TIMEOUT", "outcome": "UNKNOWN"}
    selected = [r["selector"] for r in (group_rows or [row])]
    selection = value.get("harness_selection")
    harnesses = value.get("harnesses")
    if (not isinstance(selection, dict) or selection.get("requested_filters") != selected or
            selection.get("exact") is not True or selection.get("unmatched_filters") != [] or
            selection.get("matched_count") != len(selected) or len(set(selected)) != len(selected) or
            not isinstance(harnesses, list) or len(harnesses) != len(selected) or
            any(not isinstance(h, dict) or not isinstance(h.get("name"), str) for h in harnesses) or
            sorted(h["name"] for h in harnesses) != sorted(selected)):
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    harness = next(h for h in harnesses if h["name"] == row["selector"])
    if len(json.dumps(harness).encode()) > EXPORT_CAP_BYTES:
        return {"state": "ROW_EXPORT_CAP", "outcome": "UNKNOWN"}
    if harness.get("is_automatically_generated") is not False:
        return {"state": "WRONG_GENERATION_MODE", "outcome": "UNKNOWN"}
    source_file = row.get("source_file")
    if source_file and (not isinstance(harness.get("file"), str) or
                        not harness["file"].replace("\\", "/").endswith("/" + source_file) and
                        harness["file"].replace("\\", "/") != source_file):
        return {"state": "WRONG_SOURCE_FILE", "outcome": "UNKNOWN"}
    if isinstance(harness.get("outcome"), dict) and harness["outcome"].get("kind") == "NOT_RUN":
        return {"state": "NOT_RUN", "outcome": "UNKNOWN"}
    reported_outcome = harness.get("outcome")
    if not isinstance(reported_outcome, dict) or reported_outcome.get("kind") != "COMPLETED":
        return {"state": "HARNESS_NOT_COMPLETED", "outcome": "UNKNOWN", "harness_outcome": reported_outcome}
    attrs = harness.get("attributes")
    kind = attrs.get("kind") if isinstance(attrs, dict) else None
    contract = harness.get("contract")
    reported_contract_function = None
    if row["mode"] == "PFC":
        if (not isinstance(kind, dict) or len(kind) != 1 or "ProofForContract" not in kind or
                not isinstance(kind["ProofForContract"], dict) or contract is None):
            return {"state": "WRONG_MODE", "outcome": "UNKNOWN"}
        exported_target = kind["ProofForContract"].get("target_fn")
        # The selected export entry owns binding. No global list or invented wrapper mapping.
        expected_target = (contract_binding or {}).get(row["selector"])
        if "profile_mode" in row:
            expected = row["profile_mode"].split(":", 1)[1]
            if expected == "concrete_forwarder":
                expected = {"stable_cell_n2": "stable_cell", "unstable_byte_n2": "unstable_byte",
                            "freeze_noncopy_n2": "freeze_noncopy"}[row["id"]]
            if (not isinstance(exported_target, str) or
                    not exported_target.split("::<", 1)[0].endswith("::" + expected)):
                return {"state": "SOURCE_STAGE_TARGET_MISMATCH", "outcome": "UNKNOWN"}
        reported_contract_function = contract.get("contracted_function_name") if isinstance(contract, dict) else None
        if (not isinstance(exported_target, str) or not exported_target.strip() or
                expected_target is not None and exported_target != expected_target or
                not isinstance(reported_contract_function, str) or not reported_contract_function.strip()):
            return {"state": "CONTRACT_TARGET_BINDING_MISMATCH", "outcome": "UNKNOWN",
                    "exported_target": exported_target,
                    "contracted_function_name": reported_contract_function}
    elif kind != "Proof":
        return {"state": "WRONG_MODE", "outcome": "UNKNOWN"}
    config = value.get("configuration")
    if (not isinstance(config, dict) or not isinstance(config.get("checks"), dict) or
            config["checks"].get("assert_contracts") is not False or
            any(config["checks"].get(k) is not True for k in
                ("memory_safety", "overflow", "unwinding", "undefined_function", "assertion_reach_checks")) or
            any(config["checks"].get(k) is not False for k in
                ("prove_safety_only", "ignore_global_asm", "extra_pointer_checks")) or
            config.get("coverage_enabled") is not False or
            config.get("cbmc_args") != ["--object-bits", "12"]):
        return {"state": "WRONG_CONFIGURATION", "outcome": "UNKNOWN"}
    enabled_features = value.get("enabled_unstable_features")
    required_features = set(UNSTABLE) | {"export-json"}
    if (not isinstance(enabled_features, list) or any(not isinstance(f, str) for f in enabled_features) or not required_features.issubset(set(enabled_features)) or
            any(feature in enabled_features for feature in ("uninit-checks", "valid-value-checks"))):
        return {"state": "WRONG_UNSTABLE_FEATURE_SET", "outcome": "UNKNOWN"}
    if "resolved_unwind" not in harness or harness["resolved_unwind"] != row["unwind"]:
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
    if (not isinstance(satisfied, list) or any(not isinstance(x, str) for x in satisfied) or
            len(set(satisfied)) != len(satisfied) or len(satisfied) != covers["total"] or
            cover_bad or len(satisfied) < row["required_cover_count"] or
            not set(required_covers).issubset(set(satisfied))):
        return {"state": "COVERAGE_INCOMPLETE", "outcome": "UNKNOWN", "covers": covers}
    outcome = harness.get("outcome")
    is_success = isinstance(outcome, dict) and outcome.get("kind") == "COMPLETED" and outcome.get("verdict") == "SUCCESS"
    is_failure = isinstance(outcome, dict) and outcome.get("kind") == "COMPLETED" and outcome.get("verdict") == "FAILURE"
    named = harness.get("failed_properties")
    if not isinstance(named, list):
        return {"state": "WRONG_EXPORT_SHAPE", "outcome": "UNKNOWN"}
    failed_ids = [prop.get("id") for prop in named if isinstance(prop, dict)]
    if (harness.get("n_failed") != len(failures) or len(named) != len(failures) or len(failed_ids) != len(failures) or
            set(failed_ids) != set(failures) or checks.get("success") + len(failures) != checks.get("total")):
        return {"state": "INCONSISTENT_PROPERTY_COUNTS", "outcome": "UNKNOWN",
                "failures": failures, "failed_properties": named, "checks": checks}
    if row["expected"] == "SUCCESS":
        accepted = is_success and not failures and harness.get("n_failed") == 0
    else:
        descriptions = row.get("allowed_failure_descriptions", [row.get("failure_description", "")])
        if any(d.startswith("<generated modifies") for d in descriptions):
            return {"state": "FRAME_BINDING_REVIEW_REQUIRED", "outcome": "UNKNOWN",
                    "failures": failures, "failed_properties": named, "checks": checks, "covers": covers,
                    "reason": "Generated modifies property identity must be independently bound; never guessed"}
        matched = [sum(isinstance(p.get("description"), str) and d in p["description"]
                       for p in named if isinstance(p, dict)) for d in descriptions]
        accepted = (is_failure and len(failures) == len(descriptions) and
                    matched == [1] * len(descriptions) and
                    all(sum(d in p.get("description", "") for d in descriptions) == 1 for p in named))
    return {"state": "VALIDATED_OBSERVATION", "outcome": "EXPECTED" if accepted else "UNEXPECTED",
            "expected": row["expected"], "failures": failures, "failed_properties": named,
            "checks": checks, "covers": covers, "checks_success": checks.get("success"),
            "checks_total": checks.get("total"), "satisfied_cover_ids": satisfied,
            "selected_root": harness.get("name"), "selected_mode": kind,
            "export_target_fn": exported_target if row["mode"] == "PFC" else None,
            "is_automatically_generated": harness["is_automatically_generated"],
            "harness_outcome": outcome,
            "reported_contracted_function_name": reported_contract_function,
            "contract_wrapper_correlation": "PENDING_REVIEW",
            "required_success_messages": row.get("required_success_messages", []),
            "success_message_binding": "REVIEW_REQUIRED_SCHEMA_HAS_NO_NAMED_SUCCESS_CHECKS",
            "proof_credit": "PENDING_REVIEW"}


def parse_export(path: Path, row: dict[str, Any], max_bytes: int = EXPORT_CAP_BYTES,
                 contract_binding: dict[str, str] | None = None,
                 group_rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    try:
        return _parse_export(path, row, max_bytes, contract_binding, group_rows)
    except (TypeError, KeyError, ValueError, AttributeError) as exc:
        return {"state": "WRONG_EXPORT_SHAPE", "outcome": "UNKNOWN",
                "original_exception": f"{type(exc).__name__}: {exc}"}


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def binary_fingerprints(tool: Path, export: dict[str, Any]) -> dict[str, Any]:
    candidates = {"kani_driver": tool / "target/kani/bin/kani-driver",
                  "kani_compiler": tool / "target/kani/bin/kani-compiler"}
    candidates["toolchain_config"] = tool / "rust-toolchain.toml"
    # build-dev has no bundle version records. Resolve the actual pinned rustc
    # without invoking it, only on CI (synthetic tests mock this lookup).
    resolution: dict[str, Any] = {}
    try:
        channel = tomllib.loads((tool / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        found = subprocess.run(["rustup", "which", "--toolchain", channel, "rustc"],
                               cwd=tool, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=10, check=False)
        resolution = {"argv": ["rustup", "which", "--toolchain", channel, "rustc"],
                      "original_exit": found.returncode, "stderr": found.stderr[:4096]}
        if found.returncode == 0 and found.stdout.strip():
            candidates["rustc"] = Path(found.stdout.strip()).resolve()
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired) as exc:
        resolution = {"original_exception": f"{type(exc).__name__}: {exc}"}
    cbmc = shutil.which("cbmc")
    if cbmc:
        candidates["cbmc"] = Path(cbmc)
    tools = export.get("tools") if isinstance(export, dict) else None
    fingerprints = {}
    for name, path in candidates.items():
        fingerprints[name] = {"path": str(path), "sha256": sha256(path) if path.is_file() else None}
    required = all(fingerprints.get(key, {}).get("sha256") for key in ("kani_driver", "kani_compiler", "cbmc", "rustc"))
    return {"binaries": fingerprints, "required_hashes_present": required,
            "reported_versions": tools if isinstance(tools, dict) else None,
            "target": export.get("target") if isinstance(export, dict) else None,
            "expected_target": TARGET, "rustc_resolution": resolution}


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


def batch_groups(rows: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Only cfg/RUSTFLAGS differ in this frozen OFF request; unwind is an attribute."""
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for row in rows:
        if row.get("variant", "production") != "production":
            raise RunnerError("batch request only admits frozen production source")
        key = (tuple(row["cfg"]), ci_env(row)["RUSTFLAGS"])
        groups.setdefault(key, []).append(row)
    for group in groups.values():
        selectors = [row["selector"] for row in group]
        if len(set(selectors)) != len(selectors):
            raise RunnerError("duplicate selector in batch")
    return list(groups.values())


def _consumer_gates(rows: list[dict[str, Any]], results: dict[str, dict[str, Any]], out: Path) -> None:
    # Kani sorts harnesses by source location, not CLI order. Admit consumers only
    # after their real-body leaf's row observation has passed, in manifest order.
    seen: set[str] = set()
    for row in rows:
        result = results[row["id"]]
        leaf = row.get("leaf_companion") if row.get("profile_mode", "").startswith("Replace:") else None
        if leaf:
            prior = results.get(leaf)
            if leaf not in seen or not prior or prior.get("outcome") != "EXPECTED":
                result.update(outcome="UNKNOWN", reason="matching_leaf_not_accepted")
            else:
                result["consumer_gate"] = {"leaf": leaf,
                    "leaf_receipt_sha256": sha256(out / leaf / "receipt.json"),
                    "assurance": "POST_BATCH_VALIDATED_OBSERVATION_ONLY_INDEPENDENT_PROOF_CREDIT_PENDING"}
        _write_json(out / row["id"] / "receipt.json", result)
        seen.add(row["id"])


def run_rows(std: Path, tool: Path, out: Path, request: dict[str, Any]) -> int:
    std, tool, out = std.resolve(), tool.resolve(), out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    phase_started = time.monotonic()
    results = {row["id"]: _row_base(row) for row in request["rows"]}
    fatal = None
    group_receipts = []
    try:
        verify_source(std, tool, request)
        groups = batch_groups(request["rows"])
        if (out / "groups").exists() or any((out / row["id"] / "receipt.json").exists() for row in request["rows"]):
            raise RunnerError("refusing reused batch output directory")
    except Exception as exc:
        groups = []
        fatal = f"preflight: {type(exc).__name__}: {exc}"
    for number, rows in enumerate(groups):
        if fatal:
            break
        group_out = out / "groups" / f"group-{number:02d}"
        group_out.mkdir(parents=True)
        group = {"id": group_out.name, "rows": [row["id"] for row in rows],
                 "cfg": rows[0]["cfg"], "state": "NOT_RUN", "proof_credit": "NONE"}
        group_receipts.append(group)
        export_path = group_out / "export.json"
        export_cap = min(len(rows) * EXPORT_CAP_BYTES, ARTIFACT_CAP_BYTES // 2)
        execution = None
        source_before = None
        try:
            env = ci_env(rows[0])
            group["environment"] = {k: env[k] for k in ("RUSTFLAGS", "KANI_TOML_FILE")}
            source_before = verify_source(std, tool, request)
            group["source_before"] = source_before
            before = binary_fingerprints(tool, {})
            group["tool_fingerprints_before"] = before
            if not before["required_hashes_present"]:
                raise RunnerError("missing required binary hashes before group")
            argv = build_argv(std, tool, [row["selector"] for row in rows], None, export_path)
            group["argv"] = argv
            rss_cap = group_rss_cap()
            remaining = PHASE_SECONDS - (time.monotonic() - phase_started) - PHASE_CLEANUP_MARGIN
            if remaining <= COMPILE_SECONDS:
                raise RunnerError("phase_seconds_cap_before_group")
            timeout = min(COMPILE_SECONDS + sum(row["timeout_seconds"] for row in rows), remaining)
            group.update(wall_limit_seconds=timeout,
                         full_group_budget_seconds=COMPILE_SECONDS + sum(row["timeout_seconds"] for row in rows),
                         phase_may_interrupt_group=timeout < COMPILE_SECONDS + sum(row["timeout_seconds"] for row in rows),
                         export_cap_bytes=export_cap, compilation_limit_seconds=COMPILE_SECONDS)
            execution = execute(argv, std, group_out, timeout, rss_cap_kib=rss_cap,
                                export_path=export_path, export_cap=export_cap, env=env,
                                batch_rows=rows, receipt_root=out)
            group.update(state="OBSERVED", execution=execution)
            # Snapshot exit/signal before any parsing or postflight can fail.
            _write_json(group_out / "receipt.json", group)
            raw = {}
            if export_path.is_file() and export_path.stat().st_size <= export_cap:
                group["export_sha256"] = sha256(export_path)
                try:
                    raw = json.loads(export_path.read_bytes())
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    pass
            after = binary_fingerprints(tool, raw if isinstance(raw, dict) else {})
            group["tool_fingerprints_after"] = after
            if (not after["required_hashes_present"] or
                    {k: v.get("sha256") for k, v in before["binaries"].items()} !=
                    {k: v.get("sha256") for k, v in after["binaries"].items()}):
                raise RunnerError("tool_binary_drift_or_missing_hash")
            if execution.get("termination_reason") or execution.get("timed_out") or execution.get("signal"):
                raise RunnerError(execution.get("termination_reason") or "group_signal_or_timeout")
            if execution.get("original_exit_code") not in (0, 1):
                raise RunnerError("unexpected_group_exit")
            compilation = execution.get("compilation", {})
            if (compilation.get("state") != "PRE_HARNESS_COMPLETE" or
                    sorted(compilation.get("harness_marker_order", [])) != sorted(row["id"] for row in rows)):
                raise RunnerError("missing_or_incomplete_harness_resource_boundaries")
            # A nonzero batch exit may belong to a sibling negative/timeout. It
            # never replaces a row's own exported outcome.
            harnesses = raw.get("harnesses") if isinstance(raw, dict) else None
            if isinstance(harnesses, list) and all(isinstance(h, dict) for h in harnesses):
                outcomes = [h.get("outcome") for h in harnesses]
                all_success = bool(outcomes) and all(o == {"kind": "COMPLETED", "verdict": "SUCCESS"} for o in outcomes)
                if (all_success and execution["original_exit_code"] != 0 or
                        any(isinstance(o, dict) and o.get("verdict") == "FAILURE" for o in outcomes) and
                        execution["original_exit_code"] == 0):
                    raise RunnerError("group_exit_export_mismatch")
            for row in rows:
                result = results[row["id"]]
                parsed = parse_export(export_path, row, max_bytes=export_cap, group_rows=rows)
                result.update(status="OBSERVED", outcome=parsed.get("outcome", "UNKNOWN"), export=parsed,
                              group=group_out.name, group_receipt=str((group_out / "receipt.json").relative_to(out)),
                              group_export_sha256=group.get("export_sha256"),
                              original_exit=execution.get("original_exit_code"), signal=execution.get("signal"),
                              exit_scope="GROUP_NOT_ROW", per_row_rss="UNKNOWN",
                              group_rss_peak_kib=execution.get("rss_peak_kib"),
                              row_rss_cap_kib=RSS_CAP_KIB, stdout_cap_bytes=STDOUT_CAP_BYTES,
                              stderr_cap_bytes=STDERR_CAP_BYTES, export_cap_bytes=EXPORT_CAP_BYTES,
                              timeout_seconds=row["timeout_seconds"], proof_credit="NONE")
        except Exception as exc:
            group.update(state="RUNNER_ERROR", reason=f"{type(exc).__name__}: {exc}")
            fatal = group["reason"]
        finally:
            target = group_out / "target"
            if target.exists():
                shutil.rmtree(target)
            group["target_cleanup"] = "REMOVED_BUILD_OUTPUT_NOT_EVIDENCE"
            try:
                group["source_after"] = verify_source(std, tool, request)
                if source_before is not None and group["source_after"] != source_before:
                    raise RunnerError("source_identity_drift")
            except Exception as exc:
                fatal = f"postflight: {type(exc).__name__}: {exc}"
                group["postflight_error"] = fatal
            if _artifact_size(out) > ARTIFACT_CAP_BYTES:
                fatal = "artifact_bytes_cap"
            if fatal:
                for row in rows:
                    results[row["id"]].update(outcome="UNKNOWN", reason=fatal,
                        status="OBSERVED" if execution else "NOT_RUN", group=group_out.name,
                        original_exit=execution.get("original_exit_code") if execution else None,
                        signal=execution.get("signal") if execution else None, exit_scope="GROUP_NOT_ROW")
            _write_json(group_out / "receipt.json", group)
        # Persist each group immediately; fallback preserves all existing receipts.
        for row in rows:
            _write_json(out / row["id"] / "receipt.json", results[row["id"]])
    for row in request["rows"]:
        result = results[row["id"]]
        if result["status"] == "NOT_RUN":
            result.setdefault("reason", fatal or "not reached")
        _write_json(out / row["id"] / "receipt.json", result)
    _consumer_gates(request["rows"], results, out)
    if _artifact_size(out) > ARTIFACT_CAP_BYTES:
        fatal = "artifact_bytes_cap"
        for row in request["rows"]:
            results[row["id"]].update(outcome="UNKNOWN", reason=fatal)
            _write_json(out / row["id"] / "receipt.json", results[row["id"]])
    unknown = any(r["outcome"] != "EXPECTED" for r in results.values())
    _write_json(out / "receipt.json", {"state": "STOPPED" if fatal else "COMPLETE_WITH_UNKNOWN" if unknown else "COMPLETE",
                "stop_reason": fatal, "proof_credit": "NONE", "std_sha": STD_SHA, "std_tree": STD_TREE,
                "tool_sha": TOOL_SHA, "tool_tree": TOOL_TREE, "groups": group_receipts,
                "phase_elapsed_seconds": round(time.monotonic() - phase_started, 3),
                "rows": [results[row["id"]] for row in request["rows"]]})
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
    args.std, args.tool = args.std.resolve(), args.tool.resolve()
    if hasattr(args, "out"): args.out = args.out.resolve()
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
