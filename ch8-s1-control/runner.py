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
        if not isinstance(timeout, int) or not 1 <= timeout <= MAX_ROW_SECONDS:
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
            "row_seconds": MAX_ROW_SECONDS}.items()):
        raise RunnerError("request budget mismatch")
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


def build_argv(std: Path, tool: Path, selector: str, unwind: int, export: Path) -> list[str]:
    argv = [str((tool.resolve() / "scripts/kani")), "verify-std", "-Z", "unstable-options"]
    for feature in UNSTABLE:
        argv += ["-Z", feature]
    argv += ["--no-assert-contracts", "--jobs=1", "--harness", selector,
             "--exact", "--default-unwind", str(unwind), "-Z", "export-json",
             "--export-json", str(export.resolve()), "--output-format=terse", str((std.resolve() / "library")),
             "--cbmc-args", "--object-bits", "12"]
    return argv


def ci_env() -> dict[str, str]:
    env = os.environ.copy()
    fixed = "--cfg=kani_smallsort_sorting --cfg=kani_smallsort_controls"
    inherited = env.get("RUSTFLAGS", "").strip()
    if inherited and inherited != fixed:
        raise RunnerError("refusing inherited RUSTFLAGS outside the frozen sorting+controls cfg")
    env["RUSTFLAGS"] = fixed
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


def execute(argv: list[str], cwd: Path, out: Path, timeout: int,
            rss_cap_kib: int = RSS_CAP_KIB, stdout_cap: int = STDOUT_CAP_BYTES,
            stderr_cap: int = STDERR_CAP_BYTES, export_path: Path | None = None,
            export_cap: int = EXPORT_CAP_BYTES, env: dict[str, str] | None = None) -> dict[str, Any]:
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
        return info
    threads = [threading.Thread(target=_read_pipe, args=(proc.stdout, out / "stdout.log", stdout_cap,
                                                         state, lock, "stdout"), daemon=True),
               threading.Thread(target=_read_pipe, args=(proc.stderr, out / "stderr.log", stderr_cap,
                                                         state, lock, "stderr"), daemon=True)]
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
    info["elapsed_seconds"] = round(time.monotonic() - started, 3)
    return info


def parse_export(path: Path, row: dict[str, Any], max_bytes: int = EXPORT_CAP_BYTES,
                 contract_binding: dict[str, str] | None = None) -> dict[str, Any]:
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
    selection = value.get("harness_selection")
    if (not isinstance(selection, dict) or selection.get("requested_filters") != [row["selector"]] or
            selection.get("exact") is not True or selection.get("unmatched_filters") != [] or
            selection.get("matched_count") != 1):
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    harnesses = value.get("harnesses")
    if not isinstance(harnesses, list) or len(harnesses) != 1:
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    harness = harnesses[0]
    if not isinstance(harness, dict) or harness.get("name") != row["selector"]:
        return {"state": "WRONG_ROOT_OR_SELECTION", "outcome": "UNKNOWN"}
    attrs = harness.get("attributes")
    kind = attrs.get("kind") if isinstance(attrs, dict) else None
    contract = harness.get("contract")
    reported_contract_function = None
    if row["mode"] == "PFC":
        if (not isinstance(kind, dict) or len(kind) != 1 or "ProofForContract" not in kind or
                not isinstance(kind["ProofForContract"], dict) or contract is None):
            return {"state": "WRONG_MODE", "outcome": "UNKNOWN"}
        list_target = (contract_binding or {}).get(row["selector"])
        exported_target = kind["ProofForContract"].get("target_fn")
        reported_contract_function = contract.get("contracted_function_name") if isinstance(contract, dict) else None
        if (not isinstance(list_target, str) or exported_target != list_target or
                not isinstance(reported_contract_function, str) or not reported_contract_function.strip()):
            return {"state": "CONTRACT_TARGET_BINDING_MISMATCH", "outcome": "UNKNOWN",
                    "list_target": list_target, "exported_target": exported_target,
                    "contracted_function_name": reported_contract_function}
    elif kind != "Proof":
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
            "list_target_fn": (contract_binding or {}).get(row["selector"]) if row["mode"] == "PFC" else None,
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


def list_inventory(std: Path, tool: Path, out: Path, request: dict[str, Any]) -> None:
    verify_source(std, tool, request)
    list_dir = out / "list"
    list_dir.mkdir(parents=True, exist_ok=True)
    list_argv = [str(tool.resolve() / "scripts/kani"), "list", str(std.resolve() / "library"),
                 "--std", "--format", "json", "--quiet", "-Z", "unstable-options"]
    for feature in UNSTABLE:
        list_argv += ["-Z", feature]
    phase_started = time.time()
    listing = execute(list_argv, list_dir, list_dir, timeout=MAX_ROW_SECONDS,
                      env=ci_env(), stdout_cap=STDOUT_CAP_BYTES, stderr_cap=STDERR_CAP_BYTES)
    if (listing.get("original_exit_code") != 0 or listing.get("timed_out") or
            listing.get("termination_reason") or listing.get("stdout_truncated") or listing.get("stderr_truncated")):
        raise RunnerError(f"Kani std list inventory failed: {listing}")
    list_json = list_dir / "kani-list.json"
    if not list_json.is_file() or list_json.stat().st_size > EXPORT_CAP_BYTES:
        raise RunnerError("Kani list JSON is missing or exceeds export cap")
    try:
        listed = json.loads(list_json.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"Kani list JSON is invalid: {exc}") from exc
    if not isinstance(listed, dict) or listed.get("file-version") != "0.1":
        raise RunnerError("Kani list file-version mismatch")
    def names(field: str) -> set[str]:
        value = listed.get(field)
        found: set[str] = set()
        if not isinstance(value, dict):
            return found
        for files in value.values():
            if not isinstance(files, list) or any(not isinstance(n, str) for n in files):
                raise RunnerError(f"Kani list field malformed: {field}")
            found.update(files)
        return found
    standard_names = names("standard-harnesses")
    contract_names = names("contract-harnesses")
    contracts = listed.get("contracts")
    if not isinstance(contracts, list):
        raise RunnerError("Kani list contracts field malformed")
    contract_binding: dict[str, str] = {}
    for item in contracts:
        if not isinstance(item, dict) or not isinstance(item.get("function"), str) or not isinstance(item.get("harnesses"), list):
            raise RunnerError("Kani list contract item malformed")
        for harness_name in item["harnesses"]:
            if not isinstance(harness_name, str):
                raise RunnerError("Kani list contract harness name malformed")
            previous = contract_binding.setdefault(harness_name, item["function"])
            if previous != item["function"]:
                raise RunnerError(f"PFC selector maps to multiple contracted functions: {harness_name}")
    for row in request["rows"]:
        inventory_names = contract_names if row["mode"] == "PFC" else standard_names
        if row["selector"] not in inventory_names:
            raise RunnerError(f"requested selector absent from {row['mode']} list inventory: {row['selector']}")
        if row["mode"] == "PFC" and row["selector"] not in contract_binding:
            raise RunnerError(f"PFC selector has no actual contracted-function mapping: {row['selector']}")
    smoke_ids = {"stable_default_cell", "stable_freeze_u8", "unstable_default_cell",
                 "unstable_freeze_u8", "freeze_default_noncopy", "freeze_copy_u8"}
    smoke_targets = {contract_binding[row["selector"]] for row in request["rows"] if row["id"] in smoke_ids}
    if len(smoke_targets) != 6 or {row["id"] for row in request["rows"] if row["id"] in smoke_ids} != smoke_ids:
        raise RunnerError("six smoke PFC roots do not map to six distinct actual contract targets")
    for diagnostic_id, smoke_id in (("activation-default", "stable_default_cell"),
                                    ("activation-override", "stable_freeze_u8")):
        diag = next((r for r in request["rows"] if r["id"] == diagnostic_id), None)
        positive = next((r for r in request["rows"] if r["id"] == smoke_id), None)
        if diag is None or positive is None or contract_binding.get(diag["selector"]) != contract_binding.get(positive["selector"]):
            raise RunnerError(f"activation diagnostic does not bind to the positive target: {diagnostic_id}")
    verify_source(std, tool, request)
    inventory = []
    for row in sorted(request["rows"], key=lambda r: (r["id"], r["selector"])):
        inventory.append({"id": row["id"], "selector": row["selector"], "mode": row["mode"],
                          "variant": row["variant"], "argv": build_argv(std, tool, row["selector"],
                                                                       row["unwind"], out / row["id"] / "export.json"),
                          "status": "NOT_RUN", "outcome": "UNKNOWN"})
    _write_json(out / "inventory.json", {"state": "INVENTORY_FROZEN_NOT_RUN",
                      "phase_started_unix": phase_started, "list_argv": list_argv,
                      "list_execution": listing, "list_json_sha256": sha256(list_json),
                      "listed_standard": sorted(standard_names), "listed_contract": sorted(contract_names),
                      "contract_binding": contract_binding,
                      "std_sha": STD_SHA, "tool_sha": TOOL_SHA, "rows": inventory})


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


def run_rows(std: Path, tool: Path, out: Path, request: dict[str, Any]) -> int:
    out.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    fatal: str | None = None
    try:
        verify_source(std, tool, request)
        inventory = json.loads((out / "inventory.json").read_text(encoding="utf-8"))
        if inventory.get("state") != "INVENTORY_FROZEN_NOT_RUN":
            raise RunnerError("missing completed list inventory")
        list_file = out / "list" / "kani-list.json"
        if sha256(list_file) != inventory.get("list_json_sha256"):
            raise RunnerError("Kani list inventory drift")
        contract_binding = inventory.get("contract_binding")
        if not isinstance(contract_binding, dict):
            raise RunnerError("list inventory lacks PFC contract bindings")
        phase_started = inventory.get("phase_started_unix")
        if not isinstance(phase_started, (int, float)):
            raise RunnerError("list inventory lacks shared phase start")
    except Exception as exc:
        fatal = f"preflight: {type(exc).__name__}: {exc}"
        phase_started = time.time()
    try:
        child_env = ci_env()
    except Exception as exc:
        child_env = None
        fatal = f"environment: {type(exc).__name__}: {exc}"

    for row in request["rows"]:
        row_out = out / row["id"]
        row_out.mkdir(parents=True, exist_ok=True)
        receipt_path = row_out / "receipt.json"
        result = _row_base(row)
        patch: Path | None = None
        if fatal:
            result["reason"] = fatal
            _write_json(receipt_path, result)
            results.append(result)
            _write_json(out / "receipt.json", {"state": "STOPPED", "stop_reason": fatal,
                         "proof_credit": "PENDING_REVIEW", "rows": results})
            continue
        remaining_phase = PHASE_SECONDS - (time.time() - phase_started)
        if remaining_phase <= MAX_ROW_SECONDS + PHASE_CLEANUP_MARGIN:
            fatal = "phase_seconds_cap"
            result["reason"] = fatal
            _write_json(receipt_path, result)
            results.append(result)
            _write_json(out / "receipt.json", {"state": "STOPPED", "stop_reason": fatal,
                         "proof_credit": "PENDING_REVIEW", "rows": results})
            continue
        try:
            source_before = verify_source(std, tool, request)
            result["source_before"] = source_before
            tool_before = binary_fingerprints(tool, {})
            result["tool_fingerprints_before"] = tool_before
            patch, variant_files = _run_variant(std, row["variant"], request)
            result["source_under_test"] = {
                "base_std_sha": STD_SHA, "variant": row["variant"],
                "file_sha256": {**request["changed_file_sha256"], **variant_files},
                "patch_sha256": sha256(patch) if patch is not None else None,
            }
            export_path = (row_out / "export.json").resolve()
            argv = build_argv(std, tool, row["selector"], row["unwind"], export_path)
            remaining = PHASE_SECONDS - (time.time() - phase_started) - PHASE_CLEANUP_MARGIN
            if remaining < row["timeout_seconds"]:
                fatal = "phase_seconds_cap"
                result["reason"] = fatal
                raise RunnerError(fatal)
            result["argv"] = argv
            invocation = execute(argv, std.resolve(), row_out,
                                 row["timeout_seconds"],
                                 rss_cap_kib=RSS_CAP_KIB, stdout_cap=STDOUT_CAP_BYTES,
                                 stderr_cap=STDERR_CAP_BYTES, export_path=export_path,
                                 export_cap=EXPORT_CAP_BYTES, env=child_env)
            result["execution"] = invocation
            result["original_exit"] = invocation.get("original_exit_code")
            result["signal"] = invocation.get("signal")
            result["status"] = "OBSERVED"
            _write_json(receipt_path, result)
            parsed = parse_export(export_path, row, max_bytes=EXPORT_CAP_BYTES,
                                  contract_binding=contract_binding)
            result["export"] = parsed
            if export_path.is_file() and export_path.stat().st_size <= EXPORT_CAP_BYTES:
                try:
                    raw_export = json.loads(export_path.read_text(encoding="utf-8"))
                    if isinstance(raw_export, dict):
                        fingerprints = binary_fingerprints(tool, raw_export)
                        result["tool_fingerprints"] = fingerprints
                        before_hashes = {k: v.get("sha256") for k, v in tool_before["binaries"].items()}
                        after_hashes = {k: v.get("sha256") for k, v in fingerprints["binaries"].items()}
                        if not fingerprints["required_hashes_present"]:
                            parsed["outcome"] = "UNKNOWN"
                            parsed["fingerprint_state"] = "MISSING_REQUIRED_BINARY_HASH"
                        if before_hashes != after_hashes:
                            parsed["outcome"] = "UNKNOWN"
                            parsed["fingerprint_state"] = "TOOL_BINARY_DRIFT"
                            fatal = "tool_binary_drift"
                except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                    pass
            output_capped = invocation.get("stdout_truncated") or invocation.get("stderr_truncated")
            killed = invocation.get("termination_reason") is not None or invocation.get("timed_out") or output_capped
            if killed or invocation.get("signal") is not None:
                parsed["outcome"] = "UNKNOWN"
                fatal = invocation.get("termination_reason") or ("output_cap" if output_capped else
                                                                    f"child_signal_{invocation.get('signal')}")
            if parsed.get("state") != "VALIDATED_OBSERVATION":
                fatal = fatal or f"invalid_export_{parsed.get('state')}"
            elif parsed.get("outcome") == "EXPECTED":
                if row["expected"] != "DETECTED" and invocation.get("original_exit_code") != 0:
                    parsed["outcome"] = "UNKNOWN"
                elif row["expected"] == "DETECTED" and invocation.get("original_exit_code") in (None, 0):
                    parsed["outcome"] = "UNKNOWN"
            result["outcome"] = parsed.get("outcome", "UNKNOWN")
            result["reviewer_binding"] = "PENDING; no automatic proof credit"
        except Exception as exc:
            result.update(status="RUNNER_ERROR", reason=f"{type(exc).__name__}: {exc}")
            fatal = fatal or "fatal_source_or_variant_drift"
        finally:
            if patch is not None:
                try:
                    subprocess.run(["git", "-C", str(std), "apply", "--reverse", "--check", str(patch)], check=True)
                    subprocess.run(["git", "-C", str(std), "apply", "--reverse", str(patch)], check=True)
                except Exception as exc:
                    result["variant_cleanup_error"] = str(exc)
                    fatal = "variant_cleanup_failed"
        try:
            source_after = verify_source(std, tool, request)
            result["source_after"] = source_after
            if source_after != result.get("source_before"):
                fatal = "source_identity_drift"
                result["outcome"] = "UNKNOWN"
        except Exception as exc:
            result["post_run_source_drift"] = str(exc)
            fatal = "source_drift"
        if _artifact_size(out) > ARTIFACT_CAP_BYTES:
            fatal = "artifact_bytes_cap"
        if fatal and result.get("status") == "OBSERVED":
            result["outcome"] = "UNKNOWN"
            result["stop_reason"] = fatal
        results.append(result)
        _write_json(receipt_path, result)
        _write_json(out / "receipt.json", {"state": "STOPPED" if fatal else "IN_PROGRESS",
                     "stop_reason": fatal, "proof_credit": "PENDING_REVIEW", "rows": results})

    for row in request["rows"][len(results):]:
        result = _row_base(row)
        result["reason"] = fatal or "not reached"
        _write_json(out / row["id"] / "receipt.json", result)
        results.append(result)
    unknown = any(result.get("outcome") != "EXPECTED" for result in results)
    final_state = "STOPPED" if fatal else ("COMPLETE" if not unknown else "COMPLETE_WITH_UNKNOWN")
    _write_json(out / "receipt.json", {"state": final_state, "stop_reason": fatal,
                 "proof_credit": "PENDING_REVIEW", "std_sha": STD_SHA, "std_tree": STD_TREE,
                 "tool_sha": TOOL_SHA, "tool_tree": TOOL_TREE,
                 "phase_elapsed_seconds": round(max(0, time.time() - phase_started), 3),
                 "rows": results})
    return 1 if fatal or unknown else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("check-source", "list", "run"):
        p = sub.add_parser(command)
        p.add_argument("--std", required=True, type=Path)
        p.add_argument("--tool", required=True, type=Path)
        if command != "check-source": p.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        request = load_request()
        if args.command == "check-source":
            print(json.dumps(verify_source(args.std, args.tool, request), sort_keys=True))
        elif args.command == "list":
            list_inventory(args.std, args.tool, args.out, request)
        else:
            return run_rows(args.std, args.tool, args.out, request)
    except Exception as exc:
        print(f"runner: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
