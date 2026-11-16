#!/usr/bin/env python3
"""Bounded, prep-only runner for the Challenge 8 E single-file controls.

Receipts describe tool observations. Exported harness IDs do not establish
source-level cover binding or proof credit.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
REQUEST = HERE / "CI-REQUEST.json"
ROWS = HERE / "rows.json"
PIN_DATA = {
    "upstream": {"sha": "0aac16ef62da9e9d5645782d458593e5d78143ba",
                 "tree": "9d8bc9312bf955ef126d32b819b3cd0ed105ed2b",
                 "repository": "model-checking/kani"},
    "sel1": {"sha": "14bc57fdb99960240c4944845a3d985c8af4dcf7",
             "tree": "1efb6e4dfa69d346df8e23741d11839b1932403d",
             "repository": "Tiramisu-Cake/kani"},
}
RSS_CAP_KIB = 6 * 1024 * 1024
LOG_CAP = 1024 * 1024
LOG_TAIL = 4096
EXPORT_CAP = 8 * 1024 * 1024
BUILD_SECONDS = 900
ROW_SECONDS = 660
PHASE_SECONDS = 75 * 60


class RunnerError(RuntimeError):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def git(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=True, text=True)
    return p.stdout.strip()


def _guard_env() -> dict[str, str]:
    env = os.environ.copy()
    if env.get("GITHUB_REPOSITORY") != "Tiramisu-Cake/kani":
        raise RunnerError("GITHUB_REPOSITORY must be Tiramisu-Cake/kani")
    if env.get("GITHUB_EVENT_NAME") != "push":
        raise RunnerError("GITHUB_EVENT_NAME must be push")
    if not env.get("GITHUB_REF", "").startswith("refs/heads/uninit-ci/ch8-e-ctl-"):
        raise RunnerError("GITHUB_REF is outside the E control branch family")
    if env.get("GITHUB_RUN_ATTEMPT") != "1":
        raise RunnerError("GITHUB_RUN_ATTEMPT must be 1")
    for key in ("KANI_ATTEMPT", "SMALLSORT_ATTEMPT"):
        if key in env and env[key] != "1":
            raise RunnerError(f"refusing {key} other than attempt 1")
    for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "KANI_FLAGS", "KANI_OPTS"):
        if env.get(key, "").strip():
            raise RunnerError(f"refusing inherited {key}")
    env["KANI_ATTEMPT"] = "1"
    return env


def load_request(pin: str) -> tuple[dict[str, Any], str]:
    try:
        raw = REQUEST.read_bytes()
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"cannot read CI request: {exc}") from exc
    if not isinstance(value, dict) or value.get("status") != "READY":
        raise RunnerError("CI request is not READY")
    if value.get("attempt") != 1 or value.get("bucket") != "E" or value.get("item") != 1:
        raise RunnerError("request is not attempt 1, bucket E, item 1")
    pins = value.get("pins")
    expected = PIN_DATA[pin]
    if not isinstance(pins, dict) or not isinstance(pins.get(pin), dict):
        raise RunnerError(f"request missing selected pin {pin}")
    if pins[pin].get("sha") != expected["sha"] or pins[pin].get("tree") != expected["tree"]:
        raise RunnerError(f"request selected pin mismatch: {pin}")
    if pins[pin].get("repository") != expected["repository"]:
        raise RunnerError(f"request repository mismatch for pin {pin}")
    payload = value.get("payload_sha256")
    if not isinstance(payload, dict) or any(not isinstance(k, str) or not isinstance(v, str)
                                            for k, v in payload.items()):
        raise RunnerError("request payload_sha256 must map paths to hashes")
    caps = value.get("caps")
    wanted_caps = {"row_envelope_seconds": ROW_SECONDS, "harness_seconds": 600,
                   "run_phase_seconds_per_pin": PHASE_SECONDS, "tool_build_seconds": BUILD_SECONDS,
                   "process_group_rss_bytes": RSS_CAP_KIB * 1024,
                   "stdout_head_bytes": LOG_CAP, "stderr_head_bytes": LOG_CAP,
                   "tail_bytes_per_stream": LOG_TAIL, "export_bytes": EXPORT_CAP}
    if not isinstance(caps, dict) or any(caps.get(key) != val for key, val in wanted_caps.items()):
        raise RunnerError("request caps do not match runner limits")
    rows_hash = value.get("rows_sha256")
    if not isinstance(rows_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", rows_hash):
        raise RunnerError("request rows_sha256 is missing or malformed")
    return value, hashlib.sha256(raw).hexdigest()


def verify_tool(tool: Path, pin: str) -> dict[str, str]:
    tool = tool.resolve()
    if tool.name != "tool" or tool.parent != HERE.parent.parent.resolve():
        raise RunnerError("tool must be the sibling 'tool' directory beside ch8-e-control")
    wanted = PIN_DATA[pin]
    try:
        actual_sha = git(tool, "rev-parse", "HEAD")
        actual_tree = git(tool, "rev-parse", "HEAD^{tree}")
        kind = git(tool, "cat-file", "-t", wanted["sha"])
        dirty = git(tool, "status", "--porcelain=v1", "--untracked-files=no")
    except (OSError, subprocess.CalledProcessError) as exc:
        raise RunnerError(f"cannot inspect pinned tool checkout: {exc}") from exc
    if actual_sha != wanted["sha"] or actual_tree != wanted["tree"] or kind != "commit":
        raise RunnerError(f"tool {pin} SHA/tree drift or pinned commit unavailable")
    if dirty:
        raise RunnerError("tool tracked state is not clean")
    return {"pin": pin, "sha": actual_sha, "tree": actual_tree}


def _payload_file_hash(payload: dict[str, str], rel: str) -> str | None:
    for key in (rel, f"ch8-e-control/{rel}"):
        if key in payload:
            return payload[key]
    return None


def load_rows(request: dict[str, Any]) -> tuple[list[dict[str, Any]], str]:
    try:
        raw = ROWS.read_bytes()
    except OSError as exc:
        raise RunnerError(f"cannot read rows.json: {exc}") from exc
    if hashlib.sha256(raw).hexdigest() != request["rows_sha256"]:
        raise RunnerError("rows.json SHA does not match CI request")
    try:
        rows = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RunnerError(f"invalid rows.json: {exc}") from exc
    if not isinstance(rows, list) or not rows:
        raise RunnerError("rows.json must be a non-empty array")
    seen: set[str] = set()
    payload = request["payload_sha256"]
    for row in rows:
        if not isinstance(row, dict):
            raise RunnerError("row must be an object")
        rid, rel, harness = row.get("id"), row.get("file"), row.get("harness")
        checks = row.get("checks")
        if not isinstance(rid, str) or not rid or rid in seen:
            raise RunnerError("missing or duplicate row id")
        seen.add(rid)
        if not isinstance(rel, str) or not rel or Path(rel).is_absolute() or ".." in Path(rel).parts:
            raise RunnerError(f"invalid relative source file for {rid}")
        source = (HERE / rel).resolve()
        if HERE.resolve() not in source.parents or not source.is_file():
            raise RunnerError(f"source file missing or outside control tree for {rid}")
        expected_sha = _payload_file_hash(payload, rel)
        if expected_sha is None or not re.fullmatch(r"[0-9a-f]{64}", expected_sha) or sha256(source) != expected_sha:
            raise RunnerError(f"source payload SHA mismatch for {rid}")
        if not isinstance(harness, str) or not harness or "\x00" in harness:
            raise RunnerError(f"invalid harness name for {rid}")
        if not isinstance(checks, list) or not checks or any(x not in ("ON", "OFF") for x in checks) or len(set(checks)) != len(checks):
            raise RunnerError(f"invalid checks for {rid}")
        expected = row.get("expected_by_check")
        if not isinstance(expected, dict) or any(c not in expected for c in checks):
            raise RunnerError(f"expected_by_check missing check for {rid}")
        if not isinstance(row.get("oracle"), (str, dict, list)):
            raise RunnerError(f"missing oracle for {rid}")
        covers = row.get("required_covers")
        if not isinstance(covers, list) or any(not isinstance(x, str) or not x for x in covers):
            raise RunnerError(f"invalid required_covers for {rid}")
        if "failure_description" in row and not isinstance(row["failure_description"], str):
            raise RunnerError(f"invalid failure_description for {rid}")
    return rows, hashlib.sha256(raw).hexdigest()


def _read_pipe(pipe, head: Path, tail_path: Path, cap: int,
               state: dict[str, Any], lock: threading.Lock, key: str) -> None:
    tail = bytearray()
    with head.open("wb") as output:
        while True:
            data = pipe.read(65536)
            if not data:
                break
            with lock:
                tail.extend(data)
                if len(tail) > LOG_TAIL:
                    del tail[:-LOG_TAIL]
                room = max(0, cap - state[key + "_kept"])
                if len(data) > room:
                    state[key + "_cap"] = True
                state[key + "_kept"] += min(room, len(data))
                state[key + "_bytes"] += len(data)
            if room:
                output.write(data[:room])
    pipe.close()
    tail_path.write_bytes(tail)


def _group_rss_kib(pgid: int) -> int:
    total = 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            fields = stat[stat.rfind(")") + 2:].split()
            if int(fields[2]) == pgid:
                for line in (entry / "status").read_text().splitlines():
                    if line.startswith("VmRSS:"):
                        total += int(line.split()[1]); break
        except (OSError, ValueError, IndexError):
            pass
    return total


def _kill_group(pgid: int, grace: float = 3.0) -> None:
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return
    until = time.monotonic() + grace
    while time.monotonic() < until:
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        time.sleep(.05)
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def execute(argv: list[str], cwd: Path, out: Path, timeout: int,
            env: dict[str, str] | None = None, export_path: Path | None = None) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    info: dict[str, Any] = {"argv": argv, "cwd": str(cwd.resolve()), "original_exit_code": None,
                            "signal": None, "timed_out": False, "rss_peak_kib": 0,
                            "output_truncated": False, "output_bytes": 0}
    state = {k: 0 for k in ("stdout_kept", "stderr_kept", "stdout_bytes", "stderr_bytes")}
    state.update(stdout_cap=False, stderr_cap=False)
    lock = threading.Lock()
    start = time.monotonic()
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    except OSError as exc:
        info.update(runner_error=f"exec failed: {exc}", elapsed_seconds=round(time.monotonic()-start, 3))
        return info
    readers = [threading.Thread(target=_read_pipe, args=(proc.stdout, out/"stdout.log", out/"stdout.tail.log", LOG_CAP, state, lock, "stdout"), daemon=True),
               threading.Thread(target=_read_pipe, args=(proc.stderr, out/"stderr.log", out/"stderr.tail.log", LOG_CAP, state, lock, "stderr"), daemon=True)]
    for t in readers: t.start()
    deadline = start + timeout
    reason = None
    external_signal: list[int] = []
    previous_handlers = {}
    def handle_signal(signum, _frame):
        external_signal.append(signum)
        _kill_group(proc.pid)
    for sig in (signal.SIGTERM, signal.SIGINT):
        previous_handlers[sig] = signal.getsignal(sig)
        signal.signal(sig, handle_signal)
    while proc.poll() is None or any(t.is_alive() for t in readers):
        info["rss_peak_kib"] = max(info["rss_peak_kib"], _group_rss_kib(proc.pid))
        with lock:
            if state["stdout_cap"]: reason = "stdout_cap"
            elif state["stderr_cap"]: reason = "stderr_cap"
        if export_path is not None:
            try:
                if export_path.exists() and export_path.stat().st_size > EXPORT_CAP:
                    reason = "export_cap"
            except OSError:
                pass
        if info["rss_peak_kib"] > RSS_CAP_KIB: reason = "rss_cap"
        if time.monotonic() >= deadline:
            info["timed_out"] = True; reason = reason or "timeout"
        if reason:
            info["termination_reason"] = reason
            _kill_group(proc.pid)
            break
        time.sleep(.05)
    for sig, handler in previous_handlers.items():
        signal.signal(sig, handler)
    if proc.poll() is None:
        _kill_group(proc.pid, 0)
    code = proc.wait()
    for t in readers: t.join(timeout=2)
    info["original_exit_code"] = code
    if code < 0: info["signal"] = -code
    if external_signal:
        info["interrupted_by_signal"] = external_signal[-1]
        info["termination_reason"] = "external_signal"
    info["stdout_truncated"], info["stderr_truncated"] = state["stdout_cap"], state["stderr_cap"]
    info["output_truncated"] = state["stdout_cap"] or state["stderr_cap"]
    info["output_bytes"] = state["stdout_bytes"] + state["stderr_bytes"]
    info["elapsed_seconds"] = round(time.monotonic() - start, 3)
    info["rss_cap_kib"] = RSS_CAP_KIB
    return info


def cap_export_snapshot(path: Path) -> dict[str, Any]:
    """Bound retained JSON artifacts even if the tool atomically emits a large file."""
    try:
        size = path.stat().st_size
        if size <= EXPORT_CAP:
            return {"size_bytes": size, "truncated": False}
        snapshot = path.with_name(path.name + ".oversize-head")
        with path.open("rb") as src, snapshot.open("wb") as dst:
            remaining = EXPORT_CAP
            while remaining:
                block = src.read(min(1024 * 1024, remaining))
                if not block: break
                dst.write(block); remaining -= len(block)
        path.unlink()
        return {"size_bytes": size, "truncated": True, "snapshot_path": str(snapshot)}
    except OSError as exc:
        return {"snapshot_error": f"{type(exc).__name__}: {exc}"}


def _schema_validate(value: Any) -> list[str]:
    """Use the checked-in RFC 0015 validator and exact schema template."""
    import importlib.util
    script = REPO / "scripts" / "validate_json_export.py"
    schema_path = REPO / "tests/json-handler/schema-validation/kani_json_schema.json"
    try:
        spec = importlib.util.spec_from_file_location("kani_json_export_validator", script)
        if spec is None or spec.loader is None: return ["validator unavailable"]
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        return module.validate_document(value, schema)
    except Exception as exc:
        return [f"schema validation unavailable: {exc}"]


def parse_export(path: Path, row: dict[str, Any], check: str, pin: str,
                 source: Path, run: dict[str, Any], max_bytes: int = EXPORT_CAP) -> dict[str, Any]:
    result = {"outcome": "UNKNOWN", "state": "UNKNOWN", "proof_credit": "NONE",
              "cover_source_binding": "PENDING_SOURCE_REVIEW"}
    if (run.get("timed_out") or run.get("output_truncated") or run.get("termination_reason") or
            run.get("runner_error") or run.get("original_exit_code") is None):
        result.update(state="EXECUTION_INCOMPLETE", reason=run.get("termination_reason"))
        return result
    try:
        size = path.stat().st_size
        if size > max_bytes: return {**result, "state": "OVERSIZE", "size_bytes": size}
        value = json.loads(path.read_bytes())
    except FileNotFoundError:
        return {**result, "state": "MISSING"}
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return {**result, "state": "INVALID_OR_PARTIAL", "error": str(exc)}
    if value is None: return {**result, "state": "NULL"}
    if not isinstance(value, dict): return {**result, "state": "WRONG_TOP_LEVEL_TYPE"}
    errors = _schema_validate(value)
    if errors: return {**result, "state": "SCHEMA_INVALID", "schema_errors": errors[:20]}
    if value.get("schema_version") != "0.1.0" or value.get("run_state") != "COMPLETE":
        return {**result, "state": "INCOMPLETE_EXPORT"}
    if value.get("kani_commit") != PIN_DATA[pin]["sha"] or value.get("kani_commit_dirty") is not False:
        return {**result, "state": "TOOL_PIN_MISMATCH"}
    selection = value.get("harness_selection", {})
    if (selection.get("requested_filters") != [row["harness"]] or selection.get("exact") is not True or
            selection.get("unmatched_filters") != [] or selection.get("matched_count") != 1):
        return {**result, "state": "SELECTION_MISMATCH"}
    if len(value.get("harnesses", [])) != 1:
        return {**result, "state": "SELECTION_MISMATCH"}
    harness = value["harnesses"][0]
    if harness["name"] != row["harness"]:
        return {**result, "state": "SELECTION_MISMATCH"}
    try:
        source_text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return {**result, "state": "SOURCE_UNREADABLE"}
    declared_loop_contract = re.search(r"(?m)^\s*#\s*\[\s*kani::loop_invariant\b", source_text) is not None
    attrs = harness["attributes"]
    if (harness["has_loop_contracts"] is not declared_loop_contract or
            harness["is_automatically_generated"] is not False or attrs["should_panic"] is not False or
            harness["contract"] is not None or attrs["verified_stubs"] != []):
        return {**result, "state": "HARNESS_METADATA_MISMATCH"}
    if (value["summary"]["total"] != 1 or
            value["summary"]["successful"] != int(harness["outcome"]["kind"] == "COMPLETED" and harness["outcome"].get("verdict") == "SUCCESS") or
            value["summary"]["failed"] != int(harness["outcome"]["kind"] == "COMPLETED" and harness["outcome"].get("verdict") == "FAILURE") or
            value["summary"]["checks_total"] != harness["checks"]["total"] or
            value["summary"]["checks_success"] != harness["checks"]["success"] or
            value["summary"]["covers_total"] != harness["covers"]["total"] or
            value["summary"]["covers_satisfied"] != len(harness["covers"]["satisfied"])):
        return {**result, "state": "SUMMARY_MISMATCH"}
    reported_file = Path(harness["file"])
    if not reported_file.is_absolute(): reported_file = (run["cwd"] and Path(run["cwd"]) / reported_file)
    if reported_file.resolve() != source.resolve():
        return {**result, "state": "SOURCE_FILE_MISMATCH", "reported_file": harness["file"]}
    if not isinstance(value.get("tools", {}).get("kani"), str):
        return {**result, "state": "MISSING_TOOL_VERSION"}
    config = value["configuration"]
    required_check = check == "ON"
    config_checks = config["checks"]
    if (config_checks.get("assert_contracts") is not True or
            any(config_checks.get(k) is not True for k in ("memory_safety", "overflow", "unwinding", "undefined_function")) or
            config_checks.get("prove_safety_only") is not False or
            config.get("cbmc_args") != ["--object-bits", "12"] or
            harness["attributes"]["kind"] != "Proof" or harness["attributes"]["stubs"] != []):
        return {**result, "state": "CONFIGURATION_MISMATCH"}
    features = value["enabled_unstable_features"]
    expected_features = {"unstable-options", "loop-contracts", "quantifiers", "export-json"}
    if required_check: expected_features.add("uninit-checks")
    if set(features) != expected_features:
        return {**result, "state": "FEATURE_MISMATCH", "features": features}
    timeout = value.get("harness_timeout_s")
    if type(timeout) not in (int, float) or timeout != 600:
        return {**result, "state": "TIMEOUT_CONFIGURATION_MISMATCH"}
    expected = row["expected_by_check"][check]
    outcome = harness["outcome"]
    checks, covers = harness["checks"], harness["covers"]
    required_covers = row["required_covers"]
    cover_ids = covers["satisfied"]
    if (covers["total"] != len(cover_ids) or len(set(cover_ids)) != len(cover_ids) or
            len(cover_ids) < len(required_covers) or
            any(covers[k] for k in ("unsatisfiable", "unreachable", "undetermined", "error", "unknown", "other"))):
        return {**result, "state": "COVER_INVENTORY_MISMATCH", "satisfied_cover_ids": cover_ids}
    if outcome["kind"] == "COMPLETED" and outcome.get("verdict") == "SUCCESS":
        complete_checks = (checks["success"] == checks["total"] and checks["failure"] == [] and
                           checks["total"] > 0 and
                           all(checks[k] == [] for k in ("unreachable", "undetermined", "error", "unknown", "other")))
        if (harness.get("failure_kind") != "NONE" or harness["n_failed"] != 0 or not complete_checks or
                harness["unsupported_constructs"] or harness["n_properties"] != checks["total"] + covers["total"]):
            return {**result, "state": "INCONSISTENT_SUCCESS"}
        if run.get("original_exit_code") != 0 or run.get("signal") is not None:
            return {**result, "state": "PROCESS_EXIT_MISMATCH"}
        observed = "SUCCESS"
        if expected == "OBSERVE": observed = "OBSERVE"
        classified = observed if expected == observed else "UNEXPECTED"
        return {**result, "state": "VALIDATED_OBSERVATION", "outcome": classified,
                "observed": observed, "expected": expected, "satisfied_cover_ids": cover_ids,
                "cover_description_binding": "PENDING_SOURCE_REVIEW"}
    if outcome["kind"] == "COMPLETED" and outcome.get("verdict") == "FAILURE":
        if type(run.get("original_exit_code")) is not int or run["original_exit_code"] <= 0 or run.get("signal") is not None:
            return {**result, "state": "PROCESS_EXIT_MISMATCH"}
        failed = harness["failed_properties"]
        ids = checks["failure"]
        if (not failed or {p["id"] for p in failed} != set(ids) or harness["n_failed"] != len(failed) or
                harness["n_properties"] != checks["total"] + covers["total"] or harness["unsupported_constructs"] or
                checks["success"] + len(failed) != checks["total"] or
                any(checks[k] for k in ("unreachable", "undetermined", "error", "unknown", "other"))):
            return {**result, "state": "UNBOUND_FAILURE"}
        matcher = row.get("failure_match")
        if not isinstance(matcher, dict):
            return {**result, "state": "UNBOUND_FAILURE"}
        wanted_class = matcher.get("class")
        pattern = matcher.get("description_regex")
        try: regex = re.compile(pattern) if isinstance(pattern, str) else None
        except re.error: regex = None
        locations = matcher.get("locations")
        if not isinstance(locations, list):
            locations = [{"file": matcher.get("file"), "line": matcher.get("line")}]
        def row_location(location: dict[str, Any]) -> tuple[str, str] | None:
            file_value, line_value = location.get("file"), location.get("line")
            if not isinstance(file_value, str) or not isinstance(line_value, (str, int)):
                return None
            file_path = Path(file_value)
            if not file_path.is_absolute(): file_path = HERE / file_path
            return (str(file_path.resolve()), str(line_value))
        wanted_locations = {item for loc in locations if isinstance(loc, dict) and (item := row_location(loc))}
        def source_bound(prop: dict[str, Any]) -> bool:
            file_value = prop.get("file")
            line_value = prop.get("line")
            if not isinstance(file_value, str) or not isinstance(line_value, str) or not line_value.isdigit():
                return False
            reported = Path(file_value)
            if not reported.is_absolute():
                from_cwd = (Path(run["cwd"]) / reported).resolve()
                reported = from_cwd if from_cwd == source.resolve() else (HERE / reported).resolve()
            return (reported.resolve() == source.resolve() and
                    (str(reported.resolve()), line_value) in wanted_locations and
                    p_class_matches(prop.get("class"), wanted_class) and regex is not None and
                    isinstance(prop.get("description"), str) and regex.fullmatch(prop["description"]) is not None)
        bound = bool(wanted_locations) and isinstance(wanted_class, str) and regex is not None and all(source_bound(p) for p in failed)
        named = None
        if bound:
            sample_desc = " ".join(p["description"] for p in failed).lower()
            if ("uninitialized" in sample_desc or "uninit" in str(row.get("oracle", "")).lower() or
                    str(wanted_class).lower() == "safety_check" and "undefined behavior" in sample_desc):
                named = "UNINIT_FAILURE"
            else:
                named = "ASSERTION_FAILURE"
        if named:
            return {**result, "state": "NAMED_FAILURE_OBSERVATION",
                    "outcome": named if expected == named else "UNEXPECTED", "observed": named,
                    "expected": expected,
                    "failure_ids": ids, "failure_descriptions": [p["description"] for p in failed]}
    return {**result, "state": "UNCLASSIFIED_EXPORT_OUTCOME"}


def _diag_matches(row: dict[str, Any], run: dict[str, Any], outdir: Path) -> bool:
    expected = row.get("frontend_diagnostic", row.get("failure_description"))
    if not isinstance(expected, str) or not expected or type(run.get("original_exit_code")) is not int or run["original_exit_code"] <= 0 or run.get("signal") is not None: return False
    if run.get("timed_out") or run.get("output_truncated") or run.get("termination_reason"): return False
    try:
        data = (outdir/"stdout.log").read_bytes() + (outdir/"stderr.log").read_bytes()
        text = data.decode("utf-8")
    except (OSError, UnicodeDecodeError): return False
    clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return any(line.strip() in (expected, "error: " + expected) for line in clean.splitlines())


def p_class_matches(actual: Any, expected: str) -> bool:
    return isinstance(actual, str) and actual == expected


def build(tool: Path, out: Path, pin: str) -> int:
    started = time.monotonic()
    receipt = out / "build.json"
    run = None
    try:
        request, request_sha = load_request(pin)
        binding = verify_tool(tool, pin)
        env = _guard_env()
        argv = ["cargo", "build-dev", "--", "--release"]
        run = execute(argv, tool.resolve(), out/"build", BUILD_SECONDS, env)
        final_binding = verify_tool(tool, pin)
        record = {"status": "COMPLETE" if run.get("original_exit_code") == 0 and not run.get("runner_error") and not run.get("termination_reason") else "FAILED",
                  "pin": pin, "tool": binding, "tool_after": final_binding, "request_sha256": request_sha,
                  "attempt": request["attempt"], "argv": argv, "cwd": str(tool.resolve()), "run": run,
                  "elapsed_seconds": round(time.monotonic()-started, 3)}
    except Exception as exc:
        record = {"status": "FAILED", "pin": pin, "error": f"{type(exc).__name__}: {exc}",
                  "elapsed_seconds": round(time.monotonic()-started, 3)}
        if run is not None: record["run"] = run
    out.mkdir(parents=True, exist_ok=True)
    receipt.write_text(json.dumps(record, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    return 0 if record["status"] == "COMPLETE" else 1


def run_rows(tool: Path, out: Path, pin: str) -> int:
    started = time.monotonic()
    try:
        request, request_sha = load_request(pin)
        binding = verify_tool(tool, pin)
        rows, rows_sha = load_rows(request)
        build_receipt_path = out / "build.json"
        build_receipt = json.loads(build_receipt_path.read_text(encoding="utf-8"))
        if (not isinstance(build_receipt, dict) or build_receipt.get("status") != "COMPLETE" or
                build_receipt.get("pin") != pin or build_receipt.get("request_sha256") != request_sha or
                build_receipt.get("tool") != binding or
                not isinstance(build_receipt.get("run"), dict) or
                build_receipt["run"].get("original_exit_code") != 0 or
                build_receipt["run"].get("termination_reason") or build_receipt["run"].get("runner_error")):
            raise RunnerError("matching successful build receipt is required")
        env = _guard_env()
    except Exception as exc:
        out.mkdir(parents=True, exist_ok=True)
        (out/"run.json").write_text(json.dumps({"status":"FAILED","error":f"{type(exc).__name__}: {exc}"}, indent=2)+"\n")
        return 1
    receipts = []
    out.mkdir(parents=True, exist_ok=True)
    status_path = out/"run.json"
    def persist(status: str, **extra: Any) -> None:
        status_path.write_text(json.dumps({"status": status, "pin": pin, "tool": binding,
                                           "request_sha256": request_sha, "rows_sha256": rows_sha,
                                           "phase_cap_seconds": PHASE_SECONDS, "receipts": receipts,
                                           "proof_credit": "NONE", **extra}, indent=2, sort_keys=True)+"\n",
                               encoding="utf-8")
    persist("RUNNING")
    for row in rows:
        source = (HERE / row["file"]).resolve()
        expected_file_sha = _payload_file_hash(request["payload_sha256"], row["file"])
        for check in row["checks"]:
            current_file_sha = sha256(source)
            elapsed = time.monotonic() - started
            remaining = PHASE_SECONDS - elapsed
            entry = {"id": row["id"], "file": str(source), "file_sha256": current_file_sha, "harness": row["harness"], "check": check,
                     "expected": row["expected_by_check"][check], "pin": pin, "tool": binding,
                     "request_sha256": request_sha, "rows_sha256": rows_sha, "attempt": 1}
            if current_file_sha != expected_file_sha:
                entry.update(status="NOT_RUN", reason="source SHA drift after request validation")
                receipts.append(entry); persist("RUNNING", elapsed_seconds=round(time.monotonic()-started, 3)); continue
            if remaining <= 0 or remaining < ROW_SECONDS + 30:
                entry.update(status="NOT_RUN", reason="insufficient phase envelope")
                receipts.append(entry); persist("RUNNING", elapsed_seconds=round(time.monotonic()-started, 3)); continue
            slot = out/"rows"/row["id"]/check.lower()
            slot.mkdir(parents=True, exist_ok=True)
            row_receipt_path = slot/"receipt.json"
            entry.update(status="RUNNING", cwd=str(slot.resolve()))
            row_receipt_path.write_text(json.dumps(entry, indent=2, sort_keys=True)+"\n", encoding="utf-8")
            receipts.append(entry)
            persist("RUNNING", elapsed_seconds=round(time.monotonic()-started, 3))
            export_path = (slot/"export.json").resolve()
            argv = [str((tool.resolve()/"scripts/kani").resolve()), str(source), "--harness", row["harness"], "--exact",
                    "-Z", "unstable-options", "-Z", "loop-contracts", "-Z", "quantifiers"]
            if check == "ON": argv += ["-Z", "uninit-checks"]
            argv += ["-Z", "export-json", "--export-json", str(export_path), "--harness-timeout", "600s",
                     "--jobs", "1", "--output-format=terse", "--cbmc-args", "--object-bits", "12"]
            try:
                run = execute(argv, slot.resolve(), slot, min(ROW_SECONDS, int(remaining)), env, export_path)
                entry.update(status="EXECUTED", cwd=run["cwd"], argv=argv, run=run,
                             export_path=str(export_path))
                row_receipt_path.write_text(json.dumps(entry, indent=2, sort_keys=True)+"\n", encoding="utf-8")
                entry["export_snapshot"] = cap_export_snapshot(export_path)
                parsed = ({**entry["export_snapshot"], "state":"OVERSIZE", "outcome":"UNKNOWN", "proof_credit":"NONE"}
                          if entry["export_snapshot"].get("truncated") else
                          parse_export(export_path, row, check, pin, source, run))
                if (type(run.get("original_exit_code")) is int and run["original_exit_code"] > 0 and run.get("signal") is None and
                        not run.get("runner_error") and parsed.get("outcome") == "UNKNOWN" and _diag_matches(row, run, slot)):
                    label = "FRONTEND_REJECTION"
                    expected = row["expected_by_check"][check]
                    parsed.update(state="FRONTEND_REJECTION_OBSERVATION",
                                  outcome=label if expected == label else "UNEXPECTED", observed=label,
                                  expected=expected, diagnostic_exact_match=True)
                entry.update(status="OBSERVED", cwd=run["cwd"], argv=argv, run=run, export=parsed,
                             export_path=str(export_path))
            except Exception as exc:
                entry.update(status="ERROR", error=f"{type(exc).__name__}: {exc}",
                             export={"state": "RUNNER_EXCEPTION", "outcome": "UNKNOWN", "proof_credit": "NONE"})
            row_receipt_path.write_text(json.dumps(entry, indent=2, sort_keys=True)+"\n", encoding="utf-8")
            persist("RUNNING", elapsed_seconds=round(time.monotonic()-started, 3))
            if entry.get("run", {}).get("interrupted_by_signal"):
                persist("INTERRUPTED", elapsed_seconds=round(time.monotonic()-started, 3))
                return 1
    final_tool = verify_tool(tool, pin)
    persist("COMPLETE", tool=final_tool, elapsed_seconds=round(time.monotonic()-started, 3))
    return 0


def fallback(out: Path, pin: str) -> int:
    out.mkdir(parents=True, exist_ok=True)
    request, request_sha = load_request(pin)
    rows, rows_sha = load_rows(request)
    path = out/"run.json"
    try:
        existing = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        existing = {}
    original_rows = existing.get("receipts") if isinstance(existing, dict) else None
    original_rows = original_rows if isinstance(original_rows, list) else []
    known = {(x.get("id"), x.get("check")): x for x in original_rows if isinstance(x, dict)
             and isinstance(x.get("id"), str) and isinstance(x.get("check"), str)}
    # A terminated aggregate write must not hide a completed per-row receipt.
    for row in rows:
        for check in row["checks"]:
            slot = out/"rows"/row["id"]/check.lower()/"receipt.json"
            try:
                record = json.loads(slot.read_bytes())
                if (isinstance(record, dict) and record.get("id") == row["id"] and
                        record.get("check") == check):
                    known[(row["id"], check)] = record
            except (OSError, UnicodeDecodeError, json.JSONDecodeError):
                pass
    present = set(known)
    missing = []
    for row in rows:
        for check in row["checks"]:
            if (row["id"], check) in present: continue
            source = HERE/row["file"]
            missing.append({"id": row["id"], "file": str(source.resolve()), "file_sha256": sha256(source),
                            "harness": row["harness"], "check": check, "expected": row["expected_by_check"][check],
                            "pin": pin, "request_sha256": request_sha, "rows_sha256": rows_sha,
                            "attempt": 1, "status": "NOT_RUN", "reason": "fallback synthesized missing receipt"})
    (out/"missing-not-run.json").write_text(json.dumps({"status":"FALLBACK_MISSING_ONLY", "pin":pin,
        "request_sha256":request_sha, "rows_sha256":rows_sha, "receipts":missing,
        "proof_credit":"NONE"}, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    cleanup = []
    try:
        targets = sorted((p for p in out.rglob("target") if p.is_dir() and
                          out.resolve() in p.resolve().parents), key=lambda p: len(p.parts), reverse=True)
        for target in targets:
            if not target.is_symlink():
                shutil.rmtree(target)
        cleanup.append({"status":"REMOVED_OR_ABSENT", "targets":[str(p) for p in targets]})
    except OSError as exc:
        cleanup.append({"status":"ERROR", "error":f"{type(exc).__name__}: {exc}"})
    except RunnerError as exc:
        cleanup.append({"status":"SKIPPED", "error":str(exc)})
    (out/"job-status.json").write_text(json.dumps({"status":"FALLBACK", "pin":pin,
        "preserved_run_status":existing.get("status") if isinstance(existing,dict) else None,
        "preserved_build_receipt":(out/"build.json").exists(), "missing_receipt_file":"missing-not-run.json",
        "incomplete_receipts":[{"id": x.get("id"), "check": x.get("check"), "original_status": x.get("status"),
                                "outcome":"UNKNOWN"} for x in known.values()
                               if x.get("status") not in ("OBSERVED", "NOT_RUN", "ERROR")],
        "target_cleanup":cleanup, "proof_credit":"NONE"}, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("build"); p.add_argument("--tool", required=True, type=Path); p.add_argument("--out", required=True, type=Path); p.add_argument("--pin", required=True, choices=PIN_DATA)
    p = sub.add_parser("run"); p.add_argument("--tool", required=True, type=Path); p.add_argument("--out", required=True, type=Path); p.add_argument("--pin", required=True, choices=PIN_DATA)
    p = sub.add_parser("fallback"); p.add_argument("--out", required=True, type=Path); p.add_argument("--pin", required=True, choices=PIN_DATA)
    args = parser.parse_args(argv)
    if args.command == "build": return build(args.tool, args.out, args.pin)
    if args.command == "run": return run_rows(args.tool, args.out, args.pin)
    try: return fallback(args.out, args.pin)
    except Exception as exc:
        print(f"fallback failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
