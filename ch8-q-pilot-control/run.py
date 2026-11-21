#!/usr/bin/env python3
"""Collect bounded q-pilot observations for offline analysis."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "ch8-s1-control"))
import runner as stock_runner
import s3_runtime

git = stock_runner.git
digest = stock_runner.sha256
WORKFLOW = ".github/workflows/ch8-q-pilot.yml"
REQUEST = "ch8-q-pilot-control/CI-REQUEST.json"
PAYLOAD = (WORKFLOW, "ch8-q-pilot-control/run.py", "ch8-q-pilot-control/test_run.py")
RESULT = "q-pilot-raw.json"
SCHEMA = "ch8-q-pilot-raw-v1"
CONTROL_PARENT = "ba32286ee4f370593a2c9f0d8834a12d473c82d7"
TOOL_SHA = "0aac16ef62da9e9d5645782d458593e5d78143ba"
TOOL_TREE = "9d8bc9312bf955ef126d32b819b3cd0ed105ed2b"
EVENT_REF = "refs/heads/uninit-ci/ch8-q-pilot-v1"
SOURCE = "library/core/src/slice/sort/shared/smallsort"
STD_FILES = {
    f"{SOURCE}.rs", f"{SOURCE}/verify.rs",
    *(f"{SOURCE}/verify/{name}.rs" for name in
      ("sorting_model", "sorting_q_model", "sorting_q_pilot", "sorting_q_controls",
       "sorting_q_merge", "sorting_q_merge_model")),
}
PREFIX = "slice::sort::shared::smallsort::verify::"
ROOTS = [
    {
        "id": rid,
        "selector": PREFIX + selector,
        "cfg": cfg,
        "object_bits": bits,
        "cbmc_args": [],
        "timeout_seconds": timeout,
    }
    for rid, selector, cfg, bits, timeout in (
        ("MW-MERGE-N32-OBSERVER-EQUIV", "sorting_q_merge::mw_merge_n32_observer_equiv", "compact_merge32", 11, 180),
        ("MW-MERGE-N32-COMPACT-OB11", "sorting_q_merge::mw_merge_n32", "compact_merge32", 11, 600),
    )
]
MERGE_CFG = "--cfg=kani_smallsort_sorting --cfg=kani_smallsort_q_pilot --cfg=kani_smallsort_q_merge"
MERGE_B_CFG = MERGE_CFG + " --cfg=kani_smallsort_q_merge_b"
MERGE_C_SORT9_CFG = MERGE_B_CFG + " --cfg=kani_smallsort_q_merge_sort9"
MERGE_WIDE_CFG = MERGE_C_SORT9_CFG + " --cfg=kani_smallsort_q_merge_wide"
CFG = {
    "merge_a": MERGE_CFG,
    "merge_b": MERGE_B_CFG,
    "merge_c_sort9": MERGE_C_SORT9_CFG,
    "merge_wide": MERGE_WIDE_CFG,
    "no_merge_sort13": MERGE_WIDE_CFG + " --cfg=kani_smallsort_q_no_merge_sort13",
    "compact_merge32": MERGE_WIDE_CFG + " --cfg=kani_smallsort_q_compact_merge32",
}
ARGV = [
    "{tool_script}", "verify-std", "-Z", "unstable-options",
    "-Z", "function-contracts", "-Z", "mem-predicates", "-Z", "float-lib",
    "-Z", "c-ffi", "-Z", "stubbing", "--no-assert-contracts", "--jobs=1",
    "--harness", "{selector}", "--exact", "--default-unwind", "36",
    "--harness-timeout", "{timeout_seconds}s", "--output-format=regular",
    "-Z", "export-json", "--export-json", "{export}", "--target-dir", "{kani_target}",
    "{std_library}", "--cbmc-args", "--object-bits", "{object_bits}",
]
MIB = 1024 * 1024
LIMITS = {
    "job_minutes": 180,
    "job_cleanup_upload_seconds": 540,
    "root_launch_headroom_seconds": 30,
    "setup_and_build_seconds": 1800,
    "tool_build_seconds": 900,
    "local_rss_kib": 6 * 1024 * 1024,
    "outer_rss_kib": 12 * 1024 * 1024,
    "memory_reserve_kib": stock_runner.MEMORY_RESERVE_KIB,
    "stdout_bytes_per_root": 16 * MIB,
    "stderr_bytes_per_root": MIB,
    "export_bytes_per_root": 8 * MIB,
    "artifact_bytes": 512 * MIB,
    "setup_receipt_bytes": MIB,
}
MEMBERS = {"stdout": "stdout.log", "stderr": "stderr.log", "export": "export.json"}
ENV_KEYS = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TZ",
            "RUSTUP_HOME", "CARGO_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR")


class PilotError(RuntimeError):
    pass


def error(exc, operation):
    result = {"operation": operation, "type": type(exc).__name__, "message": str(exc)[:2048]}
    if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
        result["stderr"] = exc.stderr[:2048]
    return result


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def atomic_bytes(path, data, staging=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=staging or path.parent, delete=False) as stream:
        temp = Path(stream.name)
        try:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(temp, path)
            fd = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        finally:
            temp.unlink(missing_ok=True)


def atomic(path, value, staging=None):
    data = (json.dumps(value, allow_nan=False, indent=2, sort_keys=True) + "\n").encode()
    atomic_bytes(path, data, staging)


def read_record(path):
    try:
        return json.loads(path.read_bytes())
    except FileNotFoundError:
        return None


def valid_hashes(mapping, paths):
    return (isinstance(mapping, dict) and set(mapping) == set(paths)
            and all(isinstance(value, str) and re.fullmatch("[a-f0-9]{64}", value)
                    for value in mapping.values()))


def load_request(repo=REPO):
    request = json.loads((repo / REQUEST).read_bytes())
    fixed = {
        "schema": "ch8-q-pilot-request-v2", "result_schema": SCHEMA,
        "status": "READY", "go": "NOT_GRANTED", "proof_credit": "NONE",
        "control_parent": CONTROL_PARENT, "tool_sha": TOOL_SHA, "tool_tree": TOOL_TREE,
        "event_ref": EVENT_REF, "workflow": WORKFLOW, "source_root": "library",
        "roots": ROOTS, "cfg": CFG, "argv": ARGV, "limits": LIMITS,
    }
    expected_keys = fixed.keys() | {"std_sha", "std_tree", "std_files", "control_payload_sha256"}
    if not isinstance(request, dict) or request.keys() != expected_keys:
        raise PilotError("request fields differ from the frozen schema")
    if not isinstance(request.get("roots"), list) or any(
            not isinstance(root, dict)
            or type(root.get("object_bits")) is not int
            or type(root.get("timeout_seconds")) is not int
            for root in request["roots"]):
        raise PilotError("invalid per-root object bits or timeout")
    if (not isinstance(request.get("limits"), dict)
            or any(type(value) is not int for value in request["limits"].values())):
        raise PilotError("invalid numeric limit types")
    for key, value in fixed.items():
        if request[key] != value:
            raise PilotError(f"frozen request mismatch: {key}")
    for key in ("std_sha", "std_tree"):
        if not isinstance(request[key], str) or not re.fullmatch("[a-f0-9]{40}", request[key]):
            raise PilotError(f"invalid request pin: {key}")
    for key, paths in (("std_files", STD_FILES), ("control_payload_sha256", PAYLOAD)):
        if not valid_hashes(request[key], paths):
            raise PilotError(f"hash inventory mismatch: {key}")
    return request


def checkout(path):
    if Path(git(path, "rev-parse", "--show-toplevel")).resolve() != path:
        raise PilotError(f"not a checkout root: {path}")
    sha, tree = git(path, "rev-parse", "HEAD", "HEAD^{tree}").splitlines()
    return {"sha": sha, "tree": tree}


def clean(path, label):
    dirty = git(path, "status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none")
    if dirty:
        raise PilotError(f"dirty {label} checkout at {path}: {dirty[:2048]}")


def check_hashes(path, hashes):
    for rel, expected in hashes.items():
        actual = digest(path / rel)
        if actual != expected:
            raise PilotError(f"payload hash mismatch for {path / rel}: {actual} != {expected}")


def validate_source(std, tool, request):
    identities = {}
    for label, path in (("std", std), ("tool", tool)):
        identity = checkout(path)
        expected = {"sha": request[label + "_sha"], "tree": request[label + "_tree"]}
        if identity != expected:
            raise PilotError(f"{label} identity mismatch at {path}: {identity} != {expected}")
        clean(path, label)
        identities[label] = identity
    check_hashes(std, request["std_files"])
    return identities


def control_identity(repo):
    return {
        **checkout(repo),
        "parents": git(repo, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:],
        "request_sha256": digest(repo / REQUEST),
        "workflow_sha256": digest(repo / WORKFLOW),
    }


def check_control(repo, request):
    if (os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_EVENT_NAME"),
        os.environ.get("GITHUB_REF"), os.environ.get("GITHUB_RUN_ATTEMPT")) != (
            "Tiramisu-Cake/kani", "push", request["event_ref"], "1"):
        raise PilotError("event is outside the frozen fork push and attempt")
    identity = control_identity(repo)
    trigger = os.environ.get("GITHUB_SHA")
    if identity["sha"] != trigger:
        raise PilotError(f"control HEAD differs from trigger SHA: {identity['sha']} != {trigger}")
    if identity["parents"] != [request["control_parent"]]:
        raise PilotError(f"control parent mismatch: {identity['parents']}")
    clean(repo, "control")
    paths = git(repo, "diff", "--name-only", request["control_parent"], "HEAD").splitlines()
    if set(paths) != {*PAYLOAD, REQUEST}:
        raise PilotError(f"control changed paths mismatch: {paths}")
    check_hashes(repo, request["control_payload_sha256"])
    return identity


def read_bounded(path, cap):
    # Nonblocking open and an fstat keep FIFOs, devices and symlinks out of the snapshot.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PilotError(f"not a regular file: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            return stream.read(cap + 1)
    finally:
        os.close(fd)


def read_setup(path, limits):
    if path is None:
        return {"reason": "SETUP_RECEIPT_PATH_UNAVAILABLE"}
    try:
        cap = limits["setup_receipt_bytes"]
        data = read_bounded(path, cap)
        if len(data) > cap:
            raise PilotError(f"setup receipt exceeds {cap} bytes")
        receipt = json.loads(data)
        if not isinstance(receipt, dict):
            raise PilotError("setup receipt must be a JSON object")
        # Refuse non-finite JSON from a damaged receipt before writing the journal.
        json.dumps(receipt, allow_nan=False)
        return {"sha256": hashlib.sha256(data).hexdigest(), "receipt": receipt}
    except FileNotFoundError:
        return {"reason": "SETUP_RECEIPT_MISSING"}
    except (OSError, ValueError, RecursionError, PilotError) as exc:
        return {"reason": "SETUP_RECEIPT_UNREADABLE", "error": error(exc, "read setup receipt")}


def setup_ready(setup, limits):
    receipt = setup.get("receipt", {})
    elapsed = receipt.get("setup_total_seconds")
    return (receipt.get("original_exit_code") == 0 and receipt.get("child_shutdown_verified") is True
            and not any(receipt.get(key) for key in (
                "runner_error", "runner_exception", "timed_out", "termination_reason",
                "stdout_truncated", "stderr_truncated", "cleanup_errors",
            ))
            and type(elapsed) in (int, float) and 0 <= elapsed <= limits["setup_and_build_seconds"])


def launch_boundary(epoch_file, limits, roots=ROOTS):
    epoch = float(epoch_file.read_text())
    if not math.isfinite(epoch) or not 0 < epoch <= time.monotonic():
        raise PilotError("invalid job epoch")
    # The first job step writes this timestamp on the runner. GitHub enforces its own hard cap.
    cleanup_by = epoch + limits["job_minutes"] * 60 - limits["job_cleanup_upload_seconds"]
    latest_starts = {
        root["id"]: cleanup_by - root["timeout_seconds"] - limits["root_launch_headroom_seconds"]
        for root in roots
    }
    return {"first_step_monotonic": epoch, "supervisor_cutoff_monotonic": cleanup_by,
            "latest_root_start_monotonic_by_root": latest_starts}


def latest_root_start(boundary, root):
    return boundary["latest_root_start_monotonic_by_root"][root["id"]]


def safe_env():
    return {key: os.environ[key] for key in ENV_KEYS if key in os.environ}


def prepare(out, root, std, tool, request):
    invocation = uuid.uuid4().hex
    temp = out / "work" / invocation
    paths = {
        "root_temp": str(temp), "tmpdir": str(temp / "tmp"),
        "cargo_target_dir": str(temp / "cargo-target"), "kani_target_dir": str(temp / "kani-target"),
        "execution": str(temp / "execution"), "export": str(temp / "export.json"),
        "worker_stderr": str(temp / "worker.stderr"),
    }
    substitutions = dict(tool_script=str(tool / "scripts/kani"), selector=root["selector"],
                         export=paths["export"], kani_target=paths["kani_target_dir"],
                         std_library=str(std / request["source_root"]),
                         object_bits=root["object_bits"], timeout_seconds=root["timeout_seconds"])
    argv = [arg.format_map(substitutions) for arg in request["argv"]]
    return {
        "invocation_id": invocation, "paths": paths,
        "object_bits": root["object_bits"], "timeout_seconds": root["timeout_seconds"],
        "cbmc_args": root["cbmc_args"],
        "cfg": request["cfg"][root["cfg"]],
        "argv": argv + root["cbmc_args"],
    }


def run_root(journal, prepared, std, limits):
    paths = prepared["paths"]
    env = safe_env() | {
        "RUSTFLAGS": prepared["cfg"], "CARGO_TARGET_DIR": paths["cargo_target_dir"],
        "TMPDIR": paths["tmpdir"], "NO_COLOR": "1", "TERM": "dumb",
    }
    try:
        Path(paths["tmpdir"]).mkdir()
        memory = stock_runner.group_memory_budget()
    except (OSError, stock_runner.RunnerError, ValueError) as exc:
        atomic(journal / "not_run.json",
               {"reason": "CHILD_PREPARATION_ERROR", "error": error(exc, "prepare child")})
        return 1
    nominal_rss_limit = limits["local_rss_kib"]
    rss_limit = min(nominal_rss_limit, memory["group_cap_kib"])
    started = None
    start_error = None

    def spawn(*args, **kwargs):
        nonlocal started, start_error
        proc = subprocess.Popen(*args, **kwargs)
        started = {"pid": proc.pid, "utc": utc_now(), "monotonic": time.monotonic()}
        try:
            atomic(journal / "started.json", started)
        except OSError as exc:
            # Hand the live handle back to execute even if persisting its start failed.
            start_error = error(exc, "record child start")
        return proc

    # Interpose in this isolated worker so the receipt records a successful
    # Popen, while execute keeps ownership of the child handle and pipes.
    original = stock_runner.subprocess
    stock_runner.subprocess = SimpleNamespace(
        Popen=spawn, PIPE=subprocess.PIPE, TimeoutExpired=subprocess.TimeoutExpired,
    )
    try:
        execution = stock_runner.execute(
            prepared["argv"], std, Path(paths["execution"]), prepared["timeout_seconds"],
            rss_cap_kib=rss_limit, stdout_cap=limits["stdout_bytes_per_root"],
            stderr_cap=limits["stderr_bytes_per_root"], export_path=Path(paths["export"]),
            export_cap=limits["export_bytes_per_root"], env=env, capture_tail=False,
            record_identity=True,
        )
    except Exception as exc:
        execution = {"worker_error": error(exc, "execute child")}
    finally:
        stock_runner.subprocess = original

    fields = (
        "original_exit_code", "signal", "timed_out", "termination_reason", "elapsed_seconds",
        "child_shutdown_verified", "cleanup_errors", "process_identity", "interrupted_by_signal",
        "rss_peak_kib", "rss_scope", "rss_sample_period_seconds", "runner_error",
        "runner_exception", "pipe_reader_errors", "worker_error", "stdout_bytes", "stderr_bytes",
        "stdout_truncated", "stderr_truncated",
        "component_group_peak_kib", "component_rss_scope",
    )
    child = {key: execution.get(key) for key in fields}
    child.update(
        started=started, start_record_error=start_error,
        worker_observed_at_utc=utc_now(), worker_observed_at_monotonic=time.monotonic(),
        wall_scope="execute elapsed through process and pipe cleanup",
        nominal_rss_cap_kib=nominal_rss_limit, rss_cap_kib=rss_limit, memory_budget=memory,
    )
    atomic(journal / "child.json", child)
    return int(bool(child["worker_error"] or child["runner_error"] or child["runner_exception"]
                    or start_error))


def absent_file(cap, reason, **extra):
    return {"path": None, "bytes": None, "sha256": None, "cap_bytes": cap,
            "truncated": None, "reason": reason, **extra}


def snapshot_member(kind, rid, path, out, cap, child, reaped):
    try:
        data = read_bounded(path, cap)
    except FileNotFoundError:
        return absent_file(cap, "FILE_MISSING")
    except (OSError, PilotError) as exc:
        return absent_file(cap, "READ_ERROR", error=error(exc, f"read {kind}"))
    reported = child.get(kind + "_truncated")
    truncated = True if len(data) > cap or reported is True else (
        False if reaped and (kind == "export" or reported is False) else None)
    data = data[:cap]
    member = f"{rid}/{MEMBERS[kind]}"
    try:
        atomic_bytes(out / "artifact" / member, data, out / "state")
    except OSError as exc:
        return absent_file(cap, "SAVE_ERROR", error=error(exc, f"save {kind}"))
    record = {"path": member, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
              "cap_bytes": cap, "truncated": truncated, "snapshot_after_reap": reaped}
    if kind == "export" and truncated is not True:
        try:
            json.loads(data)
        except (ValueError, RecursionError) as exc:
            record["decode_error"] = error(exc, "decode export JSON")
    return record


def collect_files(out, journal, root, prepared, child, reaped, limits):
    saved = read_record(journal / "files.json")
    if saved is None:
        paths = prepared["paths"]
        sources = {kind: Path(paths["execution"]) / MEMBERS[kind] for kind in ("stdout", "stderr")}
        sources["export"] = Path(paths["export"])
        saved = {kind: snapshot_member(kind, root["id"], sources[kind], out,
                                       limits[kind + "_bytes_per_root"], child or {}, reaped)
                 for kind in MEMBERS}
        atomic(journal / "files.json", saved)
    return saved


def remove_temp(out, journal, prepared, reaped):
    if prepared is None:
        return None
    prior = read_record(journal / "temp_cleanup.json")
    if prior is not None:
        return prior
    if not reaped:
        return {"removed": None, "reason": "SUPERVISOR_REAP_UNCONFIRMED"}
    invocation = prepared["invocation_id"]
    path = out / "work" / invocation
    if not re.fullmatch("[a-f0-9]{32}", invocation) or str(path) != prepared["paths"]["root_temp"]:
        raise PilotError("invalid root temp path")
    try:
        shutil.rmtree(path)
        result = {"removed": True}
    except FileNotFoundError:
        result = {"removed": not path.exists()}
    except OSError as exc:
        result = {"removed": False, "error": error(exc, "remove root temp")}
    atomic(journal / "temp_cleanup.json", result)
    return result


def collect_root(out, request, root, stop_reason):
    journal = out / "state" / root["id"]
    prepared = read_record(journal / "prepared.json")
    started = read_record(journal / "started.json")
    child = read_record(journal / "child.json")
    supervisor = read_record(journal / "supervisor.json")
    not_run = read_record(journal / "not_run.json")
    reaped = ((supervisor or {}).get("containment") or {}).get("verified") is True
    if started is None and child is not None:
        started = child["started"]

    if started is not None:
        interrupted = (not reaped or child is None or child["timed_out"]
                       or child["termination_reason"] or supervisor.get("cutoff")
                       or child["original_exit_code"] is None)
        status = "INTERRUPTED" if interrupted else "EXITED"
        reason = ("SUPERVISOR_REAP_UNCONFIRMED" if not reaped else
                  (child or {}).get("termination_reason") or supervisor.get("cutoff") or
                  ("CHILD_EXIT_UNOBSERVED" if interrupted else None))
    elif not_run is not None:
        status, reason = "NOT_RUN", not_run["reason"]
    elif prepared is None:
        status, reason = "NOT_RUN", stop_reason or "ROOT_NEVER_PREPARED"
    elif supervisor is not None and supervisor.get("worker_pid") is None and not supervisor.get("call_error"):
        status, reason = "NOT_RUN", "WORKER_NOT_SPAWNED"
    elif child is not None and child["runner_error"]:
        status, reason = "NOT_RUN", "CHILD_SPAWN_FAILED"
    elif child is not None and child["worker_error"]:
        status, reason = "NOT_RUN", "CHILD_NOT_SPAWNED"
    else:
        status, reason = "UNKNOWN", "CHILD_START_UNCONFIRMED"

    limits = request["limits"]
    if status == "NOT_RUN":
        files = {kind: absent_file(limits[kind + "_bytes_per_root"], reason) for kind in MEMBERS}
    else:
        files = collect_files(out, journal, root, prepared, child, reaped, limits)
    temp_cleanup = remove_temp(out, journal, prepared, reaped)
    return {
        **root, "cfg": request["cfg"][root["cfg"]],
        "argv": None if started is None or prepared is None else prepared["argv"],
        "invocation": prepared, "started": started, "child": child, "supervisor": supervisor,
        "supervisor_cleanup_verified": (reaped if (supervisor or {}).get("containment")
                                        is not None else None),
        "worker_exit_code": (supervisor or {}).get("worker_exit"),
        "status": status, "reason": reason, "launch_error": (not_run or {}).get("error"),
        "files": files, "temp_cleanup": temp_cleanup,
    }


def supervise_root(repo, out, std, tool, request, root, boundary):
    limits = request["limits"]
    journal = out / "state" / root["id"]
    prepared = prepare(out, root, std, tool, request)
    atomic(journal / "prepared.json", prepared)
    temp = Path(prepared["paths"]["root_temp"])
    created = False
    try:
        temp.mkdir(parents=True)
        created = True
        memory = stock_runner.group_memory_budget()
        outer_cap = min(limits["outer_rss_kib"], memory["group_cap_kib"])
    except (OSError, stock_runner.RunnerError, ValueError) as exc:
        atomic(journal / "not_run.json",
               {"reason": "ROOT_PREPARATION_ERROR", "error": error(exc, "prepare worker")})
        # No handle was created and no writer can own this directory.
        if created:
            remove_temp(out, journal, prepared, True)
        return True

    now = time.monotonic()
    root_latest_start = latest_root_start(boundary, root)
    if now >= root_latest_start:
        atomic(journal / "not_run.json", {"reason": "JOB_LAUNCH_BUDGET_EXHAUSTED"})
        remove_temp(out, journal, prepared, True)
        return None

    worker = [sys.executable, str(repo / PAYLOAD[1]), "_root",
              "--journal", str(journal), "--std", str(std)]
    try:
        supervisor = s3_runtime.supervise(
            worker, repo, safe_env() | {"PYTHONDONTWRITEBYTECODE": "1"},
            boundary["supervisor_cutoff_monotonic"] - now,
            outer_cap, Path(prepared["paths"]["worker_stderr"]),
        )
    except Exception as exc:
        supervisor = {"call_error": error(exc, "supervise worker"), "containment": None}
    supervisor.update(rss_cap_kib=outer_cap, memory_budget=memory)
    atomic(journal / "supervisor.json", supervisor)
    observation = collect_root(out, request, root, None)
    return observation["supervisor_cleanup_verified"] is True


def campaign(repo, std, tool, out, setup_receipt, epoch_file):
    request = load_request(repo)
    state = out / "state"
    state.mkdir(parents=True, exist_ok=False)
    journal = state / "campaign.json"
    campaign_record = {"setup": read_setup(setup_receipt, request["limits"]), "stop_reason": None}

    def stop(reason, exc=None):
        campaign_record.update(stop_reason=reason, sequence_closed=True)
        if exc is not None:
            campaign_record["stop_error"] = error(exc, reason)
        atomic(journal, campaign_record)
        return int(reason not in (None, "JOB_LAUNCH_BUDGET_EXHAUSTED"))

    atomic(journal, campaign_record)
    if not setup_ready(campaign_record["setup"], request["limits"]):
        return stop("SETUP_UNAVAILABLE_OR_UNSUCCESSFUL")
    try:
        boundary = launch_boundary(epoch_file, request["limits"], request["roots"])
        campaign_record["job_boundary"] = boundary
        atomic(journal, campaign_record)
    except (OSError, ValueError, PilotError) as exc:
        return stop("JOB_BOUNDARY_UNAVAILABLE", exc)

    # Recheck before each root and once after the last supervised invocation.
    for root in [*request["roots"], None]:
        try:
            campaign_record["input_identities"] = {
                "control": check_control(repo, request), **validate_source(std, tool, request),
            }
            atomic(journal, campaign_record)
        except (OSError, subprocess.CalledProcessError, PilotError) as exc:
            return stop("INPUT_VALIDATION_FAILED", exc)
        if root is None:
            break
        if time.monotonic() >= latest_root_start(boundary, root):
            return stop("JOB_LAUNCH_BUDGET_EXHAUSTED")
        cleaned = supervise_root(repo, out, std, tool, request, root, boundary)
        if cleaned is None:
            return stop("JOB_LAUNCH_BUDGET_EXHAUSTED")
        if not cleaned:
            return stop("SUPERVISOR_REAP_UNCONFIRMED")
    return stop(None)


def validate_artifact(artifact, doc, limits):
    expected = {RESULT: None}
    for root in doc["roots"]:
        for kind, entry in root["files"].items():
            member = entry["path"]
            if member is None:
                continue
            if member != f"{root['id']}/{MEMBERS[kind]}" or member in expected:
                raise PilotError(f"invalid or duplicate artifact member: {member}")
            expected[member] = (entry, limits[kind + "_bytes_per_root"])
    directories = {root["id"] for root in doc["roots"]}
    if not stat.S_ISDIR(artifact.lstat().st_mode):
        raise PilotError("artifact root must be a real directory")
    seen = set()
    total = 0
    for path in artifact.rglob("*"):
        name = path.relative_to(artifact).as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode) and name in directories:
            continue
        if not stat.S_ISREG(info.st_mode) or name not in expected:
            raise PilotError(f"unexpected artifact member: {name}")
        total += info.st_size
        if total > limits["artifact_bytes"]:
            raise PilotError("artifact cap exceeded")
        if name != RESULT:
            entry, cap = expected[name]
            if not info.st_size == entry["bytes"] <= cap or entry["cap_bytes"] != cap:
                raise PilotError(f"artifact size mismatch: {name}")
            if digest(path) != entry["sha256"]:
                raise PilotError(f"artifact digest mismatch: {name}")
        seen.add(name)
    if seen != expected.keys():
        raise PilotError(f"missing artifact members: {sorted(expected.keys() - seen)}")


def observed_identity(path, inspect):
    try:
        return inspect(path)
    except (OSError, subprocess.CalledProcessError, PilotError) as exc:
        return {"error": error(exc, f"observe checkout {path}")}


def finish(repo, std, tool, out, setup_receipt):
    request = load_request(repo)
    state = out / "state"
    state.mkdir(parents=True, exist_ok=True)
    campaign_record = read_record(state / "campaign.json") or {}
    stop_reason = campaign_record.get("stop_reason")
    workflow_steps = {name: os.environ.get(name.upper() + "_OUTCOME")
                      for name in ("control", "source", "setup", "build", "collection")}
    if campaign_record and not campaign_record.get("sequence_closed"):
        stop_reason = "COLLECTION_INTERRUPTED"
    elif not campaign_record:
        failed = next((name for name, outcome in workflow_steps.items()
                       if outcome in ("failure", "cancelled") and name != "collection"), None)
        stop_reason = (f"{failed.upper()}_STEP_{workflow_steps[failed].upper()}" if failed else
                       "COLLECTION_NOT_ENTERED")
    doc = {
        "schema": request["result_schema"], "proof_credit": "NONE",
        "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "event": os.environ.get("GITHUB_EVENT_NAME"), "ref": os.environ.get("GITHUB_REF"),
        "trigger_sha": os.environ.get("GITHUB_SHA"), "job_status": os.environ.get("JOB_STATUS"),
        "workflow_step_outcomes": workflow_steps,
        "identities": {
            "control": observed_identity(repo, control_identity),
            "std": observed_identity(std, checkout),
            "tool": observed_identity(tool, checkout),
        },
        "last_validated_inputs": campaign_record.get("input_identities"),
        "setup": campaign_record.get("setup") or read_setup(setup_receipt, request["limits"]),
        "job_boundary": campaign_record.get("job_boundary"), "limits": request["limits"],
        "stop_reason": stop_reason, "stop_error": campaign_record.get("stop_error"),
        "roots": [collect_root(out, request, root, stop_reason) for root in request["roots"]],
    }
    atomic(out / "artifact" / RESULT, doc, state)
    validate_artifact(out / "artifact", doc, request["limits"])
    return doc


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    for name in ("check-source", "run", "finish"):
        command = commands.add_parser(name)
        command.add_argument("--std", type=Path, required=True)
        command.add_argument("--tool", type=Path, required=True)
        if name != "check-source":
            command.add_argument("--out", type=Path, required=True)
            command.add_argument("--setup-receipt", type=Path, required=True)
        if name == "run":
            command.add_argument("--job-epoch", type=Path, required=True)
    worker = commands.add_parser("_root")
    worker.add_argument("--journal", type=Path, required=True)
    worker.add_argument("--std", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "validate":
            print(json.dumps(check_control(REPO, load_request())))
        elif args.command == "check-source":
            print(json.dumps(validate_source(args.std.resolve(), args.tool.resolve(), load_request())))
        elif args.command == "run":
            return campaign(REPO, args.std.resolve(), args.tool.resolve(), args.out.resolve(),
                            args.setup_receipt, args.job_epoch)
        elif args.command == "finish":
            finish(REPO, args.std.resolve(), args.tool.resolve(), args.out.resolve(), args.setup_receipt)
        else:
            prepared = read_record(args.journal / "prepared.json")
            return run_root(args.journal, prepared, args.std, load_request()["limits"])
        return 0
    except Exception as exc:
        print(json.dumps(error(exc, args.command)), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
