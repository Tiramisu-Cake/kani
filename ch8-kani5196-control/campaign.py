#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Run the frozen #5196 collection in the coordinator's fork lane."""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import re
import shutil
from types import SimpleNamespace
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "ch8-q-pilot-control"))
import run as pilot

import evidence
import observations
import tool_attestation

from request import (CHANGED, ENTRYPOINT, FIXTURE, MEMBERS, REQUEST, RESULT,
                     SOURCE, STD_ROWS, WORKFLOW, load_request)

BindingError = pilot.PilotError

def encode(value):
    return (json.dumps(value, allow_nan=False, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n").encode()


def identity(repo):
    return {**pilot.checkout(repo), "parents": pilot.git(repo, "rev-list", "--parents", "-n", "1", "HEAD").split()[1:]}


def control_identity(repo):
    return {
        **identity(repo), "request_sha256": pilot.digest(repo / REQUEST),
        "workflow_sha256": pilot.digest(repo / WORKFLOW),
    }


def validate_control(repo, request):
    for env, key in (("GITHUB_REPOSITORY", "repository"), ("GITHUB_EVENT_NAME", "event"),
                     ("GITHUB_REF", "event_ref"), ("GITHUB_RUN_ATTEMPT", "attempt")):
        if os.environ.get(env) != request[key]:
            raise BindingError(f"wrong control event: {env}")
    actual = control_identity(repo)
    if actual["sha"] != os.environ.get("GITHUB_SHA") or actual["parents"] != [request["control_parent"]]:
        raise BindingError(f"control commit or parent mismatch: {actual}")
    pilot.clean(repo, "control")
    changed = pilot.git(repo, "diff", "--name-only", request["control_base"], "HEAD").splitlines()
    if set(changed) != CHANGED | {REQUEST}:
        raise BindingError(f"control changed paths mismatch: {changed}")
    pilot.check_hashes(repo, request["control_payload_sha256"])
    return {**actual, "payload_sha256": request["control_payload_sha256"]}


def phase(journal, name, prepared):
    stamp = {
        "phase": name, "entered_monotonic": time.monotonic(),
        "phase_deadline_monotonic": prepared["phase_deadline_monotonic"],
        "root_deadline_monotonic": prepared["root_deadline_monotonic"],
    }
    pilot.atomic(journal / f"phase-{name}.json", stamp)
    pilot.atomic(journal / "phase.json", stamp)


def gap(reason, state="INCOMPLETE", **details):
    return {"state": state, "reason": reason, **details}


class ProjectionWriter:
    """Commit bounded members to the private journal before outer reap."""

    def __init__(self, journal, limit):
        self.journal = journal
        self.remaining = limit
        self.index = {}

    def save(self, kind, content):
        if kind in self.index:
            raise BindingError(f"projection already recorded: {kind}")
        state, reason = content["state"], content.get("reason")
        entry = {"path": None, "state": state, "reason": reason, "bytes": None, "sha256": None}
        if kind == "stock" and len(content.get("observations", [])) == 1:
            fields = content["observations"][0]["fields"]
            entry["harness_outcome"] = fields.get("outcome.kind")
            entry["harness_verdict"] = fields.get("outcome.verdict")
        data = encode(content)
        if len(data) > self.remaining:
            entry.update(state="INCOMPLETE", reason="ROOT_PROJECTION_CAP", projected_bytes=len(data),
                         remaining_bytes=self.remaining, prior_state=state, prior_reason=reason)
        elif state != "NOT_REQUESTED":
            name = MEMBERS[kind]
            pilot.atomic_bytes(self.journal / name, data)
            self.remaining -= len(data)
            entry.update(path=name, bytes=len(data), sha256=hashlib.sha256(data).hexdigest())
        self.index[kind] = entry
        pilot.atomic(self.journal / "files.json", self.index)


def read_attestation(path, limits):
    try:
        data = pilot.read_bounded(path, limits["setup_receipt_bytes"])
        if len(data) > limits["setup_receipt_bytes"]:
            raise BindingError("tool attestation exceeds receipt cap")
        document = json.loads(data)
        if not isinstance(document, dict):
            raise BindingError("attestation is not a JSON object")
        encode(document)
        return {"sha256": hashlib.sha256(data).hexdigest(), "receipt": document}
    except (OSError, ValueError, RecursionError, BindingError) as exc:
        return {"reason": "TOOL_ATTESTATION_UNAVAILABLE", "error": pilot.error(exc, "read attestation")}


def compact_supervisor(record):
    if record is None:
        return None
    result = dict(record)
    if record.get("containment"):
        result["containment"] = dict(record["containment"])
        for key in ("observed", "signals", "reaped_adopted"):
            items = result["containment"].get(key, [])
            result["containment"][key] = items[:64]
            result["containment"][f"{key}_omitted"] = max(0, len(items) - 64)
    events = result.get("lifecycle_events", [])
    result["lifecycle_events"] = events[-8:]
    result["lifecycle_events_omitted"] = result.get("lifecycle_events_omitted", 0) + max(0, len(events) - 8)
    return result


def verify_source_attributes(checkout, label):
    result = {}
    for row in STD_ROWS if label == "candidate" else STD_ROWS[:5]:
        rid, suffix, mode, unwind, _, _, macro, target = row
        module, name = suffix.split("::")
        path = f"{SOURCE}/verify/{module}.rs"
        src = (checkout / path).read_text()
        if macro:
            macro_block = src.split(f"macro_rules! {macro} {{", 1)[1].split("\n}", 1)[0]
            declarations = re.findall(rf"^{macro}!\({name},", src, re.M)
            expected_item = r"fn \$name\("
            attributes_from = macro_block
        else:
            declarations = re.findall(rf"^fn {name}\(", src, re.M)
            expected_item = rf"fn {name}\("
            attributes_from = src
        attribute = r"[ \t]*#\[kani::[^\]]*\]\n"
        pattern = rf"((?:{attribute})+)[ \t]*" + expected_item
        attributes = re.findall(pattern, attributes_from)
        if len(declarations) != 1 or len(attributes) != 1:
            raise BindingError(f"{label}/{rid} source declaration missing or ambiguous")
        att = [part.strip() for part in re.findall(attribute, attributes[0])]
        proof = f"#[kani::proof_for_contract({target})]" if mode == "check" else "#[kani::proof]"
        if f"#[kani::unwind({unwind})]" not in att or proof not in att or (
                mode == "replace" and f"#[kani::stub_verified({target})]" not in att):
            raise BindingError(f"{label}/{rid} source attribute mismatch: {att}")
        result[rid] = {"path": path, "macro": macro, "attributes": att, "unwind": unwind}
    return result


def validate_input(label, checkout, request):
    actual = identity(checkout)
    pin = request["pins"][label]
    if (actual["sha"], actual["tree"]) != (pin["sha"], pin["tree"]):
        raise BindingError(f"{label} commit/tree mismatch: {actual}")
    pilot.clean(checkout, label)
    hashes = request[f"{label}_files"]
    pilot.check_hashes(checkout, hashes)
    source_attributes = verify_source_attributes(checkout, label) if label != "tool" else None
    if label == "tool":
        fixture = (checkout / FIXTURE).read_text().splitlines()
        for root in request["roots"][:2]:
            expected_read = "ptr::read(base.add(2))" if root["id"] == "negative" else "ptr::read(base.add(i))"
            if expected_read not in fixture[root["read_line"] - 1]:
                raise BindingError("canary fixture read site mismatch")
    return {**actual, "files_sha256": hashes, "declared_nightly": pin["declared_nightly"],
            "source_attributes": source_attributes}


def validate_inputs(checkouts, request):
    return {label: validate_input(label, path, request) for label, path in checkouts.items()}


def job_boundary(epoch_file, limits):
    epoch = float(epoch_file.read_text())
    if not math.isfinite(epoch) or not 0 < epoch <= time.monotonic():
        raise BindingError("invalid job epoch")
    end = epoch + limits["job_minutes"] * 60
    return {"job_start_monotonic": epoch, "setup_end_monotonic": epoch + limits["setup_and_build_seconds"],
            "verification_end_monotonic": end - limits["job_cleanup_upload_seconds"],
            "job_end_monotonic": end}


def validate_isolation(paths, aux):
    for i, path in enumerate(paths):
        if any(path.is_relative_to(other) or other.is_relative_to(path) for other in paths[:i]):
            raise BindingError("control, both std trees, tool and receipt paths must be disjoint")
    for path in aux:
        if any(path.resolve().is_relative_to(other) for other in paths):
            raise BindingError(f"setup or clock path overlaps a checkout or receipt path: {path}")


def prepare(out, root, checkouts, request):
    # Use the v22 private path allocation. Render the two distinct stock invocations here.
    std = checkouts[root["pin"]]
    seed = {"argv": [], "source_root": "library", "cfg": {"off": None}}
    prepared = pilot.prepare(out, {**root, "object_bits": 12, "cbmc_args": [], "cfg": "off",
                                   "timeout_seconds": root["wall_seconds"]},
                             std, checkouts["tool"], seed)
    paths = prepared["paths"]
    standalone = root["pin"] == "tool"
    cwd = Path(paths["root_temp"])
    values = {"tool_script": str(checkouts["tool"] / "scripts/kani"), "selector": root["selector"],
              "harness_seconds": root["harness_seconds"], "export": paths["export"],
              "target": paths["kani_target_dir"], "std_library": str(std / "library")}
    template = request["standalone_argv" if standalone else "std_argv"]
    argv = []
    for arg in template:
        if arg == "{uninit}":
            if root["uninit"]:
                argv.extend(("-Z", "uninit-checks"))
        else:
            argv.append(arg.format_map(values))
    return {**prepared, "root": root, "argv": argv, "cwd": str(cwd),
            "expected_compiler": "TOOL_ATTESTATION",
            "environment": {**dict.fromkeys(request["environment_unset"]),
                            "CARGO_TARGET_DIR": paths["cargo_target_dir"], "TMPDIR": paths["tmpdir"]},
            "fixture": request["tool_files"][FIXTURE] if standalone else None,
            "std_checkout": None if standalone else str(std)}


def execute_root(journal, prepared, limits):
    # Same child PGID watchdog and successful-Popen journaling used by v22.
    paths = prepared["paths"]
    env = pilot.safe_env() | {k: v for k, v in prepared["environment"].items() if v is not None}
    env.update(NO_COLOR="1", TERM="dumb")
    Path(paths["tmpdir"]).mkdir()
    memory = pilot.stock_runner.group_memory_budget()
    local = min(limits["local_rss_kib"], memory["group_cap_kib"])
    started = start_error = None

    def spawn(*args, **kwargs):
        nonlocal started, start_error
        proc = subprocess.Popen(*args, **kwargs)
        started = {"pid": proc.pid, "utc": pilot.utc_now(), "monotonic": time.monotonic()}
        try:
            pilot.atomic(journal / "started.json", started)
        except OSError as exc:
            start_error = pilot.error(exc, "record child start")
        return proc

    original = pilot.stock_runner.subprocess
    pilot.stock_runner.subprocess = SimpleNamespace(
        Popen=spawn, PIPE=subprocess.PIPE, TimeoutExpired=subprocess.TimeoutExpired)
    try:
        seconds = prepared["timeout_seconds"]
        if time.monotonic() + seconds + limits["child_cleanup_seconds"] > prepared["phase_deadline_monotonic"]:
            pilot.atomic(journal / "not_run.json", gap("ROOT_WINDOW_UNAVAILABLE_BEFORE_CHILD", "NOT_RUN"))
            return None
        execution = pilot.stock_runner.execute(
            prepared["argv"], Path(prepared["cwd"]), Path(paths["execution"]), seconds,
            rss_cap_kib=local, stdout_cap=limits["stdout_bytes_per_root"],
            stderr_cap=limits["stderr_bytes_per_root"], export_path=Path(paths["export"]),
            export_cap=limits["export_bytes_per_root"], env=env, capture_tail=True,
            record_identity=True,
        )
    finally:
        pilot.stock_runner.subprocess = original
    keys = (
        "original_exit_code", "signal", "timed_out", "termination_reason", "elapsed_seconds",
        "child_shutdown_verified", "cleanup_errors", "process_identity", "interrupted_by_signal",
        "rss_peak_kib", "rss_scope", "rss_sample_period_seconds", "runner_error",
        "runner_exception", "pipe_reader_errors", "stdout_bytes", "stderr_bytes",
        "stdout_truncated", "stderr_truncated", "component_group_peak_kib", "component_rss_scope",
    )
    child = {k: execution.get(k) for k in keys}
    child.update(started=started, start_record_error=start_error, rss_cap_kib=local, memory_budget=memory,
                 nominal_rss_cap_kib=limits["local_rss_kib"], watchdog_seconds=seconds,
                 worker_observed_at_monotonic=time.monotonic())
    pilot.atomic(journal / "child.json", child)
    return child


def capture(path, cap, reported, truncated, tail=False):
    try:
        data = pilot.read_bounded(path, cap)
    except (OSError, BindingError) as exc:
        return None, {"bytes": None, "sha256": None, "observed_bytes": reported, "cap_bytes": cap,
                      "truncated": truncated,
                      "reason": "FILE_MISSING" if isinstance(exc, FileNotFoundError) else "READ_ERROR"}
    if len(data) > cap:
        truncated = True
        reported = path.stat().st_size if reported is None else reported
    data = data[:cap]
    layout = "PREFIX_AND_TAIL" if tail and truncated is True else "CONTIGUOUS_PREFIX"
    return data, {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "layout": layout,
                  "observed_bytes": reported, "cap_bytes": cap, "truncated": truncated,
                  "digest_scope": "CAPTURED_BYTES"}


def project(journal, prepared, request, receipt, child):
    limits, paths, root = request["limits"], prepared["paths"], prepared["root"]
    selector = root["selector"]
    captures = {stream: capture(Path(paths["execution"]) / f"{stream}.log",
                                limits[f"{stream}_bytes_per_root"], child.get(f"{stream}_bytes"),
                                child.get(f"{stream}_truncated"), tail=True)
                for stream in ("stdout", "stderr")}
    export = Path(paths["export"])
    captures["export"] = capture(export, limits["export_bytes_per_root"],
                                 export.stat().st_size if export.is_file() else None,
                                 False if child.get("child_shutdown_verified") else None)
    pilot.atomic(journal / "sources.json", {k: meta for k, (_, meta) in captures.items()})
    writer = ProjectionWriter(journal, limits["projection_bytes_per_root"])
    projections = {}
    for kind, source, parse in (("regular", "stdout", evidence.regular),
                                ("stock", "export", evidence.stock_export)):
        data, meta = captures[source]
        if data is None:
            result = gap(meta["reason"])
        elif source == "stdout" and meta["truncated"] is not False:
            # Only parse the known prefix of a split or unconfirmed capture.
            data = data[:meta["cap_bytes"] // 2]
            result = parse(data[:data.rfind(b"\n") + 1], selector)
        else:
            result = parse(data, selector)
        if data is not None and meta["truncated"] is not False:
            result = {**result, "state": "INCOMPLETE", "reason": "SOURCE_TRUNCATED_OR_UNCONFIRMED",
                      "parser_state": result["state"], "parser_reason": result.get("reason")}
        projections[kind] = result
        writer.save(kind, {**result, "selector": selector, "source_capture": meta})
    native = observations.native(captures)
    std = Path(prepared["std_checkout"]) if prepared["std_checkout"] else None
    blocker = observations.blocker(root, native, child, std)
    launch_error = child.get("runner_error")
    if (child.get("started") is None and isinstance(launch_error, str)
            and re.match(r"exec failed: \[Errno (?:2|8|13)\]", launch_error)
            and repr(prepared["argv"][0]) in launch_error):
        blocker = {"scope": "all", "reason": "SHARED_TOOL_LAUNCH_FAILURE",
                   "diagnostic": {"source": "child.runner_error", "text": launch_error}}
    joined = observations.reconcile(projections["regular"], projections["stock"], root, request,
                                    receipt.get("rustc_release"), child.get("original_exit_code"))
    if child.get("termination_reason") or not child.get("child_shutdown_verified"):
        joined.update(state="INCOMPLETE", reason="CHILD_EXECUTION_INCOMPLETE")
        if joined.get("calibration"):
            joined["calibration"]["state"] = "INCOMPLETE"
    writer.save("diagnostics", {**native, "selector": selector, "reconciliation": joined,
                                "shared_blocker": blocker})
    # Keep this compact when the projection hits a cap. Coordinates link into
    # the published diagnostics, or explicitly identify a truncated channel.
    pilot.atomic(journal / "observation-summary.json",
                 {"state": joined["state"], "calibration": joined.get("calibration"),
                  "shared_blocker": blocker, "verification_seconds": joined.get("verification_seconds"),
                  "native_compile_seconds": native["markers"]["compile_seconds"].get("native_values"),
                  "native_properties": joined.get("native_property_counts"),
                  "unsupported_count": len(joined["unsupported"]) if "unsupported" in joined else None,
                  "uninit_count": len(joined["uninit_reads"]) if "uninit_reads" in joined else None})


def worker(journal, request, attestation):
    prepared = pilot.read_record(journal / "prepared.json")
    phase(journal, "kani", prepared)
    child = execute_root(journal, prepared, request["limits"])
    if child is None:
        return 1
    if child.get("child_shutdown_verified") is not True and not child.get("runner_error"):
        return 1
    phase(journal, "native_projection", prepared)
    project(journal, prepared, request, attestation, child)
    phase(journal, "collection_closed", prepared)
    return int(bool(child.get("runner_exception") or child.get("start_record_error") or child.get("runner_error")))


def supervise_root(repo, out, checkouts, request, root, boundary, attestation, tool_receipt):
    limits = request["limits"]
    child_and_cleanup = root["wall_seconds"] + limits["child_cleanup_seconds"]
    worker_slot = limits["worker_startup_seconds"] + child_and_cleanup
    root_slot = worker_slot + limits["root_reap_reserve_seconds"]
    latest = boundary["verification_end_monotonic"] - root_slot - limits["root_launch_headroom_seconds"]
    if time.monotonic() > latest:
        return None
    journal = out / "state" / root["id"]
    prepared = prepare(out, root, checkouts, request)
    prepared.update(expected_compiler=tool_receipt["binaries"]["kani_compiler"],
                    rustc_release=tool_receipt["rustc_release"], toolchain=tool_receipt["rust_toolchain"])
    temp = Path(prepared["cwd"])
    try:
        temp.mkdir(parents=True)
        if prepared["fixture"]:
            copy = temp / "main.rs"
            shutil.copyfile(checkouts["tool"] / FIXTURE, copy)
            if pilot.digest(copy) != prepared["fixture"]:
                raise BindingError("standalone fixture copy does not match pin")
        memory = pilot.stock_runner.group_memory_budget()
        outer_cap = min(limits["outer_rss_kib"], memory["group_cap_kib"])
    except (OSError, pilot.stock_runner.RunnerError, ValueError, BindingError) as exc:
        pilot.atomic(journal / "prepared.json", prepared)
        pilot.atomic(journal / "not_run.json", gap("ROOT_PREPARATION_ERROR", "NOT_RUN",
                     error=pilot.error(exc, "prepare worker")))
        pilot.remove_temp(out, journal, prepared, True)
        return True

    # Give the child the full watchdog after parent preparation. The startup
    # allowance covers journaling and worker bootstrap before the child runs.
    launch = time.monotonic()
    if launch > latest:
        pilot.atomic(journal / "prepared.json", prepared)
        pilot.atomic(journal / "not_run.json", gap("JOB_LAUNCH_BUDGET_EXHAUSTED", "NOT_RUN"))
        pilot.remove_temp(out, journal, prepared, True)
        return None
    phase_deadline = launch + worker_slot
    prepared.update(root_deadline_monotonic=launch + root_slot, phase_deadline_monotonic=phase_deadline)
    pilot.atomic(journal / "prepared.json", prepared)
    argv = [sys.executable, str(repo / ENTRYPOINT), "_root", "--journal", str(journal),
            "--attestation", str(attestation)]
    now = time.monotonic()
    if now + child_and_cleanup > phase_deadline:
        pilot.atomic(journal / "not_run.json", gap("JOB_LAUNCH_BUDGET_EXHAUSTED", "NOT_RUN"))
        pilot.remove_temp(out, journal, prepared, True)
        return None
    try:
        supervisor = pilot.s3_runtime.supervise(
            argv, repo, pilot.safe_env() | {"PYTHONDONTWRITEBYTECODE": "1"},
            phase_deadline - now, outer_cap, Path(prepared["paths"]["worker_stderr"]))
    except Exception as exc:
        supervisor = {"call_error": pilot.error(exc, "supervise worker"), "containment": None}
    supervisor.update(rss_cap_kib=outer_cap, nominal_rss_cap_kib=limits["outer_rss_kib"], memory_budget=memory)
    pilot.atomic(journal / "supervisor.json", supervisor)
    reaped = (supervisor.get("containment") or {}).get("verified") is True
    if (reaped and not supervisor.get("orphan_survivors_at_worker_exit")
            and not (journal / "observation-summary.json").exists() and (journal / "started.json").exists()):
        pilot.atomic(journal / "fallback.json", {"reason": "PROJECTION_INTERRUPTED_AFTER_REAP"})
    else:
        pilot.remove_temp(out, journal, prepared, reaped)
    return reaped


def build_and_attest(tool, out, epoch_file, limits, request):
    # This entry point runs on the Actions runner after moving the exact tool checkout.
    out.mkdir(parents=True, exist_ok=False)
    (out / "tmp").mkdir()
    deadline = job_boundary(epoch_file, limits)["setup_end_monotonic"]
    try:
        validate_input("tool", tool, request)
        left = min(limits["tool_build_seconds"], deadline - time.monotonic())
        if left <= 0:
            raise BindingError("setup budget exhausted before stock build")
        memory = pilot.stock_runner.group_memory_budget()
        result = pilot.stock_runner.execute(
            ["cargo", "build-dev", "--", "--release"], tool, out, left,
            rss_cap_kib=min(limits["local_rss_kib"], memory["group_cap_kib"]),
            stdout_cap=limits["stdout_bytes_per_root"], stderr_cap=limits["stderr_bytes_per_root"],
            env=pilot.safe_env() | {"CARGO_BUILD_JOBS": "1", "TMPDIR": str(out / "tmp")},
            capture_tail=True, record_identity=True,
        )
        result["setup_total_seconds"] = limits["setup_and_build_seconds"] - (deadline - time.monotonic())
        result["build_memory_budget"] = memory
        public_keys = ("original_exit_code", "child_shutdown_verified", "cleanup_errors", "runner_error",
                       "runner_exception", "timed_out", "termination_reason", "stdout_truncated",
                       "stderr_truncated", "setup_total_seconds", "elapsed_seconds", "rss_peak_kib",
                       "build_memory_budget", "stdout_bytes", "stderr_bytes", "component_group_peak_kib")
        receipt = {key: result.get(key) for key in public_keys}
        if not pilot.setup_ready({"receipt": receipt}, limits):
            captures = {stream: capture(out / f"{stream}.log", limits[f"{stream}_bytes_per_root"],
                                        result.get(f"{stream}_bytes"), result.get(f"{stream}_truncated"),
                                        tail=True) for stream in ("stdout", "stderr")}
            receipt["diagnostics"] = observations.native(captures)
            receipt["captures"] = {key: meta for key, (_, meta) in captures.items()}
        pilot.atomic(out / "receipt.json", receipt)
        if not pilot.setup_ready({"receipt": receipt}, limits):
            raise BindingError("stock build incomplete or unsuccessful")
        document = tool_attestation.attest(tool, deadline)
        document["setup_elapsed_seconds"] = limits["setup_and_build_seconds"] - (deadline - time.monotonic())
    except Exception as exc:
        pilot.atomic(out / "attestation.json", {"status": "INCOMPLETE", "error": pilot.error(exc, "build or attest")})
        raise
    pilot.atomic(out / "attestation.json", document)


def campaign(repo, checkouts, out, setup_receipt, attestation, epoch_file):
    request = load_request(repo)
    validate_isolation((repo, *checkouts.values(), out), (setup_receipt, attestation, epoch_file))
    state = out / "state"
    state.mkdir(parents=True, exist_ok=False)
    journal = state / "campaign.json"
    limits = request["limits"]
    attestation_record = read_attestation(attestation, limits)
    tool_receipt = attestation_record.get("receipt", {})
    record = {"setup": pilot.read_setup(setup_receipt, limits), "tool_attestation": attestation_record,
              "blockers": {}}

    def close(reason=None, exc=None):
        record.update(stop_reason=reason, sequence_closed=True)
        if exc is not None:
            record["stop_error"] = pilot.error(exc, reason)
        pilot.atomic(journal, record)
        return int(reason not in (None, "JOB_LAUNCH_BUDGET_EXHAUSTED"))

    pilot.atomic(journal, record)
    if not pilot.setup_ready(record["setup"], limits):
        return close("SETUP_UNAVAILABLE_OR_UNSUCCESSFUL")
    try:
        boundary = job_boundary(epoch_file, limits)
        record["job_boundary"] = boundary
        request_hash = pilot.digest(repo / REQUEST)
        if time.monotonic() > boundary["setup_end_monotonic"]:
            return close("SETUP_WINDOW_EXHAUSTED")
        record["input_identities"] = {"control": validate_control(repo, request), **validate_inputs(checkouts, request)}
        tool_attestation.verify(tool_receipt, checkouts["tool"], request,
                                min(time.monotonic() + 45, boundary["verification_end_monotonic"]))
        pilot.atomic(journal, record)
    except (OSError, ValueError, BindingError, subprocess.SubprocessError, tool_attestation.AttestationError) as exc:
        return close("INPUT_OR_SETUP_VALIDATION_FAILED", exc)

    stop = None
    for root in request["roots"]:
        blocked = record["blockers"].get("all") or record["blockers"].get(root["pin"])
        if blocked:
            pilot.atomic(state / root["id"] / "not_run.json", gap(blocked["reason"], "NOT_RUN", blocker=blocked))
            continue
        try:
            if pilot.digest(repo / REQUEST) != request_hash or read_attestation(attestation, limits) != attestation_record:
                raise BindingError("request or setup attestation changed")
            reaped = supervise_root(repo, out, checkouts, request, root, boundary, attestation, tool_receipt)
        except (OSError, ValueError, BindingError, subprocess.SubprocessError) as exc:
            return close("ROOT_SUPERVISION_ERROR", exc)
        if reaped is not True:
            stop = "JOB_LAUNCH_BUDGET_EXHAUSTED" if reaped is None else "SUPERVISOR_REAP_UNCONFIRMED"
            break
        observation = pilot.read_record(state / root["id"] / "observation-summary.json") or {}
        blocked = observation.get("shared_blocker")
        if blocked:
            record["blockers"][blocked["scope"]] = {**blocked, "root": root["id"]}
            pilot.atomic(journal, record)
    try:
        closed = {"control": validate_control(repo, request), **validate_inputs(checkouts, request)}
        if closed != record["input_identities"] or read_attestation(attestation, limits) != attestation_record:
            raise BindingError("immutable campaign input changed")
        tool_attestation.verify(tool_receipt, checkouts["tool"], request,
                                min(time.monotonic() + 20, boundary["job_end_monotonic"] - 8 * 60))
        record["closing_input_identities"] = closed
    except (OSError, ValueError, BindingError, subprocess.SubprocessError, tool_attestation.AttestationError) as exc:
        return close("CLOSING_INPUT_VALIDATION_FAILED", exc)
    return close(stop)


def collect_root(out, root, stop_reason, limits):
    journal = out / "state" / root["id"]
    prepared = pilot.read_record(journal / "prepared.json")
    child = pilot.read_record(journal / "child.json")
    started = pilot.read_record(journal / "started.json") or (child or {}).get("started")
    supervisor = pilot.read_record(journal / "supervisor.json")
    not_run = pilot.read_record(journal / "not_run.json")
    cutoff = (supervisor or {}).get("cutoff")
    reaped = ((supervisor or {}).get("containment") or {}).get("verified") is True
    survivors = (supervisor or {}).get("orphan_survivors_at_worker_exit")
    if not_run:
        status, reason = "NOT_RUN", not_run["reason"]
    elif not prepared:
        status, reason = "NOT_RUN", stop_reason or "ROOT_NEVER_PREPARED"
    elif not reaped:
        status, reason = "UNKNOWN", "SUPERVISOR_REAP_UNCONFIRMED"
    elif not started:
        status, reason = "NOT_RUN", "CHILD_SPAWN_FAILED" if (child or {}).get("runner_error") else "CHILD_START_UNOBSERVED"
    elif cutoff or survivors or not child or child.get("termination_reason") or child.get("signal"):
        status, reason = "INTERRUPTED", cutoff or (child or {}).get("termination_reason") or "CHILD_EXIT_INCOMPLETE"
    elif ((supervisor or {}).get("worker_exit") != 0
          or child.get("child_shutdown_verified") is not True or child.get("original_exit_code") is None):
        status, reason = "INTERRUPTED", "RUNNER_TRANSPORT_ERROR"
    else:
        status, reason = "EXITED", None
    fallback = pilot.read_record(journal / "fallback.json")
    if fallback and prepared and reaped:
        project_cutoff(journal, prepared, child or {}, limits)
    staged = (pilot.read_record(journal / "files.json") or {}) if reaped and not survivors else {}
    files = {}
    total = 0
    for kind, name in MEMBERS.items():
        entry = staged.get(kind) or gap(reason or "PROJECTION_PHASE_INCOMPLETE", path=None)
        if entry["path"] is not None:
            data = pilot.read_bounded(journal / name, limits["projection_bytes_per_root"] - total)
            total += len(data)
            if (entry["path"] != name or total > limits["projection_bytes_per_root"]
                    or len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]):
                entry = gap("PROJECTION_DIGEST_OR_SIZE_MISMATCH", path=None)
            else:
                entry["path"] = f"{root['id']}/{name}"
                pilot.atomic_bytes(out / "artifact" / entry["path"], data, out / "state")
        files[kind] = entry
    row = {
        **root, "status": status, "reason": reason, "not_run": not_run, "invocation": prepared,
        "started": started, "child": child, "supervisor": compact_supervisor(supervisor),
        "sources": pilot.read_record(journal / "sources.json"),
        "phases": [stamp for name in ("kani", "native_projection", "collection_closed")
                   if (stamp := pilot.read_record(journal / f"phase-{name}.json")) is not None],
        "last_phase": pilot.read_record(journal / "phase.json"), "fallback": fallback,
        "observations": (pilot.read_record(journal / "observation-summary.json") or gap("PROJECTIONS_UNAVAILABLE"))
        if reaped and not survivors else gap("ROOT_CONTAINMENT_OR_EVIDENCE_UNCONFIRMED"),
        "temp_cleanup": pilot.remove_temp(out, journal, prepared, reaped), "files": files,
        "projection_cap_bytes": limits["projection_bytes_per_root"],
    }
    for entry in reversed(list(files.values())):
        if len(encode(row)) + sum(e.get("bytes") or 0 for e in files.values() if e["path"]) <= row["projection_cap_bytes"]:
            break
        drop_member(out, entry, "ROOT_PUBLICATION_CAP")
    return row


def project_cutoff(journal, prepared, child, limits):
    """Retain typed terminal/compile diagnostics when the outer worker was reaped mid-projection."""
    original = pilot.read_record(journal / "files.json") or {}
    if original.get("diagnostics") is not None:
        return
    paths = prepared["paths"]
    captures = {stream: capture(Path(paths["execution"]) / f"{stream}.log", limits[f"{stream}_bytes_per_root"],
                                child.get(f"{stream}_bytes"), child.get(f"{stream}_truncated"), tail=True)
                for stream in ("stdout", "stderr")}
    if not (journal / "sources.json").exists():
        export = Path(paths["export"])
        captures["export"] = capture(export, limits["export_bytes_per_root"],
                                     export.stat().st_size if export.is_file() else None, None)
        pilot.atomic(journal / "sources.json", {key: meta for key, (_, meta) in captures.items()})
    native = observations.native(captures, edge_bytes=64 * 1024)
    writer = ProjectionWriter(journal, limits["projection_bytes_per_root"] -
                              sum(entry.get("bytes") or 0 for entry in original.values()))
    writer.index.update(original)
    writer.save("diagnostics", {**native, "state": "INCOMPLETE", "reason": "OUTER_WORKER_INTERRUPTED",
                                "selector": prepared["root"]["selector"]})


def drop_member(out, entry, reason):
    if entry["path"] is not None:
        (out / "artifact" / entry["path"]).unlink(missing_ok=True)
        entry.update(path=None, state="INCOMPLETE", reason=reason)


def pair_manifest(off, on):
    def entry(row):
        return {key: row[key] for key in ("id", "uninit", "status", "reason", "files")}
    def metric(row, source, key):
        value = (row.get(source) or {}).get(key)
        if isinstance(value, list) and len(value) == 1:
            value = float(value[0])
        return value if type(value) in (int, float) and math.isfinite(value) else None
    deltas = {}
    for label, source, key in (("verification_seconds", "observations", "verification_seconds"),
                               ("compile_seconds", "observations", "native_compile_seconds"),
                               ("child_wall_seconds", "child", "elapsed_seconds"),
                               ("child_peak_rss_kib", "child", "rss_peak_kib")):
        a, b = metric(off, source, key), metric(on, source, key)
        complete = (a is not None and b is not None and all(row["status"] == "EXITED"
                    and row["observations"]["state"] == "CONSISTENT"
                    and all(row["files"][k]["path"] for k in ("regular", "stock", "diagnostics"))
                    for row in (off, on)))
        deltas[label] = {"off": a, "on": b, "state": "OBSERVED" if complete else "INCOMPLETE",
                         "on_minus_off": b - a if complete else None,
                         "on_over_off": b / a if complete and a else None}
    return {"pair": off["pair"], "pin": off["pin"], "selector": off["selector"], "mode": off["mode"],
            "off": entry(off), "on": entry(on), "measurements": deltas}


def validate_artifact(artifact, expected, limit):
    total, seen = 0, set()
    directories = {str(Path(name).parent) for name in expected}
    for path in artifact.rglob("*"):
        name = path.relative_to(artifact).as_posix()
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode) and name in directories:
            continue
        if not stat.S_ISREG(info.st_mode) or name not in expected:
            raise BindingError(f"unexpected artifact member: {name}")
        total += info.st_size
        entry = expected[name]
        if total > limit or entry != (info.st_size, pilot.digest(path)):
            raise BindingError(f"artifact size or digest mismatch: {name}")
        seen.add(name)
    if seen != expected.keys():
        raise BindingError(f"missing artifact members: {sorted(expected.keys() - seen)}")


def finish(repo, checkouts, out, setup_receipt, attestation, epoch_file):
    request = load_request(repo)
    validate_isolation((repo, *checkouts.values(), out), (setup_receipt, attestation, epoch_file))
    limits = request["limits"]
    state, artifact = out / "state", out / "artifact"
    state.mkdir(parents=True, exist_ok=True)
    artifact.mkdir(exist_ok=True)
    previous = pilot.read_record(state / "campaign.json") or {}
    workflows = {key: os.environ.get(key.upper() + "_OUTCOME")
                 for key in ("control", "source", "setup", "build", "collection")}
    if previous:
        stop = previous.get("stop_reason") if previous.get("sequence_closed") else "COLLECTION_INTERRUPTED"
    else:
        failed = next((k for k, v in workflows.items() if v in ("failure", "cancelled")), None)
        stop = f"{failed.upper()}_STEP_{workflows[failed].upper()}" if failed else "COLLECTION_NOT_ENTERED"
    try:
        boundary = job_boundary(epoch_file, limits)
    except (OSError, ValueError, BindingError):
        boundary = None
    rows = [collect_root(out, root, stop, limits) for root in request["roots"]]
    calibration = {r["id"]: r["observations"].get("calibration") or gap("NATIVE_CANARY_EVIDENCE_INCOMPLETE")
                   for r in rows[:2]}
    doc = {
        "schema": request["result_schema"], "proof_credit": "NONE",
        "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "event": os.environ.get("GITHUB_EVENT_NAME"), "ref": os.environ.get("GITHUB_REF"),
        "trigger_sha": os.environ.get("GITHUB_SHA"), "job_status": os.environ.get("JOB_STATUS"),
        "workflow_step_outcomes": workflows, "identities": {
            "control": pilot.observed_identity(repo, control_identity),
            **{label: pilot.observed_identity(path, identity) for label, path in checkouts.items()},
        },
        "intended_pins": request["pins"], "validated_inputs": previous.get("input_identities"),
        "closing_inputs": previous.get("closing_input_identities") or gap("CLOSING_INPUT_VALIDATION_INCOMPLETE"),
        "setup": previous.get("setup") or pilot.read_setup(setup_receipt, limits),
        "tool_attestation": previous.get("tool_attestation") or read_attestation(attestation, limits),
        "job_boundary": boundary, "limits": limits, "stop_reason": stop, "stop_error": previous.get("stop_error"),
        "shared_blockers": previous.get("blockers", {}), "evidence_channel": request["evidence"], "roots": rows,
        "calibration": {"state": "INCOMPLETE", "canaries": calibration},
    }

    def materialization():
        doc["calibration"]["state"] = ("CANARIES_MATCH" if
            all(calibration[r["id"]]["state"] == "MATCH" and
                all(r["files"][kind]["path"] for kind in MEMBERS) and r["status"] == "EXITED" for r in rows[:2])
            else "INCOMPLETE")
        pairs = {f"pairs/{off['pair']}.json": encode(pair_manifest(off, on))
                 for off, on in zip(rows[2::2], rows[3::2])}
        doc["pairs"] = {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                        for name, data in pairs.items()}
        index = encode(doc)
        members = {entry["path"]: (entry["bytes"], entry["sha256"])
                   for row in rows for entry in row["files"].values() if entry["path"]}
        total = sum(n for n, _ in members.values()) + sum(map(len, pairs.values())) + len(index)
        return index, pairs, members, total

    index, pairs, members, total = materialization()
    for row in reversed(rows):
        for entry in reversed(list(row["files"].values())):
            if total <= limits["artifact_bytes"]:
                break
            if entry["path"]:
                drop_member(out, entry, "AGGREGATE_ARTIFACT_CAP")
                index, pairs, members, total = materialization()
    if total > limits["artifact_bytes"]:
        pairs = {}
        doc["pairs"] = {}
        doc["pair_publication"] = gap("AGGREGATE_ARTIFACT_CAP")
        index = encode(doc)
        if len(index) > limits["artifact_bytes"]:
            # A last-resort index keeps all row identities and explains the cutoff.
            doc = {k: doc[k] for k in ("schema", "proof_credit", "trigger_sha", "limits", "calibration", "stop_reason")}
            doc.update(index_publication=gap("INDEX_DETAIL_CUTOFF"), roots=[{k: row[k] for k in
                       ("id", "pin", "selector", "status", "reason")} for row in rows])
            index = encode(doc)
        if len(index) > limits["artifact_bytes"]:
            raise BindingError("aggregate cap cannot retain even the minimal index")
    for name, data in {**pairs, RESULT: index}.items():
        pilot.atomic_bytes(artifact / name, data, state)
        members[name] = (len(data), hashlib.sha256(data).hexdigest())
    # Dropped projections can leave empty private-output directories.
    for folder in artifact.iterdir():
        if folder.is_dir() and not any(folder.iterdir()):
            folder.rmdir()
    validate_artifact(artifact, members, limits["artifact_bytes"])
    return doc


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("validate")
    for name in ("check-source", "run", "finish"):
        cmd = commands.add_parser(name)
        for label in ("candidate", "pr752", "tool"):
            cmd.add_argument(f"--{label}", type=Path, required=True)
        if name != "check-source":
            for option in ("out", "setup-receipt", "attestation", "job-epoch"):
                cmd.add_argument(f"--{option}", type=Path, required=True)
    build = commands.add_parser("build-and-attest")
    for option in ("tool", "out", "job-epoch"):
        build.add_argument(f"--{option}", type=Path, required=True)
    inner = commands.add_parser("_root")
    inner.add_argument("--journal", type=Path, required=True)
    inner.add_argument("--attestation", type=Path, required=True)
    args = parser.parse_args()
    try:
        request = load_request(REPO)
        if args.command == "validate":
            print(json.dumps(validate_control(REPO, request)))
        elif args.command == "check-source":
            paths = {label: getattr(args, label).resolve() for label in ("candidate", "pr752", "tool")}
            validate_isolation((REPO, *paths.values()), ())
            print(json.dumps(validate_inputs(paths, request)))
        elif args.command == "build-and-attest":
            validate_control(REPO, request)
            build_and_attest(args.tool.resolve(), args.out.resolve(), args.job_epoch, request["limits"], request)
        elif args.command == "_root":
            receipt = read_attestation(args.attestation, request["limits"]).get("receipt", {})
            return worker(args.journal, request, receipt)
        else:
            paths = {label: getattr(args, label).resolve() for label in ("candidate", "pr752", "tool")}
            action = campaign if args.command == "run" else finish
            result = action(REPO, paths, args.out.resolve(), args.setup_receipt.resolve(),
                            args.attestation.resolve(), args.job_epoch.resolve())
            return result if isinstance(result, int) else 0
    except Exception as exc:
        print(json.dumps(pilot.error(exc, args.command)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
