"""Discover inherited REV2 harnesses and measure the three N32 closure singletons."""
from __future__ import annotations

import argparse
from collections import Counter

from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import time

import request as spec
import setup_diagnostics
import stdout_relay
import supervisor


class RunError(RuntimeError):
    pass


class ReceiptDeadlineExceeded(Exception):
    pass


# Keep the last second of the existing five-second receipt budget for the mandatory commit.
RECEIPT_COMMIT_RESERVE_SECONDS = 1
PINS_SECONDS = 45
SOURCES_SECONDS = 120
MEASUREMENT_JOURNAL_SECONDS = spec.LIMITS["measurement_journal_seconds"]
UPLOAD_LAUNCH_HEADROOM_SECONDS = spec.LIMITS["upload_launch_headroom_seconds"]
# Allow the identity gate time to run when measurement starts before the setup cutoff.
MEASURE_SECONDS = (spec.LIMITS["slots_seconds"] + spec.LIMITS["post_attestation_seconds"]
                   + MEASUREMENT_JOURNAL_SECONDS + spec.LIMITS["measure_gate_seconds"])


@contextmanager
def receipt_window(deadline, operation="receipt publication"):
    """Interrupt work in the main thread at the absolute deadline."""
    def expire(_signum, _frame):
        raise ReceiptDeadlineExceeded(f"{operation} window exhausted")

    previous = signal.signal(signal.SIGALRM, expire)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            expire(None, None)
        signal.setitimer(signal.ITIMER_REAL, remaining)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(data, allow_nan=False, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    temp.replace(path)


def output(key, value):
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
        print(f"{key}={value}", file=stream)


def frozen_env(directory, cfg=(), jobs=None):
    env = {key: value for key, value in os.environ.items()
           if key not in {"RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN",
                          "CARGO_BUILD_RUSTFLAGS", "KANI_FLAGS", "KANI_ARGS", "KANI_JOBS"}}
    env["CARGO_TARGET_DIR"] = str(directory / "cargo-target")
    for key in ("TMPDIR", "TMP", "TEMP"):
        env[key] = str(directory / "tmp")
    env["CARGO_TERM_COLOR"] = "never"
    env["NO_COLOR"] = "1"
    if cfg:
        env["RUSTFLAGS"] = " ".join(f"--cfg={flag}" for flag in cfg)
    if jobs is not None:
        env["KANI_JOBS"] = str(jobs)
    return env


def workspace():
    checkout_root = Path(os.environ["GITHUB_WORKSPACE"]).resolve(strict=True)
    state = Path(os.environ["REV2_STATE"]).resolve(strict=True)
    temp = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    spec.require(state == temp / "ch8-rev2-gen-stable-n32-closure",
                 "state is outside the frozen N32 closure runner path")
    std, tool = (checkout_root / "std").resolve(), (checkout_root / "tool").resolve()
    spec.require(std == checkout_root / "std" and tool == checkout_root / "tool"
                 and spec.REPO == checkout_root / "control", "source paths must be separate checkouts")
    return state, std, tool


def clocks(state):
    epoch = float((state / "epoch").read_text())
    spec.require(math.isfinite(epoch) and 0 < epoch <= time.monotonic(), "invalid job epoch")
    limits = spec.LIMITS
    spec.require(limits["reap_seconds"] == supervisor.TERM_GRACE + supervisor.KILL_GRACE,
                 "reap budget does not match supervisor grace periods")
    stride = spec.slot_seconds() + limits["launch_headroom_seconds"]
    # The separate identity gate occupies the minute between prepare and slot 1.
    slots_offset = limits["setup_seconds"] + limits["measure_gate_seconds"] + limits["slots_seconds"]
    starts = {key: slots_offset - (len(spec.SLOT_IDS) - index) * stride
              for index, key in enumerate(spec.SLOT_IDS)}
    spec.require(limits["slots_seconds"] == len(spec.SLOT_IDS) * stride
                 and starts == spec.LATEST_START_OFFSETS, "REV2 latest starts do not fit the slot window")
    verify_offset = slots_offset + limits["post_attestation_seconds"]
    finish_offset = verify_offset + limits["finish_seconds"]
    finalize_offset = finish_offset + limits["upload_seconds"]
    # Finish and upload admission share the cutoff that reserves the full upload window.
    publication_offset = finish_offset - UPLOAD_LAUNCH_HEADROOM_SECONDS
    reserve_offset = finalize_offset + limits["reserve_seconds"]
    spec.require(reserve_offset == limits["planned_job_seconds"] <= limits["job_seconds"],
                 "REV2 plan exceeds job budget")
    return {"epoch": epoch, "setup_deadline": epoch + limits["setup_seconds"] + limits["measure_gate_seconds"],
            "prepare_deadline": epoch + limits["setup_seconds"],
            "slots_deadline": epoch + slots_offset, "verify_deadline": epoch + verify_offset,
            "finalize_deadline": epoch + finalize_offset, "reserve_deadline": epoch + reserve_offset,
            "job_deadline": epoch + limits["job_seconds"],
            "receipt_publication_deadline": epoch + publication_offset,
            "latest_starts": {key: epoch + offset for key, offset in starts.items()}}


def platform_name():
    name = platform.system()
    arch = platform.machine()
    spec.require(name == "Linux" and arch == "x86_64", f"unsupported platform {name}/{arch}")
    return name


def machine():
    name = platform_name()
    memory = supervisor.memory_snapshot()
    cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name") and ":" in line), platform.processor())
    return {"os": name, "release": platform.platform(), "arch": platform.machine(),
            "runner_image": os.environ.get("ImageOS"), "runner_image_version": os.environ.get("ImageVersion"),
            "runner_arch": os.environ.get("RUNNER_ARCH"), "cpu": cpu or "UNKNOWN",
            "logical_cpus": os.cpu_count(), "memory": memory}


def sources(state, std, tool, request, trigger, *, deadline):
    stage = {"trigger": trigger, "machine": machine(), "stdlib_base": spec.identity(std, spec.BASE, deadline=deadline),
             "tool_before_setup": spec.identity(tool, spec.TOOL, deadline=deadline)}
    dump(state / "source.json", stage)
    bundle = spec.HERE / "std-overlay.bundle"
    spec.git(std, "bundle", "verify", str(bundle), deadline=deadline)
    heads = spec.git(std, "bundle", "list-heads", str(bundle), deadline=deadline).splitlines()
    spec.require(heads == [request["overlay"][0] + " HEAD"], "overlay bundle advertised unexpected refs")
    spec.git(std, "bundle", "unbundle", str(bundle), deadline=deadline)
    # Read objects without creating any checkout branch or remote ref.
    overlay = request["overlay"][0]
    chain = (spec.CAL1_OVERLAY, spec.CAL2_OVERLAY, spec.FIX3_OVERLAY, spec.BINDING_OVERLAY,
             spec.GEOMETRIES_OVERLAY, spec.CONSUMER_OVERLAY, spec.COMPOSITE_OVERLAY, spec.N17_OVERLAY,
             spec.N18_N19_PROVIDERS_OVERLAY, spec.N18_N19_CONSUMER_R1,
             spec.N18_N19_CONSUMER_FIX1, spec.N20_N21_PROVIDERS_OVERLAY, spec.MERGE_PAIR_FIXED_OVERLAY,
             spec.N20_N21_CONSUMER_OVERLAY, spec.N22_N25_PROVIDERS_OVERLAY,
             spec.N22_N25_CONSUMER_OVERLAY, spec.HALVES_OVERLAY, spec.MERGE_OVERLAY,
             spec.N26_N31_CONSUMER_OVERLAY, spec.COPY_BACK_OVERLAY, spec.U64_N13_OVERLAY,
             spec.U64_N14_N17_OVERLAY, spec.U64_N18_N19_R1_OVERLAY,
             spec.U64_N18_N19_FIX1_OVERLAY, spec.U64_N20_N21_FINAL_OVERLAY,
             spec.N22_N25_FINAL_OVERLAY, spec.N26_N32_PROVIDERS_OVERLAY,
             spec.N26_N32_CONSUMER_OVERLAY, spec.PILOT_OVERLAY, spec.FIX1_OVERLAY,
             spec.CLOSE_R1_OVERLAY, tuple(request["close_overlay"]),
             tuple(request["wide_witness_overlay"]), tuple(request["n10_wide_witness_overlay"]),
             tuple(request["n12_wide_witness_overlay"]), tuple(request["wide_n12_n14_overlay"]),
             tuple(request["n32_pilot_overlay"]), tuple(request["n32_closure_overlay"]))
    parent = spec.BASE[0]
    for commit, expected_tree in chain:
        spec.require(spec.git(std, "show", "-s", "--format=%T%n%P", commit).splitlines() ==
                     [expected_tree, parent], "unpacked overlay tree/parent mismatch")
        parent = commit
    stage["overlay_delta"] = spec.check_overlay_layout(std, overlay)
    stage["source_bindings"] = spec.check_source_bindings(std, request, deadline=deadline)
    check_native_source(std, request)
    stage["native_coordinates_checked"] = True
    dump(state / "source.json", stage)


def check_native_source(std, request):
    overlay = request["overlay"][0]
    spec.check_native_coordinates(std, overlay, request["source_bindings"]["merge_roster"],
                                  module_file=spec.MERGE_FILE)
    spec.check_native_coordinates(std, overlay, request["source_bindings"]["consumer_roster"],
                                  module_file=spec.HISTORICAL_CONSUMER_FILE)
    spec.check_native_coordinates(std, overlay, request["source_bindings"]["copy_back_roster"],
                                  module_file=spec.COPY_BACK_FILE)
    spec.check_native_coordinates(std, spec.U64_N13_OVERLAY[0],
                                  request["source_bindings"]["u64_n13_roster"], module_file=spec.U64_N13_FILE)
    spec.check_native_coordinates(std, overlay, request["source_bindings"]["u64_n14_n17_roster"],
                                  module_file=spec.U64_N14_N17_FILE)
    spec.check_native_coordinates(std, overlay, request["source_bindings"]["u64_n18_n19_roster"],
                                  module_file=spec.U64_N18_N19_FILE)
    spec.check_native_coordinates(std, spec.U64_N20_N21_FINAL_OVERLAY[0],
                                  request["source_bindings"]["u64_n20_n21_roster"],
                                  module_file=spec.U64_N20_N21_FILE)
    spec.check_native_coordinates(std, overlay, request["source_bindings"]["u64_n22_n25_roster"],
                                  module_file=spec.U64_N22_N25_PROVIDERS_FILE)
    spec.check_native_coordinates(std, overlay, request["source_bindings"]["u64_n26_n32_providers_roster"],
                                  module_file=spec.U64_N26_N32_PROVIDERS_FILE)
    spec.check_native_coordinates(std, overlay, request["source_bindings"]["u64_n26_n32_consumer_roster"],
                                  module_file=spec.U64_N26_N32_CONSUMER_FILE)
    spec.check_native_coordinates(std, spec.PILOT_OVERLAY[0], request["source_bindings"]["pilot_roster"],
                                  module_file=spec.PILOT_MODULE_FILE)
    spec.check_native_coordinates(std, spec.FIX1_OVERLAY[0], request["source_bindings"]["pilot_fix1_roster"],
                                  prefix=spec.FIX1_PREFIX, module_file=spec.PILOT_MODULE_FILE)
    spec.check_native_coordinates(std, spec.CLOSE_OVERLAY[0],
                                  request["source_bindings"]["pilot_close_roster"],
                                  prefix=spec.CLOSE_PREFIX, module_file=spec.CLOSE_MODULE_FILE)
    spec.check_native_coordinates(std, spec.WIDE_WITNESS_OVERLAY[0], request["source_bindings"]["wide_witness_roster"],
                                  prefix=spec.WIDE_WITNESS_PREFIX, module_file=spec.CLOSE_MODULE_FILE)
    spec.check_native_coordinates(std, spec.N10_WITNESS_OVERLAY[0], request["source_bindings"]["n10_wide_witness_roster"],
                                  prefix=spec.N10_WITNESS_PREFIX, module_file=spec.CLOSE_MODULE_FILE)
    # Historical witness roots are checked on their own revisions; the append-only chain keeps their bytes.
    spec.check_native_coordinates(std, spec.N12_WITNESS_OVERLAY[0], request["source_bindings"]["n12_wide_witness_roster"],
                                  prefix=spec.N12_WITNESS_PREFIX, module_file=spec.CLOSE_MODULE_FILE)
    spec.check_native_coordinates(std, spec.WIDE_N12_N14_OVERLAY[0], request["source_bindings"]["wide_n12_n14_roster"],
                                  prefix=spec.WIDE_N12_N14_PREFIX, module_file=spec.CLOSE_MODULE_FILE)
    spec.check_native_coordinates(std, spec.N32_PILOT_OVERLAY[0], request["source_bindings"]["n32_pilot_roster"],
                                  prefix=spec.N32_PREFIX, module_file=spec.CLOSE_MODULE_FILE)
    spec.check_native_coordinates(std, overlay, request["source_bindings"]["n32_closure_roster"],
                                  prefix=spec.N32_CLOSURE_PREFIX, module_file=spec.CLOSE_MODULE_FILE)


def can_start(deadline, seconds, now=None):
    now = time.monotonic() if now is None else now
    return now + seconds + spec.LIMITS["launch_headroom_seconds"] <= deadline


def invoke(argv, *, cwd, directory, deadline, nominal_kib, jobs=None, cfg=(), build=False,
           cargo_verbose=False, diagnostics=None, path_prefix=None):
    # Bind the command to an isolated working/output directory and the planned limits.
    env = frozen_env(directory, cfg, jobs)
    if path_prefix is not None:
        # Only the relay slot puts its private `cbmc` first. The rest of PATH stays stock.
        env["PATH"] = path_prefix + os.pathsep + env.get("PATH", "")
    (directory / "tmp").mkdir(parents=True)
    if cargo_verbose:
        env["CARGO_TERM_VERBOSE"] = "true"
    if build:
        # Leave the stock scripts/kani build output in the tool worktree.
        env.pop("CARGO_TARGET_DIR")
        env["CARGO_BUILD_JOBS"] = "2"
    return supervisor.run(argv, cwd=cwd, env=env, directory=directory, deadline=deadline,
                          nominal_kib=nominal_kib, reserve_kib=spec.LIMITS["reserve_kib"], diagnostics=diagnostics)


def child_ok(child):
    return (child.get("status") == "COMPLETED" and child.get("stop_reason") == "EXITED"
            and child.get("exit_code") == 0 and child.get("reaped") is True
            and child.get("sampler_valid") is True and child.get("stdout_complete") is True
            and child.get("stderr_complete") is True)


def read_list(path):
    spec.require(path.is_file() and 0 < path.stat().st_size <= 4 * spec.MIB, "missing or oversized Kani list")
    doc = spec.read(path)
    spec.require(isinstance(doc, dict) and doc.get("file-version") == "0.1", "unsupported Kani list file-version")
    result = []
    for kind in ("standard-harnesses", "contract-harnesses"):
        bucket = doc.get(kind)
        spec.require(isinstance(bucket, dict), f"missing Kani list {kind}")
        for file, names in bucket.items():
            spec.require(isinstance(file, str) and isinstance(names, list) and
                         all(isinstance(name, str) and name for name in names), "malformed Kani list entries")
            result.extend({"selector": name, "kind": kind, "file": file} for name in names)
    spec.require(len(result) > 0, "Kani list contained no harnesses")
    contracts = doc.get("contracts")
    spec.require(isinstance(contracts, list), "missing Kani list contract objects")
    targets = {}
    for contract in contracts:
        spec.require(isinstance(contract, dict) and
                     all(isinstance(contract.get(field), str) and contract[field]
                         for field in ("function", "file")) and
                     isinstance(contract.get("harnesses"), list) and
                     all(isinstance(selector, str) and selector for selector in contract["harnesses"]),
                     "malformed Kani list contract object")
        for selector in contract["harnesses"]:
            targets.setdefault(selector, []).append((contract["function"], contract["file"]))
    known = {entry["selector"] for entry in result}
    for entry in result:
        if entry["selector"] in targets:
            entry["targets"] = targets[entry["selector"]]
    spec.require(not any(selector.startswith((spec.MERGE_PREFIX, spec.PREFIX, spec.HISTORICAL_CONSUMER_PREFIX,
                                              spec.COPY_BACK_PREFIX, spec.U64_N13_PREFIX, spec.U64_N14_N17_PREFIX,
                                              spec.U64_N18_N19_PREFIX, spec.U64_N22_N25_PROVIDERS_PREFIX,
                                              spec.U64_N26_N32_CONSUMER_PREFIX, spec.PILOT_PREFIX,
                                              spec.FIX1_PREFIX, spec.CLOSE_PREFIX,
                                              spec.WIDE_WITNESS_PREFIX, spec.N10_WITNESS_PREFIX,
                                              spec.N12_WITNESS_PREFIX, spec.WIDE_N12_N14_PREFIX,
                                              spec.N32_PREFIX, spec.N32_CLOSURE_PREFIX))
                         for selector in targets.keys() - known),
                 "REV2 contract object names an unlisted harness")
    return result


def discovery_additions(rows):
    """Every active row is a cfg-on addition: the left S8 and the two literal N32 controls."""
    return list(rows)


def check_overlay_roster(items, rows):
    active_rows = tuple(("contract-harnesses" if row["check"] else "standard-harnesses", row["selector"])
                        for row in discovery_additions(rows))
    spec.require(active_rows in ((), spec.N32_CLOSURE_DISCOVERY),
                 "N32 closure additions must be empty in cfg-off or the exact three plain roots in cfg-on")
    modules = {
        spec.PROVIDER_PREFIX: "/smallsort/verify/rev2_provider_cost.rs",
        spec.BINDING_PREFIX: "/smallsort/verify/rev2_s13_binding.rs",
        spec.GEOMETRIES_PREFIX: "/smallsort/verify/rev2_s13_geometries.rs",
        spec.CONSUMER_PREFIX: "/smallsort/verify/rev2_n32_consumer.rs",
        spec.N17_PREFIX: "/smallsort/verify/rev2_n17.rs",
        spec.N18_N19_PROVIDERS_PREFIX: "/smallsort/verify/rev2_n18_n19_providers.rs",
        spec.N18_N19_CONSUMER_PREFIX: "/smallsort/verify/rev2_n18_n19_consumer.rs",
        spec.N20_N21_PROVIDERS_PREFIX: f"/smallsort/verify/{spec.N20_N21_PROVIDERS_MODULE}.rs",
        spec.U64_N20_N21_PREFIX: f"/{spec.U64_N20_N21_FILE}",
        spec.MERGE_PAIR_FIXED_PREFIX: f"/smallsort/verify/{spec.MERGE_PAIR_FIXED_MODULE}.rs",
        spec.N20_N21_CONSUMER_PREFIX: f"/smallsort/verify/{spec.N20_N21_CONSUMER_MODULE}.rs",
        spec.N22_N25_PROVIDERS_PREFIX: f"/{spec.N22_N25_PROVIDERS_FILE}",
        spec.N22_N25_CONSUMER_PREFIX: f"/smallsort/verify/{spec.N22_N25_CONSUMER_MODULE}.rs",
        spec.N26_N31_HALVES_PREFIX: f"/{spec.N26_N31_HALVES_FILE}",
        spec.MERGE_PREFIX: f"/{spec.MERGE_FILE}",
        spec.HISTORICAL_CONSUMER_PREFIX: f"/{spec.HISTORICAL_CONSUMER_FILE}",
        spec.COPY_BACK_PREFIX: f"/{spec.COPY_BACK_FILE}",
        spec.U64_N13_PREFIX: f"/{spec.U64_N13_FILE}",
        spec.U64_N14_N17_PREFIX: f"/{spec.U64_N14_N17_FILE}",
        spec.U64_N18_N19_PREFIX: f"/{spec.U64_N18_N19_FILE}",
        spec.U64_N22_N25_PROVIDERS_PREFIX: f"/{spec.U64_N22_N25_PROVIDERS_FILE}",
        spec.U64_N26_N32_CONSUMER_PREFIX: f"/{spec.U64_N26_N32_CONSUMER_FILE}",
        spec.PILOT_PREFIX: f"/{spec.PILOT_MODULE_FILE}",
        spec.FIX1_PREFIX: f"/{spec.PILOT_MODULE_FILE}",
        spec.CLOSE_PREFIX: f"/{spec.CLOSE_MODULE_FILE}",
        spec.WIDE_WITNESS_PREFIX: f"/{spec.CLOSE_MODULE_FILE}",
        spec.N10_WITNESS_PREFIX: f"/{spec.CLOSE_MODULE_FILE}",
        spec.N12_WITNESS_PREFIX: f"/{spec.CLOSE_MODULE_FILE}",
        spec.WIDE_N12_N14_PREFIX: f"/{spec.CLOSE_MODULE_FILE}",
        spec.N32_PREFIX: f"/{spec.CLOSE_MODULE_FILE}",
        spec.N32_CLOSURE_PREFIX: f"/{spec.CLOSE_MODULE_FILE}",
        spec.PREFIX: f"/{spec.MODULE_FILE}",
    }
    rev2 = [item for item in items if item["selector"].startswith(tuple(modules)) or
            ("/" + item["file"].lstrip("/")).endswith(tuple(modules.values()))]
    observed = Counter((item["kind"], item["selector"]) for item in rev2)
    expected = Counter((*spec.PROVIDER_DISCOVERY, *spec.BINDING_DISCOVERY, *spec.GEOMETRIES_DISCOVERY,
                        *spec.CONSUMER_DISCOVERY, *spec.N17_DISCOVERY,
                        *spec.N18_N19_PROVIDERS_DISCOVERY, *spec.N18_N19_CONSUMER_DISCOVERY,
                        *spec.N20_N21_PROVIDERS_DISCOVERY, *spec.MERGE_PAIR_FIXED_DISCOVERY))
    expected.update(spec.N20_N21_CONSUMER_DISCOVERY)
    expected.update(spec.U64_N20_N21_DISCOVERY)
    expected.update(spec.N22_N25_PROVIDERS_DISCOVERY)
    expected.update(spec.N22_N25_CONSUMER_DISCOVERY)
    expected.update(spec.N26_N31_HALVES_DISCOVERY)
    expected.update(("contract-harnesses", selector) for selector in spec.MERGE_CHECKS)
    expected.update(spec.HISTORICAL_CONSUMER_DISCOVERY)
    expected.update(spec.COPY_BACK_DISCOVERY)
    expected.update(spec.U64_N13_DISCOVERY)
    expected.update(spec.U64_N14_N17_DISCOVERY)
    expected.update(spec.U64_N18_N19_HISTORICAL_DISCOVERY)
    expected.update(spec.U64_N22_N25_PROVIDER_DISCOVERY)
    expected.update(spec.U64_N26_N32_DISCOVERY)
    expected.update(spec.U64_N26_N32_CONSUMER_DISCOVERY)
    expected.update(spec.CLOSE_DISCOVERY)
    expected.update(spec.WIDE_WITNESS_DISCOVERY)
    expected.update(spec.N10_WITNESS_DISCOVERY)
    expected.update(spec.N12_WITNESS_DISCOVERY)
    expected.update(spec.WIDE_N12_N14_DISCOVERY)
    expected.update(spec.N32_DISCOVERY)
    expected.update(active_rows)
    expected.update(spec.PILOT_DISCOVERY)
    expected.update(spec.FIX1_DISCOVERY)
    spec.require(observed == expected and all(
        any(item["selector"].startswith(prefix) and ("/" + item["file"].lstrip("/")).endswith(path)
            for prefix, path in modules.items()) for item in rev2
    ), "REV2 exact discovery has missing, ambiguous, extra, wrong-kind or wrong-file selectors")
    for item in rev2:
        selector = item["selector"]
        targets = item.get("targets", [])
        check = (spec.N22_N25_PROVIDER_CHECKS.get(selector)
                 or spec.N26_N31_HALVES_CHECKS.get(selector)
                 or spec.MERGE_CHECKS.get(selector)
                 or spec.PROVIDER_CHECKS.get(selector)
                 or spec.U64_N20_N21_CHECKS.get(selector)
                 or spec.U64_N18_N19_CHECKS.get(selector)
                 or spec.U64_N22_N25_PROVIDER_CHECKS.get(selector)
                 or spec.PILOT_CHECKS.get(selector)
                 or spec.FIX1_CHECKS.get(selector)
                 or spec.WIDE_N12_N14_CHECKS.get(selector)
                 or spec.N32_CHECKS.get(selector)
                 or spec.PROVIDER_CHECKS.get(selector))
        if check:
            definition, file = check
            spec.require(len(targets) == 1 and targets[0][0] == definition
                         and spec.source_file_matches(targets[0][1], file),
                         f"REV2 exact discovery Check object mismatch for {selector}")
        elif item["kind"] == "standard-harnesses":
            spec.require(not targets, f"standard harness has a contract target: {selector}")
    return rev2


def setup_child(argv, *, cwd, directory, deadline, journal, cfg=(), build=False, cargo_verbose=False):
    env = frozen_env(directory, cfg)
    journal.update({"argv": argv, "cwd": str(cwd), "cfg": list(cfg), "deadline_monotonic": deadline,
                    "env": {key: env.get(key) for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "TMPDIR")}})
    if not build:
        journal["env"]["CARGO_TARGET_DIR"] = env["CARGO_TARGET_DIR"]
    if cargo_verbose:
        journal["env"]["CARGO_TERM_VERBOSE"] = "true"
    journal["child"] = invoke(argv, cwd=cwd, directory=directory, deadline=deadline, cfg=cfg,
                              build=build, cargo_verbose=cargo_verbose, nominal_kib=spec.LIMITS["setup_kib"])
    return journal["child"]


def require_setup_child(child, directory, journal, action):
    if not child_ok(child):
        journal.update(setup_diagnostics.failure_details(directory, child))
        raise RunError(f"{action} failed: {child.get('stop_reason')}, exit code {child.get('exit_code')}")


def compile_overlay(std, tool, directory, request, setup_deadline, journal):
    directory.mkdir(parents=True)
    flags = [flag for name in request["verify_z"] for flag in ("-Z", name)]
    # Kani's normal banner probes CBMC. Enable Cargo's command trace separately.
    argv = [str(tool / "scripts/kani"), "verify-std", *flags, "--no-assert-contracts",
            "--no-codegen", "--only-codegen", "--quiet", "--target-dir", str(directory / "kani-target"),
            str(std / "library")]
    deadline = min(setup_deadline, time.monotonic() + spec.LIMITS["overlay_compile_seconds"])
    journal["compilation_status"] = "UNKNOWN"
    child = setup_child(argv, cwd=directory, directory=directory, deadline=deadline, cfg=spec.CFG,
                        journal=journal, cargo_verbose=True)
    witness = setup_diagnostics.core_compile_witness(directory, spec.CFG)
    journal["core_compile_witness"] = witness
    try:
        require_setup_child(child, directory, journal, "overlay compile preflight")
    except RunError:
        cargo_summary = (journal["cargo_tail"] or {}).get("summary")
        if child.get("stop_reason") == "EXITED" and (child.get("exit_code") or 0) > 0 and cargo_summary:
            journal["compilation_status"] = "FAILED"
        raise
    if not witness or child.get("max_verifier_children") != 0:
        journal.update(setup_diagnostics.failure_details(directory, child))
        raise RunError("overlay compile preflight did not establish cfg-on core compilation without verifier children")
    journal["compilation_status"] = "PASS"


def list_one(std, tool, directory, deadline, journal, cfg):
    directory.mkdir(parents=True)
    flags = [flag for name in spec.STOCK_Z for flag in ("-Z", name)]
    argv = [str(tool / "scripts/kani"), "list", *flags, str(std / "library"), "--std", "--format", "json"]
    journal["status"] = "FAILED"
    journal["requested_nominal_cap_kib"] = spec.LIMITS["setup_kib"]
    try:
        child = setup_child(argv, cwd=directory, directory=directory, deadline=deadline,
                            cfg=cfg, journal=journal)
        require_setup_child(child, directory, journal, "discovery")
        entries = read_list(directory / "kani-list.json")
        journal["status"] = "COMPLETE"
        return entries
    except (OSError, ValueError) as exc:
        if "child" in journal:
            journal.update(setup_diagnostics.failure_details(directory, journal["child"]))
        raise RunError(f"invalid discovery output: {exc}") from exc
    finally:
        child = journal.get("child", {})
        journal.update({field: child.get(field) for field in ("nominal_cap_kib", "effective_cap_kib", "admission_memory")})
        journal["stop_reason"] = child.get("stop_reason")
        journal["primary_stop_reason"] = child.get("primary_stop_reason") or child.get("stop_reason")
        journal["last_observed_phase"] = child.get("last_observed_phase")
        memory = child.get("admission_memory") or {}
        journal["physical_kib"] = memory.get("physical_kib")
        journal["initial_available_kib"] = memory.get("available_kib")


def discover(std, tool, directory, deadline, journal, rows):
    cfg_off = spec.CFG[:-1]
    journal.update(status="FAILED", last_list="cfg_off")
    try:
        before = list_one(std, tool, directory / "off", deadline, journal.setdefault("cfg_off", {}), cfg_off)
        inherited = check_overlay_roster(before, ())
        journal["last_list"] = "cfg_on"
        after = list_one(std, tool, directory / "on", deadline, journal.setdefault("cfg_on", {}), spec.CFG)
        registrations = check_overlay_roster(after, rows)
        before_counts = Counter((item["kind"], item["selector"], item["file"], tuple(sorted(item.get("targets", []))))
                                for item in before)
        after_counts = Counter((item["kind"], item["selector"], item["file"], tuple(sorted(item.get("targets", []))))
                               for item in after)
        spec.require(before_counts <= after_counts and len(after) - len(before) == len(discovery_additions(rows)),
                     "REV2 discovery changed the cfg-off harness inventory beyond the exact additions")
    except ValueError as exc:
        raise RunError(f"invalid discovery output: {exc}") from exc
    journal["status"] = "COMPLETE"
    return {"cfg": spec.CFG, "total_listed": len(after), "rev2_ordered": registrations,
            "cfg_off": {"cfg": cfg_off, "total_listed": len(before), "rev2_ordered": inherited}}


def setup_failure(journal):
    phase = journal["phase"]
    path = {"KANI_BUILD": ("build",), "OVERLAY_COMPILE_PREFLIGHT": ("overlay_compile",),
            "OVERLAY_DISCOVERY": ("discovery",)}.get(phase, ())
    if phase == "OVERLAY_DISCOVERY" and (last_list := journal["discovery"].get("last_list")):
        path += (last_list,)
    stage = journal
    for name in path:
        stage = stage.get(name, {})
    failure = {"stage": "prepare", "phase": phase, "message": journal["error"],
               "receipt": "setup.json" + ("#/" + "/".join(path) if path else "")}
    diagnostics = stage.get("diagnostics", {})
    headers = [diagnostics[stream] for stream in ("stdout", "stderr")
               if diagnostics.get(stream, {}).get("header")]
    if headers:
        first = next((record for record in headers if record["code"]), headers[0])
        failure["primary_diagnostic"] = {"message": first["header"], "code": first["code"],
                                         "stream": first["stream"], "line": first["start_line"]}
    return failure


def prepare(state, std, tool, request, boundaries):
    import tool_attestation

    journal = {"status": "SETUP_ERROR", "phase": "SOURCE_CHECK", "version_first_lines": {},
               "clocks": boundaries, "discovery": {"status": "NOT_STARTED", "phase": "OVERLAY_DISCOVERY"}}
    started = time.monotonic()
    deadline = boundaries["prepare_deadline"]
    platform_name()
    scratch = state / "setup"
    scratch.mkdir(exist_ok=True)
    try:
        spec.require(can_start(deadline, 15), "setup budget already exhausted")
        journal["tool_before_build"] = spec.identity(tool, spec.TOOL, deadline=deadline)
        journal["stdlib_base_before_list"] = spec.identity(std, spec.BASE, deadline=deadline)
        journal["phase"] = "KANI_BUILD"
        dump(state / "setup.json", journal)
        build = journal.setdefault("build", {})
        child = setup_child(["cargo", "build-dev", "--release"], cwd=tool, build=True,
                            directory=scratch / "build", deadline=deadline, journal=build)
        require_setup_child(child, scratch / "build", build, "stock build")
        journal["phase"] = "TOOL_ATTESTATION"
        dump(state / "setup.json", journal)
        journal["tool"] = tool_attestation.attest(tool, deadline, include_goto_cc=True,
                                                version_first_lines=journal["version_first_lines"])
        journal["tool_after_build"] = spec.identity(tool, spec.TOOL, deadline=deadline)
        journal["phase"] = "OVERLAY_CHECKOUT"
        spec.git(std, "checkout", "--detach", request["overlay"][0], deadline=deadline)
        journal["overlay"] = spec.identity(std, request["overlay"], deadline=deadline)
        journal["phase"] = "OVERLAY_COMPILE_PREFLIGHT"
        gate = journal.setdefault("overlay_compile", {})
        dump(state / "setup.json", journal)
        compile_overlay(std, tool, scratch / "overlay-compile", request, deadline, gate)
        journal["phase"] = "OVERLAY_DISCOVERY"
        dump(state / "setup.json", journal)
        discovery = discover(std, tool, scratch / "overlay-list", deadline, journal["discovery"], request["roster"])
        spec.identity(std, request["overlay"], deadline=deadline)
        shutil.rmtree(scratch)
        spec.require(time.monotonic() <= deadline, "setup and discovery exceeded their deadline")
        dump(state / "discovery.json", discovery)
        journal["phase"] = "DISCOVERY_COMPLETE"
        journal["status"] = "READY"
    except Exception as exc:
        journal["error"] = f"{type(exc).__name__}: {exc}"[:2048]
        if journal["discovery"]["status"] != "COMPLETE":
            journal["discovery"]["reason"] = journal["error"]
        dump(state / "error.json", setup_failure(journal))
        raise
    finally:
        journal["prepare_seconds"] = time.monotonic() - started
        journal["first_step_elapsed_seconds"] = time.monotonic() - boundaries["epoch"]
        dump(state / "setup.json", journal)


def verify_argv(std, tool, directory, row, request):
    flags = [flag for name in request["verify_z"] for flag in ("-Z", name)]
    return [str(tool / "scripts/kani"), "verify-std", *flags, "--no-assert-contracts",
            "--harness", row["selector"], "--exact", "--jobs=1", "--output-format=regular",
            "-Z", "export-json", "--export-json", str(directory / "export.json"), "--verbose",
            "--target-dir", str(directory / "kani-target"), str(std / "library"),
            "--cbmc-args", "--object-bits", str(row["object_bits"])]


def expected_slots(request):
    return [(row["id"], "singleton", [row], row["seconds"]) for row in request["roster"]]


def receipt(slot, outcome, reason, *, pss_failure=None):
    key, mode, rows, seconds = slot
    record = {"id": key, "mode": mode, "roots": rows, "window_seconds": seconds,
              "cold_wall_limit_seconds": spec.LIMITS["cold_wall_seconds"],
              "object_bits": rows[0].get("object_bits"), "solver": "cadical", "cbmc_version": spec.CBMC_VERSION,
              "uninit_checks": False, "validity_checks": False,
              "outcome": outcome, "reason": reason, "censored": False, "projection": None}
    if pss_failure is not None:
        record["pss"] = pss_failure
    return record


def save_receipt(state, record):
    dump(state / "artifact" / "slots" / record["id"] / "receipt.json", record)


def attach_telemetry(record, child, diagnostics):
    """Put the bounded RSS/PSS summary and group census into the record. Cheap and independent of parsing."""
    series, compact = diagnostics.publication()
    compact["error"] = child.get("diagnostic_error")
    compact["supervisor_sampling"] = {field: child.get(field) for field in (
        "sampler_valid", "samples_attempted", "samples_succeeded", "samples_missed",
        "sample_pid_records_skipped", "sampling_cadence_seconds", "sampling_interval_target_seconds",
    )}
    record["memory_telemetry"] = compact
    return series


def slot_projection(state, directory, record, diagnostics):
    """Collect compact evidence and optionally publish the detailed projection."""
    import results

    child = record["child"]
    series = attach_telemetry(record, child, diagnostics)
    projection = results.project(directory, record["roots"], child, mode=record["mode"])
    observed = projection.get("observed_outcome", projection["outcome"])
    record.update(
        outcome=observed,
        observed_outcome=observed,
        reason=projection.get("reason") or child.get("stop_reason"),
        projection_outcome=projection["outcome"],
        covers=projection.get("cover_summary", projection.get("covers_summary", {})),
        last_phase=projection.get("last_phase") or record["last_phase"],
        projection_complete=projection.get("complete"), projection_truncated=projection.get("projection_truncated", False),
    )
    for field in ("timings", "last_phase_source", "last_phase_monotonic", "last_phase_timestamp", "phase_observations",
                  "solver_version", "resolved", "native_metrics", "result_evidence", "expected_result"):
        if field in projection:
            record[field] = projection[field]
    record["censored"] |= record["outcome"] in {"TIMEOUT", "OUT_OF_MEMORY"}

    artifact = state / "artifact"
    target = artifact / "slots" / record["id"]
    timeline = target / "timeline.json"
    dump(timeline, series)
    record["timeline"] = str(timeline.relative_to(artifact))
    content = json.dumps(projection, allow_nan=False, ensure_ascii=False, separators=(",", ":")).encode()
    if len(content) <= spec.LIMITS["projection_bytes"]:
        path = target / "projection.json"
        staged = directory / "projection.tmp"
        staged.write_bytes(content)
        staged.replace(path)
        record["projection"] = str(path.relative_to(artifact))
    else:
        record["publication_truncated"] = True


def record_receipt_time(record, completed):
    record["receipt_write_completed_monotonic"] = completed
    record["slot_elapsed_seconds"] = completed - record["started_monotonic"]
    record["receipt_deadline_exceeded"] = completed > record["receipt_deadline_monotonic"]


def measure_slot(state, std, tool, request, slot, latest_start, pss_probe=None, *, pss_failure=None, setup=None):
    from telemetry import MemoryTelemetry

    key, _, rows, seconds = slot
    now = time.monotonic()
    if now > latest_start:
        record = receipt(slot, "NOT_STARTED", "INSUFFICIENT_LATEST_START_WINDOW", pss_failure=pss_failure)
        record["latest_start_monotonic"] = latest_start
        return record

    directory = state / "work" / key
    argv = verify_argv(std, tool, directory, rows[0], request)
    env = frozen_env(directory, rows[0]["cfg"], jobs=1)
    cold_deadline = now + spec.LIMITS["cold_wall_seconds"]
    reap_deadline = cold_deadline + spec.LIMITS["reap_seconds"]
    slot_deadline = now + seconds
    record = receipt(slot, "INCOMPLETE", "INTERRUPTED_BEFORE_RECEIPT", pss_failure=pss_failure)
    record.update({"argv": argv, "cwd": str(directory), "cfg": rows[0]["cfg"], "jobs": 1,
                   "env": {field: env.get(field) for field in ("KANI_JOBS", "CARGO_TARGET_DIR", "TMPDIR",
                                                              "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")},
                   "cold_deadline_monotonic": cold_deadline, "reap_deadline_monotonic": reap_deadline,
                   "started_monotonic": now, "latest_start_monotonic": latest_start,
                   "slot_deadline_monotonic": slot_deadline})
    try:
        with receipt_window(cold_deadline):
            directory.mkdir(parents=True)
            save_receipt(state, record)
        if time.monotonic() >= cold_deadline:
            raise ReceiptDeadlineExceeded("prelaunch receipt consumed the cold window")
    except (ReceiptDeadlineExceeded, OSError) as exc:
        record.update(outcome="NOT_STARTED", reason="PRELAUNCH_RECEIPT_UNAVAILABLE",
                      receipt_write_deferred=True, receipt_error=f"{type(exc).__name__}: {exc}"[:1024])
        return record

    relay_state = None
    relay_slot = key == request["stdout_relay"]["slot"]
    frozen_delivery = rows[0].get("stdout_delivery")
    if frozen_delivery != (spec.STDOUT_RELAY_DELIVERY if relay_slot else spec.STOCK_PIPE):
        # The relay serves exactly the slot frozen as STDOUT_RELAY; a frozen stock-pipe slot never runs behind
        # it, and a frozen relay slot never runs on the stock pipe, whatever the relay configuration names.
        error = ("relay configured for a STOCK_PIPE slot" if relay_slot else
                 f"slot frozen as {frozen_delivery!r} is not the configured relay slot")
        record.update(outcome="NOT_STARTED", reason="STDOUT_DELIVERY_CONFLICT",
                      stdout_relay={"status": "REFUSED", "error": error})
        try:
            with receipt_window(cold_deadline):
                save_receipt(state, record)
        except (ReceiptDeadlineExceeded, OSError) as error:
            record.update(receipt_write_deferred=True, receipt_error=f"{type(error).__name__}: {error}"[:1024])
        return record
    if key == request["stdout_relay"]["slot"]:
        installed = time.monotonic()
        try:
            real = stdout_relay.resolve_real((setup or {}).get("tool"), env.get("PATH", ""))
            relay_state = stdout_relay.install(directory, real, config=request["stdout_relay"])
        except Exception as exc:
            record.update(outcome="NOT_STARTED", reason="STDOUT_RELAY_UNAVAILABLE",
                          stdout_relay={"status": "NOT_INSTALLED", "error": f"{type(exc).__name__}: {exc}"[:1024]})
            try:
                with receipt_window(cold_deadline):
                    save_receipt(state, record)
            except (ReceiptDeadlineExceeded, OSError) as error:
                record.update(receipt_write_deferred=True, receipt_error=f"{type(error).__name__}: {error}"[:1024])
            return record
        record["stdout_relay"] = {"status": "INSTALLED", "install_seconds": time.monotonic() - installed,
                                  **relay_state["receipt"]}
        record["env"]["PATH_PREFIX"] = relay_state["path_prefix"]
    diagnostics = MemoryTelemetry(pss_probe, pss_unavailable=pss_failure["reason"] if pss_failure else None,
                                  relay_phase=stdout_relay.phase_probe(relay_state["journal_dir"])
                                  if relay_state else None)
    try:
        child = invoke(argv, cwd=directory, directory=directory, deadline=reap_deadline,
                       nominal_kib=spec.LIMITS["singleton_kib"], jobs=1, cfg=rows[0]["cfg"], diagnostics=diagnostics,
                       path_prefix=relay_state["path_prefix"] if relay_state else None)
    except Exception as exc:
        child = {"status": "ERROR", "stop_reason": "SUPERVISOR_ERROR", "reaped": False, "sampler_valid": False,
                 "error": f"{type(exc).__name__}: {exc}"[:1024]}
    receipt_started = time.monotonic()
    receipt_deadline = min(slot_deadline, receipt_started + spec.LIMITS["receipt_seconds"])
    record.update(receipt_started_monotonic=receipt_started, receipt_deadline_monotonic=receipt_deadline)
    record["child"] = {name: value for name, value in child.items() if name != "timeline"}
    observed_end = child.get("monotonic_observation_end")
    record["cold_wall_seconds"] = observed_end - now if observed_end is not None else None
    observed_stop = child.get("stop_reason")
    primary_stop = child.get("primary_stop_reason") or observed_stop
    record["censored"] = primary_stop in {"TIMEOUT", "RSS_LIMIT", "LIVE_MEMORY_PRESSURE", "LIVE_MEMORY_RESERVE"}
    if observed_stop and observed_stop != "EXITED":
        record.update(outcome=observed_stop, reason=observed_stop, process_outcome=observed_stop)
    else:
        exit_code = child.get("exit_code")
        record["process_outcome"] = f"EXIT_{exit_code}" if type(exit_code) is int else "UNKNOWN"
        record["reason"] = "TERMINAL_EVIDENCE_PENDING"
    record.update(last_phase=child.get("last_observed_phase") or "UNKNOWN",
                  last_phase_monotonic=child.get("last_phase_monotonic"))
    if child.get("last_observed_phase"):
        record["last_phase_source"] = "sampled_process_image"
    record.update(projection_status="PENDING", projection_complete=False)
    if child.get("reaped") is True:
        # The census reaches the checkpoint even when a later parse runs out of its window.
        try:
            attach_telemetry(record, record["child"], diagnostics)
        except Exception as exc:
            record["memory_telemetry_error"] = f"{type(exc).__name__}: {exc}"[:300]

    # The child disposition and cleanup are durable before any optional parsing.
    try:
        projection_deadline = receipt_deadline - RECEIPT_COMMIT_RESERVE_SECONDS
        with receipt_window(projection_deadline):
            save_receipt(state, record)
            record["checkpoint_monotonic"] = time.monotonic()
            if record["checkpoint_monotonic"] >= projection_deadline:
                raise ReceiptDeadlineExceeded("checkpoint consumed the projection window")
            if relay_state is not None:
                # Delivery is judged before projection from journals and one log line. It can only withhold a match.
                record["stdout_relay"].update(stdout_relay.collect(relay_state, directory, child,
                                                                   config=request["stdout_relay"]))
                record["stdout_delivery"] = record["stdout_relay"]["status"]
                save_receipt(state, record)
            if child.get("reaped") is not True:
                record.update(projection_status="REAP_UNVERIFIED", projection_complete=False,
                              projection_skipped=True)
            else:
                slot_projection(state, directory, record, diagnostics)
            if time.monotonic() > projection_deadline:
                raise ReceiptDeadlineExceeded("projection completed beyond its window")
        if child.get("reaped") is True:
            record["projection_complete"] = (record["projection_complete"] is True
                                             and not record.get("projection_truncated")
                                             and record["projection"] is not None)
            record["projection_status"] = "COMPLETE" if record["projection_complete"] else "INCOMPLETE"
    except ReceiptDeadlineExceeded:
        record.update(projection_status="DEADLINE", projection_complete=False,
                      projection_budget_exhausted=True, publication_truncated=True)
    except Exception as exc:
        record.update(projection_status="ERROR", projection_complete=False,
                      projection_error=f"{type(exc).__name__}: {exc}"[:1024])

    if record["outcome"] == "VERIFIED" and record["projection_complete"] is not True:
        record.update(outcome="INCOMPLETE", reason="VERIFIED_OBSERVATION_WITH_INCOMPLETE_PROJECTION")
    spill_pending = relay_state is not None and child.get("reaped") is True
    if spill_pending:
        # A stop before replay leaves the spill. Its prefix is read after projection in its own bounded window.
        spill_deadline = receipt_deadline - RECEIPT_COMMIT_RESERVE_SECONDS
        try:
            with receipt_window(spill_deadline, "spill prefix"):
                record["stdout_relay"].update(stdout_relay.drain_spill(relay_state, request["stdout_relay"]))
            spill_pending = False
        except ReceiptDeadlineExceeded:
            record["stdout_relay"]["spill_prefix_reason"] = "SPILL_PREFIX_DEADLINE"
        except Exception as exc:
            record["stdout_relay"]["spill_prefix_reason"] = "SPILL_PREFIX_ERROR"
            record["stdout_relay"]["spill_prefix_error"] = f"{type(exc).__name__}: {exc}"[:300]
    # Shown next to expected_result.status: a native MATCHED on N16 is accepted only with COMPLETE delivery.
    if relay_state is None:
        record["stdout_delivery"] = "STOCK_PIPE"
    else:
        status = record["stdout_relay"]["status"]
        # An installed relay whose delivery was never judged is reported as such, never as complete.
        record["stdout_delivery"] = status if status in ("COMPLETE", "INCOMPLETE") else "NOT_JUDGED"
    if isinstance(record.get("expected_result"), dict):
        record["expected_result"]["stdout_delivery"] = record["stdout_delivery"]
    try:
        with receipt_window(receipt_deadline):
            save_receipt(state, record)
            completed = time.monotonic()
    except (ReceiptDeadlineExceeded, OSError) as exc:
        record.update(receipt_write_deferred=True, receipt_deadline_exceeded=True,
                      receipt_error=f"{type(exc).__name__}: {exc}"[:1024])
    else:
        record_receipt_time(record, completed)
    if spill_pending:
        # The receipt already says the prefix was not read. Free the disk after the confirmed reap.
        try:
            stdout_relay.remove_spill(relay_state)
        except OSError:
            pass
    # Cold targets live on the disposable runner outside artifact/ until job teardown.
    return record


def close_measurements(state, std, tool, request, setup, verify_deadline):
    import tool_attestation

    started = time.monotonic()
    deadline = min(verify_deadline, started + spec.LIMITS["post_attestation_seconds"])
    record = {"status": "RUNNING", "started_monotonic": started, "deadline_monotonic": deadline,
              "version_first_lines": {}}
    path = state / "attestation.json"
    try:
        with receipt_window(deadline):
            dump(path, record)
            tool_attestation._remaining(deadline)
            replay = tool_attestation.attest(tool, deadline, include_goto_cc=True,
                                            version_first_lines=record["version_first_lines"])
            spec.require(tool_attestation._runtime_identity(replay) == tool_attestation._runtime_identity(setup["tool"]),
                         "tool runtime identity changed between setup and final check")
            record["tool"] = spec.identity(tool, spec.TOOL, deadline=deadline)
            record["overlay"] = spec.identity(std, request["overlay"], deadline=deadline)
            tool_attestation._remaining(deadline)
            dump(state / "end.json", {"tool": record["tool"], "overlay": record["overlay"],
                                     "tool_runtime_identity_rechecked": True,
                                     "measurements_finished_monotonic": time.monotonic()})
            tool_attestation._remaining(deadline)
            record.update(status="COMPLETE", finished_monotonic=time.monotonic())
            dump(path, record)
            tool_attestation._remaining(deadline)
    except Exception as exc:
        timeout = isinstance(exc, (TimeoutError, subprocess.TimeoutExpired, tool_attestation.AttestationTimeout,
                                   ReceiptDeadlineExceeded))
        record.update(status="TIMEOUT" if timeout else "FAILED", error=f"{type(exc).__name__}: {exc}"[:1024],
                      finished_monotonic=time.monotonic())
        try:
            dump(path, record)
        except OSError as journal_error:
            exc.add_note(f"Final attestation receipt could not be saved: {journal_error}")
        raise


def measure(state, std, tool, request, boundaries, *, step_deadline=None, gate_deadline=None):
    if step_deadline is None:
        step_deadline = time.monotonic() + MEASURE_SECONDS
    if gate_deadline is None:
        gate_deadline = time.monotonic() + spec.LIMITS["measure_gate_seconds"]
    verify_deadline = min(boundaries["verify_deadline"], step_deadline - MEASUREMENT_JOURNAL_SECONDS)
    deadline = min(boundaries["slots_deadline"], verify_deadline - spec.LIMITS["post_attestation_seconds"])
    slot_reduction = boundaries["slots_deadline"] - deadline
    last_slot_latest = boundaries["latest_starts"][spec.SLOT_IDS[-1]] - slot_reduction
    gate_deadline = min(gate_deadline, boundaries["setup_deadline"], last_slot_latest)
    with receipt_window(gate_deadline, "measurement input gate"):
        setup = spec.read(state / "setup.json")
        spec.require(setup["status"] == "READY", "setup or exact discovery failed")
        spec.identity(std, request["overlay"], deadline=gate_deadline)
        spec.identity(tool, spec.TOOL, deadline=gate_deadline)
        platform_name()
    if time.monotonic() > gate_deadline:
        raise ReceiptDeadlineExceeded("measurement input gate exceeded its window")
    stop_reason = None
    pss_probe = pss_failure = None
    from telemetry import PssProbe
    try:
        pss_probe = PssProbe()
    except Exception as exc:
        pss_failure = {"pss_kib": None, "reason": "PROBE_START_FAILED",
                       "error": f"{type(exc).__name__}: {exc}"[:300]}
    timings, pending = {}, {}
    measurement_error = None
    try:
        for slot in expected_slots(request):
            key = slot[0]
            latest = boundaries["latest_starts"][key] - slot_reduction
            if stop_reason is None:
                record = measure_slot(state, std, tool, request, slot, latest, pss_probe, pss_failure=pss_failure,
                                      setup=setup)
                child = record.get("child", {})
                # No child or a reaped child leaves later slots eligible for their own windows.
                if child and child.get("status") != "NOT_STARTED" and child.get("reaped") is not True:
                    stop_reason = "PROCESS_CLEANUP_COULD_NOT_BE_VERIFIED"
            else:
                record = receipt(slot, "NOT_STARTED", stop_reason, pss_failure=pss_failure)
                record["latest_start_monotonic"] = latest
            if record.get("receipt_write_deferred") or (record["outcome"] == "NOT_STARTED" and "child" not in record):
                pending[key] = record
            if "receipt_write_completed_monotonic" in record:
                timings[key] = {field: record[field] for field in (
                    "receipt_write_completed_monotonic", "slot_elapsed_seconds", "receipt_deadline_exceeded",
                )}
        if stop_reason is not None:
            raise RunError(stop_reason)
        close_measurements(state, std, tool, request, setup, verify_deadline)
    except Exception as exc:
        measurement_error = exc
        raise
    finally:
        # Keep late snapshots for finish. No retry runs in a later slot's window.
        deadline = min(boundaries["receipt_publication_deadline"], step_deadline,
                       time.monotonic() + MEASUREMENT_JOURNAL_SECONDS)
        try:
            with receipt_window(deadline):
                dump(state / "receipt-finalization.json", {"timings": timings, "pending": pending})
        except (OSError, ReceiptDeadlineExceeded) as exc:
            if measurement_error is None:
                raise
            measurement_error.add_note(f"Receipt finalization journal could not be saved: {exc}")


def admitted_request(state, trigger):
    spec.require(trigger == spec.read(state / "trigger.json"), "trigger differs from the initial checkout receipt")
    return spec.load()


def finish_run(state, std, step_started, boundaries):
    limits = spec.LIMITS
    step_seconds = limits["finish_seconds"]
    deadline = min(boundaries["receipt_publication_deadline"],
                   step_started + step_seconds)
    with receipt_window(deadline):
        import report

        request = admitted_request(state, spec.check_trigger(deadline=deadline))
        source_path = state / "source.json"
        source_receipt = spec.read(source_path) if source_path.is_file() else {}
        if source_receipt.get("native_coordinates_checked") is True:
            source_bindings = spec.check_source_bindings(std, request, deadline=deadline)
            spec.require(source_receipt["source_bindings"] == source_bindings,
                         "source bindings differ from the source receipt")
            check_native_source(std, request)
        report.finish(state, request, platform_name())
        if time.monotonic() > deadline:
            raise ReceiptDeadlineExceeded("finish completed beyond its publication window")


def main():
    step_started = time.monotonic()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("pins", "sources", "prepare", "measure", "finish", "upload-gate", "upload-check"))
    command = parser.parse_args().command
    state, std, tool = workspace()
    boundaries = clocks(state)
    if command in {"upload-gate", "upload-check"}:
        if command == "upload-gate":
            import report

            deadline = boundaries["receipt_publication_deadline"]
            spec.require(time.monotonic() < deadline,
                         "full upload window no longer fits before publication deadline")
            with receipt_window(deadline, "upload admission"):
                trigger = spec.check_trigger(deadline=deadline)
                request = admitted_request(state, trigger)
                index = report.validate_artifact_index(state / "artifact", request)
                spec.require(index.get("trigger") == trigger,
                             "artifact trigger differs from the admission receipt")
            spec.require(time.monotonic() <= deadline, "upload admission exceeded the publication cutoff")
        else:
            spec.require(time.monotonic() <= boundaries["finalize_deadline"],
                         "upload completed after publication deadline")
        return
    if command == "finish":
        finish_run(state, std, step_started, boundaries)
        return
    if command in {"pins", "sources"}:
        step_seconds = PINS_SECONDS if command == "pins" else SOURCES_SECONDS
        deadline = min(boundaries["prepare_deadline"], step_started + step_seconds)
        with receipt_window(deadline, command):
            trigger = spec.check_trigger(deadline=deadline)
            if time.monotonic() >= deadline:
                raise ReceiptDeadlineExceeded(f"{command} trigger validation exceeded its window")
            if command == "pins":
                spec.load()
                if time.monotonic() >= deadline:
                    raise ReceiptDeadlineExceeded("pins request validation exceeded its window")
                dump(state / "trigger.json", trigger)
                output("trigger_admitted", "true")
                output("std", spec.BASE[0])
                output("tool", spec.TOOL[0])
            else:
                sources(state, std, tool, admitted_request(state, trigger), trigger, deadline=deadline)
            if time.monotonic() > deadline:
                raise ReceiptDeadlineExceeded(f"{command} completed beyond its window")
        return
    step_deadline = step_started + MEASURE_SECONDS
    gate_deadline = boundaries["prepare_deadline"] if command == "prepare" else min(
        boundaries["setup_deadline"], step_started + spec.LIMITS["measure_gate_seconds"])
    with receipt_window(gate_deadline, f"{command} trigger validation"):
        request = admitted_request(state, spec.check_trigger(deadline=gate_deadline))
    if command == "prepare":
        prepare(state, std, tool, request, boundaries)
    else:
        measure(state, std, tool, request, boundaries, step_deadline=step_deadline, gate_deadline=gate_deadline)


def cli():
    try:
        main()
    except Exception as exc:
        message = f"{type(exc).__name__}: {exc}"[:2048]
        state = os.environ.get("REV2_STATE")
        if state and Path(state).is_dir():
            path = Path(state) / "error.json"
            if sys.argv[1] != "prepare" or not path.is_file():
                record = {"stage": sys.argv[1], "message": message}
                if getattr(exc, "__notes__", None):
                    record["notes"] = exc.__notes__
                dump(path, record)
        print(f"REV2: {message}", file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    cli()
