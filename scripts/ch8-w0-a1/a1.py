#!/usr/bin/env python3
"""Narrow CI adapter for CH8 W0-A1. Receipts never grant proof credit."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import subprocess
import sys
import time
from typing import Any

import replay_origin as origin

HERE = Path(__file__).resolve().parent
REQUEST = HERE / "CI-REQUEST.json"
MAX_INVOCATION_SECONDS = 600
STDOUT_LIMIT = STDERR_LIMIT = 32 * 1024 * 1024
METADATA_LIMIT = 16 * 1024 * 1024
JOB_OUTPUT_LIMIT = 256 * 1024 * 1024
RSS_RESERVE_BYTES = 2 * 1024 * 1024 * 1024
TERM_GRACE_SECONDS = 5
PIN_NAMES = ("baseline", "sel1")
PIN_IDENTITIES = {
    "baseline": ("0aac16ef62da9e9d5645782d458593e5d78143ba", "9d8bc9312bf955ef126d32b819b3cd0ed105ed2b"),
    "sel1": ("14bc57fdb99960240c4944845a3d985c8af4dcf7", "1efb6e4dfa69d346df8e23741d11839b1932403d"),
}
R1_SUFFIXES = {
    "stable_freeze_u64_n8", "stable_freeze_u64_n16", "stable_freeze_u64_n32",
    "unstable_general_nocopy_u64_n8", "unstable_general_nocopy_u64_n16",
    "unstable_general_nocopy_u64_n32", "unstable_network_u64_n18",
    "unstable_network_u64_n32",
}
ISSUE_CASES = {"5020", "4854", "5151"}
R2_SELECTORS = {"nonnull_field", "initialized_same_type_companion",
                "reassemble_ptr_fragments_in_static", "explicit_proof_observes_initialized_null",
                "drop_uninit_in_array", "drop_initialized_slot_in_array"}
R2_FIXTURES = {
    "nonnull_field": "native/issue-5020-nonnull.rs",
    "initialized_same_type_companion": "native/issue-5020-initialized-companion.rs",
    "reassemble_ptr_fragments_in_static": "native/issue-4854-autoharness.rs",
    "explicit_proof_observes_initialized_null": "native/issue-4854-explicit-proof-companion.rs",
    "drop_uninit_in_array": "native/issue-5151-empty-drop.rs",
    "drop_initialized_slot_in_array": "native/issue-5151-initialized-slot-companion.rs",
}
EXCERPT_LIMIT = 64 * 1024
DIAGNOSTIC_ENV_KEYS = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR",
                       "CARGO_BUILD_TARGET", "RUSTC", "RUSTC_WRAPPER",
                       "RUSTC_WORKSPACE_WRAPPER", "RUSTUP_TOOLCHAIN")
INVALID_EXPORT_STATES = set(origin.INVALID_EXPORT_STATES) | {
    "UNKNOWN_SCHEMA", "PARTIAL", "NO_HARNESSES_SELECTED", "UNKNOWN_WRONG_SELECTOR",
    "UNKNOWN_HARNESS_SELECTION", "UNKNOWN_HARNESS_SCHEMA",
}


def sha256(path: Path) -> str:
    return origin.sha256(path)


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    origin.write_json_atomic(path, value)


def git(repo: Path, *args: str) -> str:
    return origin.git(repo, *args)


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_request() -> dict[str, Any]:
    if not REQUEST.is_file():
        raise ValueError(f"missing CI request: {REQUEST}")
    req = json.loads(REQUEST.read_text())
    if not isinstance(req, dict):
        raise ValueError("CI-REQUEST must be a JSON object")
    pins = req.get("pins")
    if not isinstance(pins, dict) or set(pins) != set(PIN_NAMES):
        raise ValueError("request must contain exactly baseline and sel1 pins")
    for name in PIN_NAMES:
        p = pins[name]
        if not isinstance(p, dict) or not _is_sha(p.get("sha")) or not _is_sha(p.get("tree")):
            raise ValueError(f"invalid {name} pin SHA/tree")
        if (p["sha"], p["tree"]) != PIN_IDENTITIES[name]:
            raise ValueError(f"{name} pin does not match the literal frozen SHA/tree")
        binding = p.get("binding")
        if not isinstance(binding, str) or Path(binding).name != binding or not binding.endswith(".json"):
            raise ValueError(f"invalid {name} binding filename")
    std = req.get("std")
    if not isinstance(std, dict) or not all(_is_sha(std.get(k)) for k in
                                               ("base_sha", "base_tree", "base_library_tree", "patch_sha256")):
        raise ValueError("invalid frozen std identity or patch hash")
    if std.get("patch") != "std-test-only.patch" or not isinstance(std.get("patched_files"), dict) or not std["patched_files"]:
        raise ValueError("invalid std overlay inventory")
    for path, digest in std["patched_files"].items():
        if not isinstance(path, str) or path.startswith("/") or ".." in Path(path).parts or not _is_sha(digest):
            raise ValueError("unsafe or invalid std patched file inventory")
    if sha256(HERE / "std-test-only.patch") != std["patch_sha256"]:
        raise ValueError("std patch SHA-256 mismatch")
    for stage in ("r1", "r2"):
        section = req.get(stage)
        rows = section.get("rows") if isinstance(section, dict) else None
        if not isinstance(rows, list) or not rows:
            raise ValueError(f"missing {stage} rows")
        ids, selectors = set(), set()
        for row in rows:
            validate_row(stage, row)
            if stage == "r2":
                if row["fixture"] != R2_FIXTURES[row["selector"]]:
                    raise ValueError(f"wrong pinned fixture for selector {row['selector']}")
                _fixture_for(row)
            if row["id"] in ids or row["selector"] in selectors:
                raise ValueError(f"duplicate {stage} row id or selector")
            ids.add(row["id"]); selectors.add(row["selector"])
        if stage == "r1" and {r["selector"].rsplit("::", 1)[-1] for r in rows} != R1_SUFFIXES:
            raise ValueError("r1 must contain the exact eight A1 selector rows")
        if stage == "r2":
            if {r["selector"] for r in rows} != R2_SELECTORS:
                raise ValueError("r2 must contain the exact three originals and three companions")
            expected_pairs = {
                "5020": {"nonnull_field", "initialized_same_type_companion"},
                "4854": {"reassemble_ptr_fragments_in_static", "explicit_proof_observes_initialized_null"},
                "5151": {"drop_uninit_in_array", "drop_initialized_slot_in_array"},
            }
            for issue, expected in expected_pairs.items():
                cases = {r["selector"] for r in rows if issue in r["id"]}
                if cases != expected:
                    raise ValueError(f"r2 issue #{issue} original/companion pairing mismatch")
    return req


def _is_sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(c in "0123456789abcdef" for c in value) or (
        isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value))


def validate_row(stage: str, row: Any) -> dict[str, Any]:
    if stage not in ("r1", "r2") or not isinstance(row, dict):
        raise ValueError("row must be an object in stage r1 or r2")
    if not isinstance(row.get("id"), str) or not row["id"] or not isinstance(row.get("selector"), str) or not row["selector"]:
        raise ValueError("row requires id and exact selector")
    argv, env = row.get("argv"), row.get("environment")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("row argv must be a nonempty string array")
    if not isinstance(env, dict) or not all(isinstance(k, str) and (v is None or isinstance(v, str)) for k, v in env.items()):
        raise ValueError("row environment must map strings to string/null values")
    if sum(a.count("<KANI>") for a in argv) != 1 or sum(a.count("<OUT>") for a in argv) < 1 or argv[0] != "<KANI>":
        raise ValueError("row must use one leading <KANI> and explicit <OUT>")
    if stage == "r1":
        if "verify-std" not in argv or "./library" not in argv or "<FIXTURE>" in argv or row.get("fixture") is not None:
            raise ValueError("r1 must be verify-std ./library and cannot name a native fixture")
        if any(a == "--target" or a.startswith("--target=") for a in argv):
            raise ValueError("r1 host-default target policy forbids an explicit --target override")
        if row.get("mode") != "actual-body" or argv[1] != "verify-std":
            raise ValueError("r1 must use the pinned actual-body verify-std mode")
        if row["selector"].rsplit("::", 1)[-1] not in R1_SUFFIXES:
            raise ValueError("r1 selector is outside the exact A1 allowlist")
        std_position = argv.index("./library")
        if std_position == 0 or "--harness" not in argv or argv.index("--harness") + 1 >= len(argv) or argv[argv.index("--harness") + 1] != row["selector"]:
            raise ValueError("r1 mode/selector argv mismatch")
        uninit_on = "-Zuninit-checks" in argv or any(argv[i:i+2] == ["-Z", "uninit-checks"] for i in range(len(argv)-1))
        if (not uninit_on or "--no-assert-contracts" not in argv or
                "--object-bits" not in argv or argv.index("--object-bits") + 1 >= len(argv) or argv[argv.index("--object-bits") + 1] != "12" or
                "--harness-timeout" not in argv or argv.index("--harness-timeout") + 1 >= len(argv) or argv[argv.index("--harness-timeout") + 1] != "600s"):
            raise ValueError("r1 controls/profile flags or environment differ from the frozen request")
        if row["environment"].get("RUSTFLAGS") != "--cfg kani_smallsort_controls":
            raise ValueError("r1 controls/profile flags or environment differ from the frozen request")
        export_index = argv.index("--export-json") if "--export-json" in argv else -1
        if export_index < 0 or export_index + 1 >= len(argv) or argv[export_index + 1] != "<OUT>/export.json":
            raise ValueError("std row export path must be isolated at <OUT>/export.json")
    else:
        if "verify-std" in argv or "./library" in argv or argv.count("<FIXTURE>") != 1:
            raise ValueError("r2 native row cannot use verify-std/library and needs one fixture")
        if "-Zuninit-checks" not in argv and not any(argv[i:i+2] == ["-Z", "uninit-checks"] for i in range(len(argv)-1)):
            raise ValueError("r2 native row must retain uninit-checks")
        fixture = row.get("fixture")
        if not isinstance(fixture, str) or fixture.startswith("/") or ".." in Path(fixture).parts or not _is_sha(row.get("fixture_sha256")):
            raise ValueError("r2 row requires safe fixture path and pinned SHA-256")
        if row["selector"] not in R2_SELECTORS:
            raise ValueError("r2 selector is outside the exact native-case allowlist")
        mode = row.get("mode")
        if mode not in ("proof", "autoharness"):
            raise ValueError("r2 mode must be proof or autoharness")
        if mode == "autoharness":
            if row["selector"] != "reassemble_ptr_fragments_in_static" or "-Zautoharness" not in argv or "--run-sanity-checks" not in argv or "--harness" in argv:
                raise ValueError("#4854 original autoharness mode/selector argv mismatch")
            if argv.count("autoharness") != 1:
                raise ValueError("#4854 original autoharness command mode is missing")
            if argv.count("-Zuninit-checks") < 2:
                raise ValueError("#4854 original duplicate -Zuninit-checks flag is missing")
            if (env.get("RUSTFLAGS") != "--edition=2021 --cap-lints=warn" or
                    env.get("RUST_BACKTRACE") != "full"):
                raise ValueError("#4854 original scoped RUSTFLAGS/RUST_BACKTRACE differ from request")
        elif "--harness" not in argv or argv.index("--harness") + 1 >= len(argv) or argv[argv.index("--harness") + 1] != row["selector"]:
            raise ValueError("r2 proof selector/mode argv mismatch")
        elif row["selector"] in ("drop_uninit_in_array", "drop_initialized_slot_in_array"):
            if env.get("RUSTFLAGS") != "--edition=2021" or "RUST_BACKTRACE" in env:
                raise ValueError("#5151 rows require scoped RUSTFLAGS=--edition=2021 only")
        elif "RUSTFLAGS" in env or "RUST_BACKTRACE" in env:
            raise ValueError("native non-#4854/#5151 rows cannot receive issue-only compiler environment")
        export_index = argv.index("--export-json") if "--export-json" in argv else -1
        if export_index < 0 or export_index + 1 >= len(argv) or argv[export_index + 1] != "<OUT>/export.json":
            raise ValueError("native row export path must be isolated at <OUT>/export.json")
    return row


def _binding_path(pin: dict[str, Any]) -> Path:
    path = (HERE / pin["binding"]).resolve()
    if path.parent != HERE.resolve():
        raise ValueError("binding must be a sibling file in CI controls")
    return path


def verify_source(repo: Path, pin_name: str, request: dict[str, Any] | None = None,
                  require_submodules: bool = False) -> dict[str, Any]:
    req = request or load_request()
    if pin_name not in PIN_NAMES:
        raise ValueError(f"unknown source pin: {pin_name}")
    pin = req["pins"][pin_name]
    if (pin.get("sha"), pin.get("tree")) != PIN_IDENTITIES[pin_name]:
        raise ValueError(f"{pin_name} source pin is not the literal frozen identity")
    binding = json.loads(_binding_path(pin).read_text())
    if binding.get("state") not in ("FROZEN", f"{pin_name.upper()}_FROZEN"):
        raise ValueError(f"{pin_name} source binding is not frozen")
    if binding.get("export_sha") != pin["sha"] or binding.get("export_tree") != pin["tree"]:
        raise ValueError(f"{pin_name} binding/request identity mismatch")
    if git(repo, "cat-file", "-t", pin["sha"]) != "commit":
        raise ValueError(f"{pin_name} commit object unavailable")
    tree = git(repo, "rev-parse", f"{pin['sha']}^{{tree}}")
    if tree != pin["tree"]:
        raise ValueError(f"{pin_name} frozen tree mismatch")
    head = git(repo, "rev-parse", "HEAD")
    status = git(repo, "status", "--porcelain")
    if head != pin["sha"] or status:
        raise ValueError(f"{pin_name} source checkout is not exact and clean (HEAD={head}, status={status!r})")
    files = binding.get("files")
    subtrees = binding.get("subtrees")
    submodules = binding.get("submodules", [])
    if not isinstance(files, dict) or not files or not isinstance(subtrees, dict) or not subtrees or not isinstance(submodules, list):
        raise ValueError(f"{pin_name} binding coverage missing")
    for rel, expected in files.items():
        raw = subprocess.run(["git", "-C", str(repo), "show", f"{pin['sha']}:{rel}"], check=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
        if _digest_bytes(raw) != expected:
            raise ValueError(f"{pin_name} bound file byte mismatch: {rel}")
        worktree_path = repo / rel
        if worktree_path.is_symlink():
            worktree_bytes = os.fsencode(os.readlink(worktree_path))
        elif worktree_path.is_file():
            worktree_bytes = worktree_path.read_bytes()
        else:
            raise ValueError(f"{pin_name} bound worktree file missing: {rel}")
        if _digest_bytes(worktree_bytes) != expected:
            raise ValueError(f"{pin_name} bound worktree byte mismatch: {rel}")
    for rel, expected in subtrees.items():
        if git(repo, "rev-parse", f"{pin['sha']}:{rel}") != expected:
            raise ValueError(f"{pin_name} bound subtree mismatch: {rel}")
    submodule_states = []
    for item in submodules:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not _is_sha(item.get("commit")):
            raise ValueError(f"{pin_name} malformed submodule pin")
        actual = git(repo, "ls-tree", pin["sha"], "--", item["path"])
        if not actual.endswith("\t" + item["path"]) or actual.split()[2] != item["commit"]:
            raise ValueError(f"{pin_name} submodule identity mismatch: {item['path']}")
        module = repo / item["path"]
        if not module.exists() or not (module / ".git").exists():
            submodule_states.append({"path": item["path"], "state": "UNINITIALIZED", "expected_commit": item["commit"]})
            if require_submodules:
                raise ValueError(f"{pin_name} submodule is not initialized: {item['path']}")
            continue
        module_head = git(module, "rev-parse", "HEAD")
        module_tree = git(module, "rev-parse", "HEAD^{tree}")
        module_status = git(module, "status", "--porcelain")
        if module_head != item["commit"] or module_status:
            raise ValueError(f"{pin_name} initialized submodule drift/dirty: {item['path']}")
        submodule_states.append({"path": item["path"], "state": "VALID", "head": module_head, "tree": module_tree})
    return {"pin": pin_name, "sha": pin["sha"], "tree": pin["tree"], "head": head,
            "binding_sha256": sha256(_binding_path(pin)), "bound_files": len(files),
            "bound_subtrees": len(subtrees), "submodules": submodule_states, "status": "VALID"}


def prepare_std(repo_url: str, destination: Path, request: dict[str, Any] | None = None) -> dict[str, Any]:
    req = request or load_request(); spec = req["std"]
    if destination.exists() and any(destination.iterdir()):
        raise ValueError(f"refusing non-empty std destination: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir(exist_ok=True)
    subprocess.run(["git", "clone", "--no-hardlinks", repo_url, str(destination)], check=True)
    git(destination, "checkout", "--detach", spec["base_sha"])
    subprocess.run(["git", "-C", str(destination), "submodule", "update", "--init", "--depth", "1"], check=True)
    _verify_std_base(destination, spec)
    patch = HERE / spec["patch"]
    subprocess.run(["git", "-C", str(destination), "apply", "--check", str(patch)], check=True)
    subprocess.run(["git", "-C", str(destination), "apply", str(patch)], check=True)
    _verify_std_overlay(destination, spec)
    return {"base_sha": spec["base_sha"], "base_tree": spec["base_tree"],
            "base_library_tree": spec["base_library_tree"], "patch_sha256": sha256(patch),
            "patched_files": spec["patched_files"], "status": "PREPARED_NOT_RUN"}


def _verify_std_base(repo: Path, spec: dict[str, Any]) -> dict[str, str]:
    actual = {"head": git(repo, "rev-parse", "HEAD"), "tree": git(repo, "rev-parse", "HEAD^{tree}"),
              "library_tree": git(repo, "rev-parse", "HEAD:library")}
    expected = {"head": spec["base_sha"], "tree": spec["base_tree"], "library_tree": spec["base_library_tree"]}
    if actual != expected:
        raise ValueError(f"std base pin mismatch: expected {expected}, got {actual}")
    return actual


def _verify_std_overlay(repo: Path, spec: dict[str, Any]) -> dict[str, Any]:
    status = subprocess.run(["git", "-C", str(repo), "status", "--porcelain=v1", "-z"], check=True,
                            stdout=subprocess.PIPE).stdout
    paths = sorted(entry[3:].decode() for entry in status.split(b"\0") if entry)
    expected_paths = sorted(spec["patched_files"])
    hashes = {rel: sha256(repo / rel) for rel in expected_paths if (repo / rel).is_file()}
    if paths != expected_paths or hashes != spec["patched_files"]:
        raise ValueError(f"std overlay path/hash mismatch: paths={paths}, hashes={hashes}")
    return {"paths": paths, "sha256": hashes}


def parse_export(path: Path, selector: str) -> dict[str, Any]:
    """Bind one parsed Kani result to exactly one selected harness; never award proof credit."""
    if not path.exists(): return {"state": "MISSING", "outcome": "UNKNOWN"}
    try:
        raw = path.read_bytes()
        if not raw: return {"state": "EMPTY", "outcome": "UNKNOWN"}
        doc = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        return {"state": "INVALID_OR_PARTIAL", "error": str(e), "outcome": "UNKNOWN"}
    if doc is None: return {"state": "NULL", "outcome": "UNKNOWN"}
    if not isinstance(doc, dict): return {"state": "WRONG_TOP_LEVEL_TYPE", "outcome": "UNKNOWN"}
    run_state = doc.get("run_state")
    if run_state == "NO_HARNESSES_SELECTED":
        return {"state": "NO_HARNESSES_SELECTED", "run_state": run_state, "outcome": "UNKNOWN"}
    if run_state != "COMPLETE":
        return {"state": "PARTIAL" if run_state == "PARTIAL" else "UNKNOWN_SCHEMA",
                "run_state": run_state, "outcome": "UNKNOWN"}
    selection = doc.get("harness_selection")
    harnesses = doc.get("harnesses")
    if not isinstance(selection, dict) or not isinstance(harnesses, list):
        return {"state": "UNKNOWN_SCHEMA", "outcome": "UNKNOWN"}
    matched_count = selection.get("matched_count")
    unmatched = selection.get("unmatched_filters")
    exact = selection.get("exact")
    requested = selection.get("requested_filters")
    if (not isinstance(matched_count, int) or isinstance(matched_count, bool) or
            not isinstance(unmatched, list) or not isinstance(requested, list) or not isinstance(exact, bool)):
        return {"state": "UNKNOWN_HARNESS_SELECTION", "outcome": "UNKNOWN"}
    if matched_count != 1 or unmatched:
        return {"state": "UNKNOWN_HARNESS_SELECTION", "matched_count": matched_count,
                "unmatched_filters": unmatched, "outcome": "UNKNOWN"}
    if exact is not True and selector != "reassemble_ptr_fragments_in_static":
        return {"state": "UNKNOWN_HARNESS_SELECTION", "exact": exact, "outcome": "UNKNOWN"}
    if selector != "reassemble_ptr_fragments_in_static" and not any(
            isinstance(f, str) and (f == selector or f.endswith("::" + selector)) for f in requested):
        return {"state": "UNKNOWN_HARNESS_SELECTION", "requested_filters": requested, "outcome": "UNKNOWN"}
    if len(harnesses) != 1 or not isinstance(harnesses[0], dict):
        return {"state": "UNKNOWN_WRONG_SELECTOR", "harness_count": len(harnesses), "outcome": "UNKNOWN"}
    h = harnesses[0]
    name = h.get("name")
    if not isinstance(name, str) or not (name == selector or name.endswith("::" + selector)):
        return {"state": "UNKNOWN_WRONG_SELECTOR", "observed_name": name, "outcome": "UNKNOWN"}
    autogenerated = h.get("is_automatically_generated")
    if selector == "reassemble_ptr_fragments_in_static":
        if autogenerated is not True:
            return {"state": "UNKNOWN_WRONG_SELECTOR", "observed_name": name,
                    "is_automatically_generated": autogenerated, "outcome": "UNKNOWN"}
    elif autogenerated is True:
        return {"state": "UNKNOWN_WRONG_SELECTOR", "observed_name": name,
                "is_automatically_generated": True, "outcome": "UNKNOWN"}
    outcome = h.get("outcome")
    checks, covers = h.get("checks"), h.get("covers")
    check_arrays = ("failure", "unreachable", "undetermined", "error", "unknown", "other")
    cover_arrays = ("satisfied", "unsatisfiable", "unreachable", "undetermined", "error", "unknown", "other")
    if (not isinstance(h.get("file"), str) or not isinstance(h.get("line"), int) or
            not isinstance(outcome, dict) or not isinstance(outcome.get("kind"), str) or
            (outcome.get("kind") == "COMPLETED" and outcome.get("verdict") not in ("SUCCESS", "FAILURE", "UNKNOWN")) or
            not isinstance(h.get("is_automatically_generated"), bool) or
            not isinstance(h.get("failed_properties"), list) or
            not isinstance(h.get("unsupported_constructs"), list) or
            not isinstance(checks, dict) or not isinstance(covers, dict) or
            not isinstance(checks.get("total"), int) or not isinstance(checks.get("success"), int) or
            any(not isinstance(checks.get(k), list) for k in check_arrays) or
            not isinstance(covers.get("total"), int) or
            any(not isinstance(covers.get(k), list) for k in cover_arrays)):
        return {"state": "UNKNOWN_HARNESS_SCHEMA", "observed_name": name, "outcome": "UNKNOWN"}
    summary = {key: h.get(key) for key in (
        "name", "file", "line", "is_automatically_generated", "outcome", "n_properties",
        "n_failed", "failed_properties", "unsupported_constructs", "checks", "covers",
        "resolved_solver", "resolved_unwind") if key in h}
    return {"state": "UNVALIDATED_COMPLETE_SINGLE_HARNESS", "run_state": run_state,
            "harness_selection": {"requested_filters": requested,
                                  "exact": exact, "matched_count": matched_count,
                                  "unmatched_filters": unmatched},
            "harness": summary, "outcome": "UNKNOWN", "generated_property_binding": None,
            "review_required": ["verify selected source/body and useful checks/covers",
                                "inspect all failures, unsupported constructs, unwind and artifact completeness"]}


def _memory_threshold() -> dict[str, Any]:
    frozen_available = os.environ.get("A1_MEM_AVAILABLE_BYTES")
    frozen_limit = os.environ.get("A1_RSS_LIMIT_BYTES")
    if frozen_available is not None or frozen_limit is not None:
        try:
            available = int(frozen_available)
            limit = int(frozen_limit)
        except (TypeError, ValueError) as e:
            raise ValueError("A1 RSS policy requires integer available and limit byte variables") from e
        if available < 0 or limit < 0 or limit > max(0, available - RSS_RESERVE_BYTES):
            raise ValueError("frozen A1 RSS limit exceeds recorded MemAvailable minus 2 GiB reserve")
        return {"available_bytes_before_dispatch": available, "reserve_bytes": RSS_RESERVE_BYTES,
                "group_rss_kill_threshold_bytes": limit, "status": "FROZEN_JOB_POLICY"}
    available = None
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemAvailable:"):
                available = int(line.split()[1]) * 1024
                break
    except (OSError, ValueError):
        pass
    return {"available_bytes_before_dispatch": available, "reserve_bytes": RSS_RESERVE_BYTES,
            "group_rss_kill_threshold_bytes": max(0, available - RSS_RESERVE_BYTES) if available is not None else None,
            "status": "OBSERVED" if available is not None else "UNKNOWN_NO_WATCHDOG_THRESHOLD"}


def _process_group_rss(pgid: int) -> dict[str, int]:
    total = driver = backend = 0
    proc = Path("/proc")
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
            tail = stat[stat.rfind(")") + 2:].split()
            group = int(tail[2])
            if group != pgid:
                continue
            rss = 0
            for line in (entry / "status").read_text().splitlines():
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1]) * 1024; break
            total += rss
            cmd = (entry / "comm").read_text().strip().lower()
            if "kani-driver" in cmd: driver += rss
            if any(token in cmd for token in ("cbmc", "kissat", "cadical", "z3")): backend += rss
        except (OSError, ValueError, IndexError):
            continue
    return {"aggregate_current_bytes": total, "driver_current_bytes": driver, "backend_current_bytes": backend}


def _group_exists(pgid: int) -> bool:
    """Ignore zombies; they retain a process-group id after all work is dead."""
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit(): continue
        try:
            stat = (entry / "stat").read_text()
            fields = stat[stat.rfind(")") + 2:].split()
            if int(fields[2]) == pgid and fields[0] not in ("Z", "X"):
                return True
        except (OSError, ValueError, IndexError):
            continue
    return False


def _tree_bytes(root: Path) -> tuple[int, int, list[str]]:
    total = metadata = 0; oversized: list[str] = []
    if not root.exists(): return total, metadata, oversized
    for p in root.rglob("*"):
        try:
            if "target" in p.relative_to(root).parts:
                continue
            if p.is_file():
                size = p.stat().st_size; total += size
                if p.suffix.lower() in (".json", ".jsonl"):
                    metadata += size
                    if size > METADATA_LIMIT: oversized.append(str(p))
        except OSError:
            continue
    return total, metadata, oversized


def execute(argv: list[str], cwd: Path, env: dict[str, str], out: Path,
            timeout_seconds: float = MAX_INVOCATION_SECONDS,
            artifact_root: Path | None = None) -> dict[str, Any]:
    """Bound a whole process group and stream/artifact growth; preserve leader wait4 data."""
    if timeout_seconds <= 0 or timeout_seconds > MAX_INVOCATION_SECONDS:
        raise ValueError(f"invocation cap must be in (0,{MAX_INVOCATION_SECONDS}] seconds")
    out.mkdir(parents=True, exist_ok=True)
    artifact_root = artifact_root or out
    if not artifact_root.is_absolute():
        raise ValueError("aggregate artifact root must be absolute")
    start = time.time(); deadline = time.monotonic() + timeout_seconds
    mem = _memory_threshold(); threshold = mem["group_rss_kill_threshold_bytes"]
    result: dict[str, Any] = {"started_unix": start, "original_exit_code": None, "signal": None,
                              "timed_out": False, "output_capped": False, "artifact_capped": False,
                              "rss_watchdog_killed": False, "runner_error": None,
                              "rss_status": "UNKNOWN", "rss_max_bytes": None,
                              "group_rss_peak_bytes": 0, "driver_rss_peak_bytes": 0,
                              "backend_rss_peak_bytes": 0, "memory_threshold": mem}
    streams = {"stdout": bytearray(), "stderr": bytearray()}
    tails = {"stdout": bytearray(), "stderr": bytearray()}
    limits = {"stdout": STDOUT_LIMIT, "stderr": STDERR_LIMIT}
    paths = {name: out / f"{name}.log" for name in streams}
    files = {name: p.open("wb") for name, p in paths.items()}
    proc = None; selector = selectors.DefaultSelector(); leader_wait = None
    term_sent_at = None; kill_reason = None; trunc = {"stdout": False, "stderr": False}
    try:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        assert proc.stdout and proc.stderr
        selector.register(proc.stdout, selectors.EVENT_READ, "stdout")
        selector.register(proc.stderr, selectors.EVENT_READ, "stderr")
        while True:
            now = time.monotonic()
            # Record leader's raw wait4 exactly once; continue until the entire group exits.
            if leader_wait is None:
                try:
                    pid, status, usage = os.wait4(proc.pid, os.WNOHANG)
                    if pid == proc.pid:
                        leader_wait = (status, usage)
                        proc.returncode = os.waitstatus_to_exitcode(status)
                except InterruptedError:
                    pass
            rss = _process_group_rss(proc.pid)
            result["group_rss_peak_bytes"] = max(result["group_rss_peak_bytes"], rss["aggregate_current_bytes"])
            result["driver_rss_peak_bytes"] = max(result["driver_rss_peak_bytes"], rss["driver_current_bytes"])
            result["backend_rss_peak_bytes"] = max(result["backend_rss_peak_bytes"], rss["backend_current_bytes"])
            if threshold is not None and rss["aggregate_current_bytes"] > threshold and kill_reason is None:
                kill_reason = "RSS_WATCHDOG"; result["rss_watchdog_killed"] = True
            total, metadata, oversized = _tree_bytes(artifact_root)
            if (total > JOB_OUTPUT_LIMIT or metadata > METADATA_LIMIT or oversized) and kill_reason is None:
                kill_reason = "ARTIFACT_OUTPUT_CAP"; result["artifact_capped"] = True
            if now >= deadline and kill_reason is None:
                kill_reason = "TIMEOUT"; result["timed_out"] = True
            if any(trunc.values()) and kill_reason is None:
                kill_reason = "STREAM_OUTPUT_CAP"; result["output_capped"] = True
            if kill_reason and term_sent_at is None:
                try: os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError: pass
                term_sent_at = now
            if term_sent_at is not None and now - term_sent_at >= TERM_GRACE_SECONDS:
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            for key, _ in selector.select(timeout=0.05):
                name = key.data
                try: chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                except OSError: chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj); key.fileobj.close(); continue
                room = limits[name] - len(streams[name])
                if room > 0:
                    keep = chunk[:room]; streams[name].extend(keep); files[name].write(keep)
                if len(chunk) > max(room, 0): trunc[name] = True
                tails[name].extend(chunk)
                if len(tails[name]) > EXCERPT_LIMIT:
                    del tails[name][:-EXCERPT_LIMIT]
            if leader_wait is not None and not _group_exists(proc.pid) and not selector.get_map():
                break
            if leader_wait is None and not _group_exists(proc.pid):
                # Reap below on next cycle (normally wait4 sees it immediately).
                pass
        if leader_wait is None:
            while True:
                try:
                    _, status, usage = os.wait4(proc.pid, 0); leader_wait = (status, usage); break
                except InterruptedError: continue
        status, usage = leader_wait; code = os.waitstatus_to_exitcode(status)
        proc.returncode = code; result["original_exit_code"] = code
        result["rss_max_kib"] = int(usage.ru_maxrss)
        result["rss_max_bytes"] = int(usage.ru_maxrss * 1024)
        result["rss_max_mib"] = result["rss_max_bytes"] / (1024 ** 2)
        result["rss_max_gib"] = result["rss_max_bytes"] / (1024 ** 3)
        result["rss_status"] = "OBSERVED_WAIT4_LINUX_RU_MAXRSS"
        if code < 0: result["signal"] = -code
        if kill_reason == "TIMEOUT": result["runner_error"] = f"{timeout_seconds:g}s group cap elapsed; TERM then KILL"
        elif kill_reason: result["runner_error"] = f"{kill_reason}; process group terminated"
    except (OSError, subprocess.SubprocessError) as e:
        result["runner_error"] = f"runner_exec_or_wait_error: {e}"
        if proc is not None and _group_exists(proc.pid):
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
    finally:
        selector.close()
        for stream in (getattr(proc, "stdout", None), getattr(proc, "stderr", None)):
            if stream:
                try: stream.close()
                except OSError: pass
        for f in files.values():
            try: f.close()
            except OSError: pass
    result["elapsed_seconds"] = round(time.time() - start, 3)
    result["stdout_bytes"] = len(streams["stdout"]); result["stderr_bytes"] = len(streams["stderr"])
    result["stdout_truncated"] = trunc["stdout"]; result["stderr_truncated"] = trunc["stderr"]
    result["stdout_sha256"] = sha256(paths["stdout"]); result["stderr_sha256"] = sha256(paths["stderr"])
    excerpt_descriptors = {}
    for name in ("stdout", "stderr"):
        for side, data in (("head", streams[name][:EXCERPT_LIMIT]), ("tail", tails[name])):
            excerpt_path = out / f"{name}.{side}.log"
            excerpt_path.write_bytes(data)
            excerpt_descriptors[f"{name}_{side}"] = {
                "path": excerpt_path.name, "bytes": len(data), "sha256": _digest_bytes(data),
                "source": "observed_stream", "state": "COMPLETE",
            }
    result["stream_excerpts"] = excerpt_descriptors
    result["output_tree_bytes"] = _tree_bytes(artifact_root)[0]
    if kill_reason == "TIMEOUT":
        result["termination_classification"] = "TIMEOUT"
    elif kill_reason == "RSS_WATCHDOG":
        result["termination_classification"] = "RSS_WATCHDOG"
    elif kill_reason in ("STREAM_OUTPUT_CAP", "ARTIFACT_OUTPUT_CAP"):
        result["termination_classification"] = "OUTPUT_CAP"
    elif result.get("signal") == signal.SIGKILL:
        result["termination_classification"] = "SIGNAL_9_OOM_OR_EXTERNAL_UNKNOWN"
    elif result.get("signal"):
        result["termination_classification"] = f"SIGNAL_{result['signal']}"
    elif result.get("original_exit_code") is not None:
        result["termination_classification"] = "EXITED"
    else:
        result["termination_classification"] = "UNKNOWN_RUNNER_LOSS_OR_SETUP"
    result["outcome"] = "UNKNOWN"
    return result


def root_exit_code(receipt: dict[str, Any]) -> int:
    """Return the verifier's nonzero code unchanged; UNKNOWN/incomplete is nonzero."""
    code = receipt.get("original_exit_code")
    if isinstance(code, int) and code > 0: return code
    if (code is None or code < 0 or receipt.get("timed_out") or receipt.get("runner_error") or
            receipt.get("output_capped") or receipt.get("artifact_capped") or receipt.get("rss_watchdog_killed") or
            receipt.get("postprocessing_state") != "COMPLETE" or
            receipt.get("export", {}).get("state") in INVALID_EXPORT_STATES): return 1
    post = receipt.get("post_run_validation")
    if not isinstance(post, dict):
        return "post-run validation missing or wrong type"
    if post.get("source_valid") is not True: return 1
    if post.get("controls_valid") is not True: return 1
    if receipt.get("stage") == "r1" and post.get("std_overlay_valid") is not True: return 1
    if receipt.get("stage") == "r1" and post.get("std_base_valid") is not True: return 1
    if receipt.get("stage") == "r2" and post.get("fixture_valid") is not True: return 1
    rss = receipt.get("rss", {})
    if rss.get("status") != "OBSERVED_WAIT4_LINUX_RU_MAXRSS" or not isinstance(rss.get("max_bytes"), int): return 1
    return 0


def bound_artifacts(out: Path) -> dict[str, Any]:
    """Enforce upload limits, preserving receipts and recording every trimmed artifact."""
    if not out.is_dir():
        raise ValueError(f"artifact directory missing: {out}")
    # Exclude every directory named target without opening or hashing its contents.
    excluded_targets: list[dict[str, Any]] = []
    target_dirs = sorted((p for p in out.rglob("*") if p.is_dir() and p.name == "target"),
                         key=lambda p: len(p.parts))
    for target in target_dirs:
        if not target.exists():
            continue
        size = 0
        for base, dirs, names in os.walk(target):
            dirs[:] = dirs
            for name in names:
                try: size += (Path(base) / name).stat().st_size
                except OSError: pass
        rel = target.relative_to(out).as_posix()
        shutil.rmtree(target)
        excluded_targets.append({"path": rel, "bytes": size, "state": "INTENTIONALLY_EXCLUDED_TARGET_DIRECTORY"})
    # If execute was stubbed or did not produce excerpts, derive head/tail from its
    # already bounded stdout.log/stderr.log. Never synthesize a tail from discarded bytes.
    for source in out.rglob("*.log"):
        if source.name not in ("stdout.log", "stderr.log"):
            continue
        stream = source.stem
        for side in ("head", "tail"):
            dest = source.with_name(f"{stream}.{side}.log")
            if not dest.exists() and source.is_file():
                with source.open("rb") as f:
                    if side == "head": data = f.read(EXCERPT_LIMIT)
                    else:
                        f.seek(max(0, source.stat().st_size - EXCERPT_LIMIT)); data = f.read(EXCERPT_LIMIT)
                dest.write_bytes(data)
    files = [p for p in out.rglob("*") if p.is_file() and p.name != "bound-artifacts.json"]
    total = sum(p.stat().st_size for p in files)
    metadata = sum(p.stat().st_size for p in files if p.suffix.lower() in (".json", ".jsonl"))
    removed: list[dict[str, Any]] = []
    # Preserve receipts first. If necessary, remove the largest non-receipt artifacts.
    protected = {"receipt.json", "receipts.json", "stdout.head.log", "stdout.tail.log",
                 "stderr.head.log", "stderr.tail.log"}
    candidates = sorted((p for p in files if p.name not in protected),
                       key=lambda p: p.stat().st_size, reverse=True)
    for p in candidates:
        if total <= JOB_OUTPUT_LIMIT:
            break
        if not p.exists(): continue
        size = p.stat().st_size
        # Hash before deletion so the manifest identifies exactly what was omitted.
        removed.append({"path": p.relative_to(out).as_posix(), "bytes": size, "sha256": sha256(p),
                        "state": "TRUNCATED_REMOVED"})
        p.unlink()
        total -= size
        if p.suffix.lower() in (".json", ".jsonl"):
            metadata -= size
    metadata_candidates = sorted((p for p in files if p.name not in protected and
                                   p.suffix.lower() in (".json", ".jsonl") and p.exists()),
                                 key=lambda p: p.stat().st_size, reverse=True)
    for p in metadata_candidates:
        if metadata <= METADATA_LIMIT: break
        size = p.stat().st_size
        removed.append({"path": p.relative_to(out).as_posix(), "bytes": size, "sha256": sha256(p),
                        "state": "TRUNCATED_REMOVED"})
        p.unlink(); total -= size; metadata -= size
    state = "COMPLETE" if not removed and total <= JOB_OUTPUT_LIMIT and metadata <= METADATA_LIMIT else "TRUNCATED"
    manifest = {"schema": "ch8-w0-a1-bounded-artifacts-v1", "state": state,
                "total_bytes_after": total, "metadata_bytes_after": metadata,
                "total_cap_bytes": JOB_OUTPUT_LIMIT, "metadata_cap_bytes": METADATA_LIMIT,
                "removed": removed, "intentional_exclusions": excluded_targets,
                "outcome": "UNKNOWN"}
    if total > JOB_OUTPUT_LIMIT or metadata > METADATA_LIMIT:
        manifest["state"] = "INCOMPLETE_PROTECTED_RECEIPTS_EXCEED_CAP"
    # Mark every durable receipt incomplete when artifact loss occurs or caps remain exceeded.
    if manifest["state"] != "COMPLETE":
        for p in out.rglob("receipt.json"):
            try:
                value = json.loads(p.read_text())
                value["postprocessing_state"] = "INCOMPLETE"
                value["artifact_bound_state"] = manifest["state"]
                value["artifact_truncations"] = removed
                value["outcome"] = "UNKNOWN"
                write_json_atomic(p, value)
            except (OSError, json.JSONDecodeError, TypeError):
                pass
    write_json_atomic(out / "bound-artifacts.json", manifest)
    final_total, final_metadata, final_oversized = _tree_bytes(out)
    manifest["total_bytes_after"] = final_total
    manifest["metadata_bytes_after"] = final_metadata
    if final_total > JOB_OUTPUT_LIMIT or final_metadata > METADATA_LIMIT or final_oversized:
        manifest["state"] = "INCOMPLETE_PROTECTED_RECEIPTS_EXCEED_CAP"
        for p in out.rglob("receipt.json"):
            try:
                value = json.loads(p.read_text())
                value["postprocessing_state"] = "INCOMPLETE"
                value["artifact_bound_state"] = manifest["state"]
                value["artifact_truncations"] = removed
                value["outcome"] = "UNKNOWN"
                write_json_atomic(p, value)
            except (OSError, json.JSONDecodeError, TypeError):
                pass
        final_total, final_metadata, _ = _tree_bytes(out)
        manifest["total_bytes_after"] = final_total
        manifest["metadata_bytes_after"] = final_metadata
    write_json_atomic(out / "bound-artifacts.json", manifest)
    return manifest


def _fixture_for(row: dict[str, Any]) -> tuple[Path, str]:
    path = (HERE / row["fixture"]).resolve()
    if HERE not in path.parents or not path.is_file(): raise ValueError("native fixture missing or escaped CI controls")
    digest = sha256(path)
    if digest != row["fixture_sha256"]: raise ValueError(f"fixture byte hash mismatch: {row['fixture']}")
    return path, digest


def control_snapshot(pin_name: str, fixture: Path | None = None) -> dict[str, str]:
    pin = load_request()["pins"][pin_name]
    paths = {"request": REQUEST, "std_patch": HERE / "std-test-only.patch",
             "binding": _binding_path(pin), "adapter": Path(__file__).resolve(),
             "replay_origin": Path(origin.__file__).resolve()}
    if fixture is not None: paths["native_fixture"] = fixture
    return {key: sha256(path) for key, path in paths.items()}


def run(repo: Path, pin_name: str, stage_name: str, row_id: str, binary: Path, out: Path,
        std: Path | None = None, timeout_seconds: int = MAX_INVOCATION_SECONDS) -> dict[str, Any]:
    req = load_request(); section = req[stage_name]
    rows = section["rows"]
    row = next((r for r in rows if r["id"] == row_id), None)
    if row is None: raise ValueError(f"row is not in exact {stage_name} request: {row_id}")
    validate_row(stage_name, row)
    if stage_name == "r1" and std is None: raise ValueError("r1 requires the separately prepared std checkout")
    if stage_name == "r2" and std is not None: raise ValueError("r2 native rows cannot receive a std checkout")
    source_identity = verify_source(repo, pin_name, req, require_submodules=True)
    std_base_before = _verify_std_base(std, req["std"]) if std is not None else None
    std_before = _verify_std_overlay(std, req["std"]) if std is not None else None
    expected_binary = (repo / "scripts" / "kani").resolve()
    if not binary.is_absolute() or binary.resolve() != expected_binary or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError(f"binary must be the absolute frozen export executable {expected_binary}")
    if not out.is_absolute(): raise ValueError("output directory must be absolute")
    if out.exists(): raise ValueError(f"refusing existing invocation output: {out}")
    fixture_source = fixture_hash = native_cwd = isolated_fixture = None
    out.mkdir(parents=True, exist_ok=False)
    if stage_name == "r2":
        fixture_source, fixture_hash = _fixture_for(row)
        native_root = out / "cwd"
        native_root.mkdir()
        isolated_fixture = native_root / fixture_source.name
        shutil.copyfile(fixture_source, isolated_fixture)
        os.chmod(isolated_fixture, fixture_source.stat().st_mode & 0o777)
        if sha256(isolated_fixture) != fixture_hash: raise ValueError("isolated fixture copy hash mismatch")
        native_cwd = native_root
    argv = []
    for arg in row["argv"]:
        arg = arg.replace("<KANI>", str(binary)).replace("<OUT>", str(out))
        if stage_name == "r2": arg = arg.replace("<FIXTURE>", str(isolated_fixture))
        argv.append(arg)
    cwd = std if stage_name == "r1" else native_cwd
    if cwd is None or not cwd.is_absolute(): raise ValueError("actual working directory must be absolute")
    env = os.environ.copy()
    if stage_name == "r2":
        # Keep the issue-only compiler flags scoped to the original #4854 invocation.
        env.pop("RUSTFLAGS", None); env.pop("RUST_BACKTRACE", None)
    for key, value in row["environment"].items():
        if value is None: env.pop(key, None)
        else: env[key] = value
    receipt_path = out / "receipt.json"
    controls_before = control_snapshot(pin_name, fixture_source)
    begin = {
        "schema": "ch8-w0-a1-ci-receipt-v1", "pin": pin_name, "stage": stage_name,
        "row_id": row_id, "selector": row["selector"], "mode": row.get("mode"),
        "target": row.get("target"), "types": row.get("target_types", row.get("types")),
        "request_sha256": sha256(REQUEST), "source_identity": source_identity,
        "fixture": str(fixture_source.relative_to(HERE)) if fixture_source else None,
        "fixture_sha256": fixture_hash, "argv": argv,
        "cwd": str(cwd), "input_abs_path": str(isolated_fixture) if isolated_fixture else None,
        "control_snapshot_before": controls_before,
        "environment": {k: env.get(k) for k in row["environment"]},
        "diagnostic_environment": {k: env.get(k) for k in DIAGNOSTIC_ENV_KEYS if k in env},
        "std_base_before": std_base_before, "std_before": std_before, "phase": "BEGIN", "outcome": "UNKNOWN",
        "proof_status": "NOT_RUN_UNTIL_REVIEWED", "postprocessing_state": "INCOMPLETE",
    }
    write_json_atomic(receipt_path, begin)
    artifact_root = out.parent.parent if out.parent.name in PIN_NAMES else out.parent
    execution = execute(argv, cwd, env, out, timeout_seconds, artifact_root=artifact_root)
    receipt: dict[str, Any] = {
        "schema": "ch8-w0-a1-ci-receipt-v1", "pin": pin_name, "stage": stage_name,
        "row_id": row_id, "selector": row["selector"], "mode": row.get("mode"),
        "target": row.get("target"), "types": row.get("target_types", row.get("types")),
        "request_sha256": sha256(REQUEST), "source_identity": source_identity,
        "fixture": str(fixture_source.relative_to(HERE)) if fixture_source else None,
        "fixture_sha256": fixture_hash, "argv": argv,
        "cwd": str(cwd), "input_abs_path": str(isolated_fixture) if isolated_fixture else None,
        "control_snapshot_before": controls_before,
        "environment": {k: env.get(k) for k in row["environment"]},
        "diagnostic_environment": {k: env.get(k) for k in DIAGNOSTIC_ENV_KEYS if k in env},
        "std_base_before": std_base_before, "std_before": std_before,
        "rss": {"max_kib": execution.pop("rss_max_kib", None), "max_bytes": execution.pop("rss_max_bytes"),
          "max_mib": execution.pop("rss_max_mib", None), "max_gib": execution.pop("rss_max_gib", None),
          "status": execution.pop("rss_status"), "group_peak_current_bytes": execution.get("group_rss_peak_bytes"),
          "driver_peak_current_bytes": execution.get("driver_rss_peak_bytes"),
          "backend_peak_current_bytes": execution.get("backend_rss_peak_bytes")},
        **execution, "export": {"state": "PENDING_PARSE", "outcome": "UNKNOWN"},
        "runtime_identity_file": "runtime-identities.json", "outcome": "UNKNOWN",
        "proof_status": "NOT_RUN_UNTIL_REVIEWED", "postprocessing_state": "INCOMPLETE",
    }
    receipt["phase"] = "EXECUTION_COMPLETE" if execution.get("original_exit_code") is not None else "EXECUTION_UNKNOWN"
    write_json_atomic(receipt_path, receipt)
    post_error = None
    try:
        export_path = out / "export.json"
        receipt["export"] = parse_export(export_path, row["selector"])
        if receipt["export"].get("state") == "UNVALIDATED_COMPLETE_SINGLE_HARNESS":
            reported_file = receipt["export"]["harness"]["file"]
            if stage_name == "r2" and Path(reported_file).name != fixture_source.name:
                receipt["export"] = {"state": "UNKNOWN_WRONG_SELECTOR", "reported_file": reported_file,
                                     "expected_fixture": fixture_source.name, "outcome": "UNKNOWN"}
            elif stage_name == "r1" and not reported_file.replace("\\", "/").endswith(
                    "library/core/src/slice/sort/shared/smallsort/verify/wave0_a1.rs"):
                receipt["export"] = {"state": "UNKNOWN_WRONG_SELECTOR", "reported_file": reported_file,
                                     "expected_source_suffix": "library/core/src/slice/sort/shared/smallsort/verify/wave0_a1.rs",
                                     "outcome": "UNKNOWN"}
        # This inventory runs only in the coordinator's CI execution environment.
        runtime = origin.runtime_inventory(repo, binary)
        rustc_info = runtime.get("tools", {}).get("rustc", {}).get("binary", {})
        if rustc_info.get("available"):
            sysroot = subprocess.run([rustc_info["path"], "--print", "sysroot"], check=True,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15).stdout.strip()
            runtime["toolchain_sysroot"] = {"path": sysroot}
        else:
            runtime["toolchain_sysroot"] = {"status": "UNKNOWN_RUSTC_UNAVAILABLE"}
        native_sysroot = (repo / "target" / "kani").resolve()
        runtime["native_kani_sysroot"] = {
            "path": str(native_sysroot), "available": native_sysroot.is_dir(),
            "selection_basis": "source-derived from kani-driver/src/session.rs and call_single_file.rs; not rustc --print sysroot",
        }
        write_json_atomic(out / "runtime-identities.json", runtime)
        source_after = verify_source(repo, pin_name, req, require_submodules=True)
        source_valid = source_after == source_identity
        std_base_after = _verify_std_base(std, req["std"]) if std is not None else None
        std_after = _verify_std_overlay(std, req["std"]) if std is not None else None
        fixture_after = sha256(fixture_source) if fixture_source else None
        isolated_after = sha256(isolated_fixture) if isolated_fixture else None
        controls_after = control_snapshot(pin_name, fixture_source)
        receipt["post_run_validation"] = {
            "source_valid": source_valid, "source_after": source_after,
            "std_overlay_valid": std_after == std_before if std_before is not None else None,
            "std_base_valid": std_base_after == std_base_before if std_base_before is not None else None,
            "std_base_after": std_base_after,
            "std_after": std_after,
            "fixture_valid": fixture_after == fixture_hash and isolated_after == fixture_hash if fixture_hash else None,
            "fixture_source_sha256_after": fixture_after, "isolated_fixture_sha256_after": isolated_after,
            "controls_valid": controls_after == controls_before,
            "control_snapshot_after": controls_after,
        }
        receipt["phase"] = "POSTPROCESSING_COMPLETE"
        receipt["postprocessing_state"] = "COMPLETE"
    except Exception as e:  # durable execution record must survive fallible parsing/inventory/validation
        post_error = {"type": type(e).__name__, "message": str(e)}
        receipt["postprocessing_state"] = "INCOMPLETE"; receipt["postprocessing_error"] = post_error
    write_json_atomic(receipt_path, receipt)
    return receipt


def _compile_error_for_core_lib(receipt: dict[str, Any], row_out: Path) -> bool:
    code = receipt.get("original_exit_code")
    if not isinstance(code, int) or code == 0:
        return False
    if (receipt.get("timed_out") or receipt.get("runner_error") or receipt.get("output_capped") or
            receipt.get("artifact_capped") or receipt.get("rss_watchdog_killed") or
            receipt.get("postprocessing_state") != "COMPLETE" or
            receipt.get("termination_classification") not in (None, "EXITED")):
        return False
    chunks = []
    for stream in ("stdout", "stderr"):
        for side in ("head", "tail"):
            path = row_out / f"{stream}.{side}.log"
            if path.is_file():
                chunks.append(path.read_bytes()[:EXCERPT_LIMIT].decode("utf-8", "replace"))
        if not any((row_out / f"{stream}.{side}.log").is_file() for side in ("head", "tail")):
            path = row_out / f"{stream}.log"
            if path.is_file():
                with path.open("rb") as f:
                    chunks.append(f.read(EXCERPT_LIMIT).decode("utf-8", "replace"))
                    if path.stat().st_size > EXCERPT_LIMIT:
                        f.seek(max(0, path.stat().st_size - EXCERPT_LIMIT))
                        chunks.append(f.read(EXCERPT_LIMIT).decode("utf-8", "replace"))
    text = "\n".join(chunks)
    import re
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return re.search(r"could\s+not\s+compile\s*[`'\"“”‘’]?\s*core\s*[`'\"“”‘’]?\s*\(\s*lib\s*\)",
                     text, re.IGNORECASE) is not None


def _sequence_uncertain(receipt: dict[str, Any], allow_compile_missing_export: bool = False) -> str | None:
    if receipt.get("original_exit_code") is None:
        return "missing original exit code"
    if receipt.get("timed_out"):
        return "timeout"
    if receipt.get("rss_watchdog_killed"):
        return "resource watchdog termination"
    if receipt.get("output_capped") or receipt.get("artifact_capped"):
        return "output cap termination"
    if receipt.get("runner_error"):
        return "runner error"
    if receipt.get("signal") is not None or receipt.get("original_exit_code", 0) < 0:
        return "signal termination"
    if receipt.get("termination_classification") not in (None, "EXITED"):
        return f"uncertain termination: {receipt.get('termination_classification')}"
    if receipt.get("postprocessing_state") != "COMPLETE":
        return "incomplete postprocessing"
    rss = receipt.get("rss")
    if (not isinstance(rss, dict) or rss.get("status") != "OBSERVED_WAIT4_LINUX_RU_MAXRSS" or
            not isinstance(rss.get("max_bytes"), int)):
        return "RSS wait4 evidence missing or invalid"
    export = receipt.get("export")
    state = export.get("state") if isinstance(export, dict) else None
    if state != "UNVALIDATED_COMPLETE_SINGLE_HARNESS" and not (allow_compile_missing_export and state == "MISSING"):
        return f"incomplete or uncertain export: {state}"
    post = receipt.get("post_run_validation", {})
    if any(post.get(k) is not True for k in ("source_valid", "controls_valid", "std_overlay_valid", "std_base_valid")):
        return "post-run validation incomplete or mismatched"
    return None


def _write_not_run_receipt(path: Path, pin_name: str, row: dict[str, Any], reason: str) -> dict[str, Any]:
    path.mkdir(parents=True, exist_ok=False)
    value = {"schema": "ch8-w0-a1-ci-receipt-v1", "pin": pin_name, "stage": "r1",
             "row_id": row["id"], "selector": row["selector"], "status": "NOT_RUN",
             "not_run_reason": reason, "original_exit_code": None, "signal": None,
             "phase": "NOT_RUN", "proof_status": "NOT_RUN", "outcome": "UNKNOWN",
             "postprocessing_state": "INCOMPLETE"}
    write_json_atomic(path / "receipt.json", value)
    return value


def run_r1_sequence(repo: Path, pin_name: str, binary: Path, out: Path, std: Path,
                    timeout_seconds: int = MAX_INVOCATION_SECONDS) -> dict[str, Any]:
    """Run the exact frozen r1 request order, stopping only on confirmed compile or uncertainty."""
    req = load_request()
    if pin_name not in PIN_NAMES:
        raise ValueError(f"unknown source pin: {pin_name}")
    if pin_name != "sel1":
        raise ValueError("r1 sequence requires the frozen sel1 source pin")
    rows = req.get("r1", {}).get("rows")
    if not isinstance(rows, list) or len(rows) != len(R1_SUFFIXES):
        raise ValueError("r1 sequence requires the exact eight requested rows")
    for row in rows:
        validate_row("r1", row)
    expected_first = ("stable_freeze_u64_n32", "unstable_general_nocopy_u64_n32", "unstable_network_u64_n32")
    if tuple(row["id"] for row in rows[:3]) != expected_first:
        raise ValueError("r1 sequence request must begin with the exact three N32 rows in frozen order")
    if not std.is_absolute() or not out.is_absolute():
        raise ValueError("sequence std and output paths must be absolute")
    # Complete all frozen identity/stage checks before creating output or starting a child.
    verify_source(repo, pin_name, req, require_submodules=True)
    _verify_std_base(std, req["std"])
    _verify_std_overlay(std, req["std"])
    if out.exists() and not out.is_dir():
        raise ValueError(f"sequence output exists and is not a directory: {out}")
    out.mkdir(parents=True, exist_ok=True)
    if (out / "sequence-summary.json").exists():
        raise ValueError(f"refusing existing sequence summary: {out / 'sequence-summary.json'}")
    for row in rows:
        if (out / row["id"]).exists():
            raise ValueError(f"refusing existing row output: {out / row['id']}")
    rows_summary: list[dict[str, Any]] = []
    stop_reason: str | None = None
    failure_codes: list[int] = []
    for row in rows:
        row_out = out / row["id"]
        if stop_reason is not None:
            not_run = _write_not_run_receipt(row_out, pin_name, row, stop_reason)
            rows_summary.append({"row_id": row["id"], "status": "NOT_RUN", "receipt": str(row_out / "receipt.json"),
                                 "original_exit_code": None, "reason": stop_reason})
            continue
        try:
            receipt = run(repo, pin_name, "r1", row["id"], binary, row_out, std, timeout_seconds)
        except Exception as exc:
            if not (row_out / "receipt.json").is_file():
                row_out.mkdir(parents=True, exist_ok=True)
                partial = {"schema": "ch8-w0-a1-ci-receipt-v1", "pin": pin_name, "stage": "r1",
                           "row_id": row["id"], "selector": row["selector"], "phase": "RUNNER_EXCEPTION",
                           "original_exit_code": None, "signal": None, "runner_error": f"{type(exc).__name__}: {exc}",
                           "outcome": "UNKNOWN", "proof_status": "NOT_RUN_UNTIL_REVIEWED",
                           "postprocessing_state": "INCOMPLETE"}
                write_json_atomic(row_out / "receipt.json", partial)
            else:
                try:
                    partial = json.loads((row_out / "receipt.json").read_text())
                    partial.setdefault("runner_error", f"{type(exc).__name__}: {exc}")
                    partial["postprocessing_state"] = "INCOMPLETE"
                    partial["outcome"] = "UNKNOWN"
                    write_json_atomic(row_out / "receipt.json", partial)
                except (OSError, json.JSONDecodeError):
                    partial = {"original_exit_code": None}
            rows_summary.append({"row_id": row["id"], "status": "EXCEPTION", "receipt": str(row_out / "receipt.json"),
                                 "original_exit_code": partial.get("original_exit_code"),
                                 "reason": f"{type(exc).__name__}: {exc}"})
            stop_reason = f"predecessor {row['id']} receipt {row_out / 'receipt.json'}: row raised {type(exc).__name__}; later rows not run"
            failure_codes.append(1)
            continue
        code = receipt.get("original_exit_code")
        row_state = "COMPLETE" if receipt.get("postprocessing_state") == "COMPLETE" else "INCOMPLETE"
        rows_summary.append({"row_id": row["id"], "status": row_state, "receipt": str(row_out / "receipt.json"),
                             "original_exit_code": code, "signal": receipt.get("signal")})
        confirmed_compile = _compile_error_for_core_lib(receipt, row_out)
        uncertain = _sequence_uncertain(receipt, allow_compile_missing_export=confirmed_compile)
        if uncertain:
            stop_reason = f"predecessor {row['id']} receipt {row_out / 'receipt.json'}: {uncertain}; later rows not run"
            failure_codes.append(code if isinstance(code, int) and code > 0 else 1)
        elif code != 0:
            failure_codes.append(code if isinstance(code, int) and code > 0 else 1)
            if confirmed_compile:
                stop_reason = f"predecessor {row['id']} receipt {row_out / 'receipt.json'}: confirmed core (lib) compile error; later rows not run"
    summary = {"schema": "ch8-w0-a1-r1-sequence-v1", "pin": pin_name, "stage": "r1",
               "order": [r["id"] for r in rows], "rows": rows_summary, "stop_reason": stop_reason,
               "return_code": failure_codes[0] if failure_codes else 0, "outcome": "UNKNOWN"}
    write_json_atomic(out / "sequence-summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify-source"); v.add_argument("--repo", type=Path, required=True); v.add_argument("--pin", choices=PIN_NAMES, required=True)
    p = sub.add_parser("prepare-std"); p.add_argument("--repo", required=True); p.add_argument("--destination", type=Path, required=True)
    b = sub.add_parser("bound-artifacts"); b.add_argument("--out", type=Path, required=True)
    r = sub.add_parser("run"); r.add_argument("--repo", type=Path, required=True); r.add_argument("--pin", choices=PIN_NAMES, required=True)
    r.add_argument("--stage", choices=("r1", "r2"), required=True); r.add_argument("--row", required=True)
    r.add_argument("--std", type=Path); r.add_argument("--binary", type=Path, required=True); r.add_argument("--out", type=Path, required=True)
    r.add_argument("--timeout-seconds", type=int, default=MAX_INVOCATION_SECONDS)
    q = sub.add_parser("run-r1-sequence"); q.add_argument("--repo", type=Path, required=True)
    q.add_argument("--pin", choices=PIN_NAMES, required=True); q.add_argument("--std", type=Path, required=True)
    q.add_argument("--binary", type=Path, required=True); q.add_argument("--out", type=Path, required=True)
    q.add_argument("--timeout-seconds", type=int, default=MAX_INVOCATION_SECONDS)
    args = parser.parse_args()
    try:
        if args.command == "verify-source": result = verify_source(args.repo, args.pin)
        elif args.command == "prepare-std": result = prepare_std(args.repo, args.destination)
        elif args.command == "bound-artifacts":
            result = bound_artifacts(args.out)
            print(json.dumps(result, indent=2, sort_keys=True))
            return 1 if result["state"] != "COMPLETE" else 0
        elif args.command == "run-r1-sequence":
            result = run_r1_sequence(args.repo, args.pin, args.binary, args.out, args.std, args.timeout_seconds)
        else:
            result = run(args.repo, args.pin, args.stage, args.row, args.binary, args.out, args.std, args.timeout_seconds)
        print(json.dumps(result, indent=2, sort_keys=True))
        return result["return_code"] if args.command == "run-r1-sequence" else (root_exit_code(result) if args.command == "run" else 0)
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError) as e:
        print(f"A1 CI wrapper error: {e}", file=sys.stderr); return 2


if __name__ == "__main__":
    raise SystemExit(main())
