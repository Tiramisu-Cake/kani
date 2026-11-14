#!/usr/bin/env python3
"""Preparation and bounded execution receipts for the Kani 3300 SEL1 replay.

This file deliberately records observations without assigning proof credit.
Every root stays UNKNOWN until a reviewer binds useful checks and the selected
Check/Original body or intended negative to the generated artifact.
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
import time
from typing import Any


HERE = Path(__file__).resolve().parent
REQUEST = HERE / "CI-REQUEST.json"
SOURCE_BINDING = HERE / "sel1-source-binding.json"
PATCH = HERE / "sel1-test-only.patch"
TOOL_SHA = 'ec85b782a1b7156ad434cfac25403acd4e326dc1'
TOOL_TREE = '0c9e5e67ba0a17128f71af415644f3fad84099d3'
STD_SHA = "70ba5befc617627073738e26cb1466bd4fb76e41"
STD_TREE = "6ea9d3425f6d0478cfc2517cbdd2fb7d7b32a53f"
STD_COMMIT_TREE = "84ab170ccdcc29fba69e55e0a46e6acdf52d9704"
PATCH_SHA = '473526895d6d57a99bd356a060195745cc6aba9ee2b70fcc7ae90fecb6676f06'
REQUEST_SHA = 'c96c9bd955d64ca7d79bf40e589db397c2447a2cb460703544647b1c079ca033'
STD_OVERLAY_SHA = '6075e7ce17179f45642c9ffe8fe09e3ec9395726'
STD_OVERLAY_TREE = '12e87bd4a4e141a8f829d8a0519efc09260c5059'
ROOT_CAP_SECONDS = 2400
INVALID_EXPORT_STATES = {
    "MISSING", "EMPTY", "INVALID_OR_PARTIAL", "NULL", "WRONG_TOP_LEVEL_TYPE",
    "WRONG_SOURCE_OR_SELECTOR", "EXPLICIT_NOT_RUN",
}
PATCHED_FILE_HASHES = {'library/core/src/slice/sort/shared/smallsort/verify.rs': '506644ad92ed4872af19bd1d302b439ff5e1d4dd850e9e9f149d429286065a95',
 'library/core/src/slice/sort/shared/smallsort/verify/helper_contracts.rs': '22de8b24f6adf35b633b2962d9873a349041a18cca9d580944d2d4a3c9ad0655',
 'library/core/src/slice/sort/shared/smallsort/verify/helper_contracts_wide.rs': 'b2d71e6e61b4130a95dda6daac3cd5f0970f9daf7b0f7bfa8a9f99d9c3c29844',
 'library/core/src/slice/sort/shared/smallsort/verify/replay_gateb_prime.rs': 'c585f3d0c74879cb21e8f09204f52d59b7aa4948a2e17541a94e162b3ffb10a1',
 'library/core/src/slice/sort/shared/smallsort/verify/replay_uninit_controls.rs': 'c186a086dadba038ff5ad7ca823e52e1e807758a92b1a46cf4c807fc07d96a39'}
PINNED_RUST_TOOLCHAIN = "nightly-2026-10-23"
EXPECTED_ROWS = {'sort4-closure-on': {'selector': 'slice::sort::shared::smallsort::verify::helper_contracts::sort4_safety_u64',
                      'expected_mode': 'Check(sort4_stable)',
                      'source_unwind': 16,
                      'expected_result': 'SUCCESS',
                      'expected_failed_checks': 0},
 'swap-if-less-closure-on': {'selector': 'slice::sort::shared::smallsort::verify::helper_contracts::swap_safety_u64_backing4',
                             'expected_mode': 'Check(swap_if_less)',
                             'source_unwind': 8,
                             'expected_result': 'SUCCESS',
                             'expected_failed_checks': 0},
 'raw-legal-on': {'selector': 'slice::sort::shared::smallsort::verify::replay_uninit_controls::sort4_raw_all_initialized_u64',
                  'expected_mode': 'Original(sort4_stable)',
                  'source_unwind': 16,
                  'expected_result': 'SUCCESS',
                  'expected_failed_checks': 0},
 'raw-negative-on': {'selector': 'slice::sort::shared::smallsort::verify::replay_uninit_controls::sort4_raw_hole_negative_u64',
                     'expected_mode': 'Original(sort4_stable)',
                     'source_unwind': 16,
                     'expected_result': 'FAILURE',
                     'expected_failed_checks': 1},
 'merge-raw-closure-on': {'selector': 'slice::sort::shared::smallsort::verify::helper_contracts_wide::merge_safety_u64_len8_scratch48_src32_dst0',
                          'expected_mode': 'Check(bidirectional_merge)',
                          'source_unwind': 34,
                          'expected_result': 'SUCCESS',
                          'expected_failed_checks': 0},
 'merge-profile-closure-on': {'selector': 'slice::sort::shared::smallsort::verify::replay_gateb_prime::merge_profile_closure_scratch48_u8_n9',
                              'expected_mode': 'Check(merge_profile_closure_u8)',
                              'source_unwind': 34,
                              'expected_result': 'SUCCESS',
                              'expected_failed_checks': 0}}
EXPECTED_FLAGS = {'assertion_reachability': 'DEFAULT_ON',
 'cfg_controls': True,
 'coverage_requested': False,
 'experimental_valid_value': False,
 'no_assert_contracts': True,
 'object_bits': 12,
 'slicing': 'DEFAULT_ON',
 'solver': 'DEFAULT_CADICAL',
 'standard_checks': 'DEFAULTS_ON'}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def root_exit_code(receipt: dict[str, Any]) -> int:
    """Return the child's positive exit unchanged; never treat malformed exports as success."""
    code = receipt.get("original_exit_code")
    if isinstance(code, int) and code > 0:
        return code
    if (code is None or code < 0 or receipt.get("timed_out") or receipt.get("runner_error") or
            receipt.get("export", {}).get("state") in INVALID_EXPORT_STATES or
            receipt.get("postprocessing_state") != "COMPLETE"):
        return 1
    rss = receipt.get("rss", {})
    if rss.get("status") != "OBSERVED_WAIT4_LINUX_RU_MAXRSS" or not isinstance(rss.get("max_bytes"), int):
        return 1
    validation = receipt.get("post_run_validation", {})
    source = validation.get("tool_source_valid", {})
    if source.get("valid") is False or validation.get("std_test_only_overlay_valid") is False:
        return 1
    return 0


def persist_then_postprocess(path: Path, receipt: dict[str, Any], stage: dict[str, str], postprocess) -> dict[str, Any]:
    """Durably save execution evidence before any fallible receipt enrichment."""
    receipt["postprocessing_state"] = "INCOMPLETE"
    write_json_atomic(path, receipt)
    try:
        receipt.update(postprocess())
        receipt["postprocessing_state"] = "COMPLETE"
    except Exception as e:
        receipt["postprocessing_state"] = "INCOMPLETE"
        receipt["postprocessing_error"] = {"stage": stage["name"], "type": type(e).__name__, "message": str(e)}
    write_json_atomic(path, receipt)
    return receipt


def load_request() -> dict[str, Any]:
    if sha256(REQUEST) != REQUEST_SHA:
        raise ValueError("embedded request SHA-256 mismatch")
    if sha256(PATCH) != PATCH_SHA:
        raise ValueError("embedded test patch SHA-256 mismatch")
    req = json.loads(REQUEST.read_text())
    if req.get("tool_export_sha") != TOOL_SHA or req.get("tool_export_tree") != TOOL_TREE:
        raise ValueError("request does not pin the frozen SEL1 source")
    if req.get("selected_library_tree") != STD_TREE or len(req.get("roots", [])) != 6:
        raise ValueError("request library pin or exact 6-root inventory mismatch")
    expected_ids = set(EXPECTED_ROWS)
    if {r.get("id") for r in req["roots"]} != expected_ids:
        raise ValueError("request row allowlist mismatch")
    if (req.get("authorization") != "PREPARATION_ONLY" or
            req.get("run_budget", {}).get("max_invocations") != 6 or
            req.get("run_budget", {}).get("retry_policy") != "NONE" or
            req.get("run_budget", {}).get("jobs") != 1 or
            req.get("run_budget", {}).get("max_parallel") != 1):
        raise ValueError("request exceeds bounded preparation caps")
    if req.get("test_patch_sha256") != PATCH_SHA:
        raise ValueError("request test patch hash differs from wrapper")
    if req.get("patched_file_sha256") != PATCHED_FILE_HASHES:
        raise ValueError("request patched file hashes differ from wrapper")
    if (req.get("test_overlay_commit") != STD_OVERLAY_SHA or
            req.get("test_only_library_tree") != STD_OVERLAY_TREE):
        raise ValueError("request std overlay identity mismatch")
    for row in req["roots"]:
        expected = EXPECTED_ROWS[row["id"]]
        if any(row.get(key) != value for key, value in expected.items()):
            raise ValueError("request source-stage-target or row oracle mismatch")
        argv = ["<EXACT_SEL1_KANI_BINARY>", "verify-std", "-Z", "unstable-options", "./library",
                "-Z", "function-contracts", "-Z", "mem-predicates", "-Z", "float-lib", "-Z", "c-ffi",
                "-Z", "loop-contracts", "-Z", "quantifiers", "-Z", "stubbing", "-Z", "export-json",
                "-Z", "uninit-checks", "--no-assert-contracts", "--harness", expected["selector"],
                "--exact", "--jobs", "1", "--harness-timeout", "2400s", "--target-dir",
                f"<OUTPUT_ROOT>/{row['id']}/target", "--export-json",
                f"<OUTPUT_ROOT>/{row['id']}/export.json", "--output-format=regular",
                "--cbmc-args", "--object-bits", "12"]
        if (row.get("argv") != argv or row.get("uninit") is not True or
                row.get("environment") != {"NO_COLOR": "1", "RUSTFLAGS": "--cfg kani_smallsort_controls"}):
            raise ValueError("request exact argv/environment mismatch")
    if req.get("flags") != EXPECTED_FLAGS:
        raise ValueError("request checker flags differ from frozen profile")
    flags = req.get("flags", {})
    budget = req.get("run_budget", {})
    if (flags.get("object_bits") != 12 or flags.get("experimental_valid_value") is not False or
            flags.get("cfg_controls") is not True or budget.get("harness_cap_seconds") != ROOT_CAP_SECONDS or
            budget.get("aggregate_job_envelope_seconds") != 21600):
        raise ValueError("request flags or time caps exceed authorized bounds")
    if any(r.get("status") != "NOT_RUN" or r.get("state") != "NOT_RUN" or
           r.get("generated_property_binding") is not None for r in req["roots"]):
        raise ValueError("request must remain NOT_RUN with unbound generated properties")
    return req


def git(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.stdout.strip()


def verify_source(repo: Path) -> dict[str, Any]:
    """Check SEL1 by immutable git object IDs, even when overlay files are present."""
    req = load_request()
    binding = json.loads(SOURCE_BINDING.read_text())
    if binding.get("export_sha") != TOOL_SHA or binding.get("export_tree") != TOOL_TREE:
        raise ValueError("source binding does not identify SEL1")
    if git(repo, "cat-file", "-t", TOOL_SHA) != "commit":
        raise ValueError("frozen SEL1 commit object is unavailable")
    if git(repo, "rev-parse", f"{TOOL_SHA}^{{tree}}") != TOOL_TREE:
        raise ValueError("frozen SEL1 tree mismatch")
    head = git(repo, "rev-parse", "HEAD")
    if head != TOOL_SHA:
        raise ValueError("build source checkout must be the exact frozen SEL1 commit")
    if git(repo, "status", "--porcelain"):
        raise ValueError("frozen SEL1 export checkout must be clean")
    actual_files = {}
    for rel, expected in binding["files"].items():
        # git show is text-safe here but hashes must be over exact bytes.
        data = subprocess.run(["git", "-C", str(repo), "show", f"{TOOL_SHA}:{rel}"],
                              check=True, stdout=subprocess.PIPE).stdout
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            raise ValueError(f"SEL1 bound source mismatch: {rel}")
        actual_files[rel] = digest
    for rel, expected in binding["subtrees"].items():
        if git(repo, "rev-parse", f"{TOOL_SHA}:{rel}") != expected:
            raise ValueError(f"SEL1 bound subtree mismatch: {rel}")
    return {"tool_sha": TOOL_SHA, "tool_tree": TOOL_TREE, "bound_files": len(actual_files),
            "bound_subtrees": len(binding["subtrees"]), "request_sha256": sha256(REQUEST),
            "std_commit": STD_SHA, "std_tree": STD_TREE, "patch_sha256": sha256(PATCH),
            "test_overlay_tree": req["test_only_library_tree"], "proof_status": "NOT_RUN"}


def prepare_std(repo: str, destination: Path) -> dict[str, Any]:
    """Create an isolated std checkout, pin exact base, then apply only test patch."""
    if destination.exists() and any(destination.iterdir()):
        raise ValueError(f"refusing to reuse non-empty std checkout: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        destination.mkdir()
    subprocess.run(["git", "clone", "--no-hardlinks", str(repo), str(destination)], check=True)
    git(destination, "checkout", "--detach", STD_SHA)
    # std needs its submodules (e.g. library/backtrace, library/stdarch) to build.
    subprocess.run(["git", "-C", str(destination), "submodule", "update", "--init", "--depth", "1"], check=True)
    if git(destination, "rev-parse", "HEAD^{tree}") != STD_COMMIT_TREE:
        raise ValueError("selected std snapshot commit tree mismatch")
    if git(destination, "rev-parse", "HEAD:library") != STD_TREE:
        raise ValueError("selected std library subtree mismatch")
    subprocess.run(["git", "-C", str(destination), "apply", "--check", str(PATCH)], check=True)
    subprocess.run(["git", "-C", str(destination), "apply", str(PATCH)], check=True)
    status = subprocess.run(["git", "-C", str(destination), "status", "--porcelain=v1", "-z"],
                            check=True, stdout=subprocess.PIPE).stdout
    changed = [entry[3:].decode() for entry in status.split(b"\0") if entry]
    expected = sorted(PATCHED_FILE_HASHES)
    if sorted(changed) != sorted(expected):
        raise ValueError(f"test overlay changed unexpected std paths: {changed}")
    for rel, digest in PATCHED_FILE_HASHES.items():
        if sha256(destination / rel) != digest:
            raise ValueError(f"patched std source byte mismatch: {rel}")
    return {"base_commit": STD_SHA, "base_commit_tree": STD_COMMIT_TREE,
            "library_tree": STD_TREE, "patch_sha256": sha256(PATCH),
            "changed_paths": sorted(changed), "production_source_changed": False,
            "status": "PREPARED_NOT_RUN"}


def parse_export(path: Path, expected_selector: str) -> dict[str, Any]:
    """Validate the export envelope only; never infer proof or boundary credit."""
    if not path.exists():
        return {"state": "MISSING", "outcome": "UNKNOWN"}
    try:
        raw = path.read_bytes()
        if not raw:
            return {"state": "EMPTY", "outcome": "UNKNOWN"}
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        return {"state": "INVALID_OR_PARTIAL", "error": str(e), "outcome": "UNKNOWN"}
    if value is None:
        return {"state": "NULL", "outcome": "UNKNOWN"}
    if not isinstance(value, dict):
        return {"state": "WRONG_TOP_LEVEL_TYPE", "observed_type": type(value).__name__, "outcome": "UNKNOWN"}
    if any(value.get(key) == "NOT_RUN" for key in ("result", "status", "runtime_proof_status")):
        return {"state": "EXPLICIT_NOT_RUN", "outcome": "UNKNOWN"}
    # Export schema and harness identity vary across supported Kani builds.
    # A missing or mismatched recognizable identity is a gap, never a pass.
    selectors = []
    for key in ("harness", "selector", "function", "name"):
        v = value.get(key)
        if isinstance(v, str):
            selectors.append(v)
    if selectors and expected_selector not in selectors:
        return {"state": "WRONG_SOURCE_OR_SELECTOR", "observed": selectors, "outcome": "UNKNOWN"}
    return {"state": "UNVALIDATED_JSON_OBJECT", "selector_identity": selectors or None,
            "outcome": "UNKNOWN", "generated_property_binding": None,
            "review_required": ["selected Check body", "useful reached checks/ensures and covers",
                                "complete artifact coverage; no proof credit from this envelope parse"] +
                               (["sort4 expected SUCCESS:0 failed checks, useful comparator/frame/readbacks/return reached"]
                                if expected_selector.endswith("helper_contracts::sort4_safety_u64") else [])}


def execute(argv: list[str], cwd: Path, env: dict[str, str], out: Path,
            timeout_seconds: float = ROOT_CAP_SECONDS) -> dict[str, Any]:
    """Run one exact child argv and retain its exit, signal, timeout and wait4 RSS."""
    started = time.time()
    result: dict[str, Any] = {"started_unix": started, "original_exit_code": None,
                              "timed_out": False, "runner_error": None, "signal": None,
                              "rss_max_bytes": None, "rss_status": "UNKNOWN"}

    def wait4_until(pid: int, deadline: float):
        while True:
            try:
                got, status, usage = os.wait4(pid, os.WNOHANG)
            except InterruptedError:
                continue
            if got == pid:
                return status, usage
            if time.monotonic() >= deadline:
                return None
            time.sleep(min(0.05, max(0.001, deadline - time.monotonic())))

    try:
        with (out / "stdout.log").open("wb") as stdout, (out / "stderr.log").open("wb") as stderr:
            p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                 start_new_session=True)
            waited = wait4_until(p.pid, time.monotonic() + timeout_seconds)
            if waited is None:
                result["timed_out"] = True
                result["runner_error"] = f"{timeout_seconds:g} second cap elapsed; process group terminated"
                os.killpg(p.pid, signal.SIGTERM)
                waited = wait4_until(p.pid, time.monotonic() + 5)
                if waited is None:
                    os.killpg(p.pid, signal.SIGKILL)
                    while True:
                        try:
                            _, status, usage = os.wait4(p.pid, 0)
                            break
                        except InterruptedError:
                            continue
                    waited = (status, usage)
            status, usage = waited
            code = os.waitstatus_to_exitcode(status)
            p.returncode = code
            result["original_exit_code"] = code
            result["rss_max_bytes"] = int(usage.ru_maxrss * 1024)
            result["rss_status"] = "OBSERVED_WAIT4_LINUX_RU_MAXRSS"
            if code < 0:
                result["signal"] = -code
    except OSError as e:
        result["runner_error"] = f"runner_exec_or_wait_error: {e}"
    except subprocess.SubprocessError as e:
        result["runner_error"] = f"runner_subprocess_error: {e}"
    result["elapsed_seconds"] = round(time.time() - started, 3)
    for name in ("stdout.log", "stderr.log"):
        pth = out / name
        result[name.replace(".log", "_sha256")] = sha256(pth) if pth.exists() else None
        result[name.replace(".log", "_bytes")] = pth.stat().st_size if pth.exists() else 0
    return result


def runtime_inventory(repo: Path, binary: Path) -> dict[str, Any]:
    """Capture build/runtime identities without assigning model or proof credit."""
    def command_version(argv: list[str]) -> dict[str, Any]:
        try:
            p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               text=True, timeout=15, check=False)
            return {"argv": argv, "exit_code": p.returncode, "output": p.stdout[:4096]}
        except (OSError, subprocess.SubprocessError) as e:
            return {"argv": argv, "error": str(e)}

    def identity(path: Path | None) -> dict[str, Any]:
        if path is None or not path.is_file():
            return {"path": str(path) if path else None, "available": False}
        return {"path": str(path), "available": True, "sha256": sha256(path), "bytes": path.stat().st_size}

    driver = repo / "target/kani/bin/kani-driver"
    tool_identities = {}
    for name in ("cbmc", "kissat"):
        found = shutil.which(name)
        tool_identities[name] = {"binary": identity(Path(found) if found else None),
                                 "version": command_version([found, "--version"]) if found else None}
    try:
        rustc_path = subprocess.run(["rustup", "which", "--toolchain", PINNED_RUST_TOOLCHAIN, "rustc"],
                                    check=True, stdout=subprocess.PIPE, text=True, timeout=15).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        rustc_path = None
    tool_identities["rustc"] = {"binary": identity(Path(rustc_path) if rustc_path else None),
                                 "version": command_version([rustc_path, "--version", "--verbose"]) if rustc_path else None,
                                 "toolchain": PINNED_RUST_TOOLCHAIN}
    kani_tree = repo / "target/kani"
    kani_files = {}
    total_bytes = 0
    if kani_tree.is_dir():
        for p in sorted(kani_tree.rglob("*")):
            if p.is_file():
                rel = p.relative_to(repo).as_posix()
                kani_files[rel] = sha256(p)
                total_bytes += p.stat().st_size
    return {
        "kani_wrapper": command_version([str(binary), "--version"]),
        "kani_driver": identity(driver),
        "dependencies_manifest": identity(repo / "kani-dependencies"),
        "rust_toolchain_manifest": identity(repo / "rust-toolchain.toml"),
        "tools": tool_identities,
        "target_kani_file_hashes": kani_files,
        "target_kani_file_count": len(kani_files),
        "target_kani_total_bytes": total_bytes,
        "target_kani_directory_available": kani_tree.is_dir()
    }


def run_root(repo: Path, std: Path, root_id: str, binary: Path, out: Path) -> dict[str, Any]:
    req = load_request()
    row = next((r for r in req["roots"] if r["id"] == root_id), None)
    if row is None:
        raise ValueError(f"root is not one of the exact request rows: {root_id}")
    source_identity = verify_source(repo)
    if (git(std, "rev-parse", "HEAD") != STD_SHA or
            git(std, "rev-parse", "HEAD:library") != STD_TREE):
        raise ValueError("std checkout is not the selected base commit")
    status = subprocess.run(["git", "-C", str(std), "status", "--porcelain=v1", "-z"],
                            check=True, stdout=subprocess.PIPE).stdout
    changed_paths = [entry[3:].decode() for entry in status.split(b"\0") if entry]
    expected_paths = sorted(PATCHED_FILE_HASHES)
    if sorted(changed_paths) != sorted(expected_paths):
        raise ValueError(f"std checkout must contain only the exact test-only overlay paths: {changed_paths}")
    std_file_hashes = {rel: sha256(std / rel) for rel in expected_paths}
    if std_file_hashes != PATCHED_FILE_HASHES:
        raise ValueError("std checkout patched source bytes do not match the embedded exact test overlay")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("exact built Kani executable is missing or not executable")
    out.mkdir(parents=True, exist_ok=False)
    argv = [str(binary) if x == "<EXACT_SEL1_KANI_BINARY>" else x for x in row["argv"]]
    argv = [x.replace("<OUTPUT_ROOT>", str(out.parent)) for x in argv]
    env = os.environ.copy()
    env.update(row["environment"])
    execution = execute(argv, std, env, out)
    export = out / "export.json"
    receipt = {
        "schema": "kani3300-sel1-replay-receipt-v1", "root_id": root_id,
        "request_sha256": sha256(REQUEST), "tool_sha": TOOL_SHA, "tool_tree": TOOL_TREE,
        "source_identity": source_identity,
        "std_base_commit": STD_SHA, "std_base_commit_tree": STD_COMMIT_TREE,
        "std_library_tree": STD_TREE, "test_patch_sha256": sha256(PATCH),
        "argv": argv, "environment": {k: env.get(k) for k in row["environment"]},
        "expected_result": row["expected_result"], "expected_mode": row["expected_mode"],
        "expected_failed_checks": row["expected_failed_checks"], "oracle": row["oracle"],
        "source_unwind": row["source_unwind"], "test_overlay_source_commit": STD_OVERLAY_SHA,
        "expected_test_overlay_library_tree": STD_OVERLAY_TREE,
        "rss": {"max_bytes": execution.pop("rss_max_bytes"),
                "status": execution.pop("rss_status")},
        **execution,
        "export": {"state": "PENDING_PARSE", "outcome": "UNKNOWN"},
        "runtime_identity_file": "runtime-identities.json",
        "outcome": "UNKNOWN", "generated_property_binding": None,
        "runtime_proof_status": "NOT_RUN_UNTIL_REVIEWED",
        "postprocessing_state": "INCOMPLETE",
    }
    receipt_path = out / "receipt.json"
    stage = {"name": "export-parse"}

    def postprocess():
        receipt["export"] = parse_export(export, row["selector"])
        stage["name"] = "runtime-inventory"
        runtime = runtime_inventory(repo, binary)
        write_json_atomic(out / "runtime-identities.json", runtime)
        stage["name"] = "post-run-source-validation"
        try:
            post_source = verify_source(repo)
            post_source_state = {"valid": True, "identity": post_source}
        except (OSError, ValueError, subprocess.CalledProcessError) as e:
            post_source_state = {"valid": False, "error": str(e)}
        stage["name"] = "post-run-std-validation"
        post_std_status = subprocess.run(["git", "-C", str(std), "status", "--porcelain=v1", "-z"],
                                         check=True, stdout=subprocess.PIPE).stdout
        post_std_paths = [entry[3:].decode() for entry in post_std_status.split(b"\0") if entry]
        post_std_hashes = {rel: sha256(std / rel) for rel in expected_paths if (std / rel).is_file()}
        post_std_valid = sorted(post_std_paths) == sorted(expected_paths) and post_std_hashes == PATCHED_FILE_HASHES
        return {
            "export": receipt["export"],
            "post_run_validation": {
                "tool_source_valid": post_source_state,
                "std_overlay_paths": sorted(post_std_paths),
                "std_overlay_sha256": post_std_hashes,
                "std_test_only_overlay_valid": post_std_valid,
            },
            "runtime_identity_file": "runtime-identities.json",
        }

    persist_then_postprocess(receipt_path, receipt, stage, postprocess)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify-source"); v.add_argument("--repo", type=Path, default=Path.cwd())
    p = sub.add_parser("prepare-std"); p.add_argument("--repo", type=str, required=True); p.add_argument("--destination", type=Path, required=True)
    r = sub.add_parser("run-root"); r.add_argument("--repo", type=Path, required=True); r.add_argument("--std", type=Path, required=True); r.add_argument("--root", required=True); r.add_argument("--binary", type=Path, required=True); r.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "verify-source": result = verify_source(args.repo)
        elif args.command == "prepare-std": result = prepare_std(args.repo, args.destination)
        else:
            result = run_root(args.repo, args.std, args.root, args.binary, args.out)
            print(json.dumps(result, indent=2, sort_keys=True))
            return root_exit_code(result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError, json.JSONDecodeError) as e:
        print(f"replay preparation/execution error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
