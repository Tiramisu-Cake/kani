#!/usr/bin/env python3
"""Preparation and bounded execution receipts for the Kani 3300 replay.

This file deliberately records observations without assigning proof credit.
Every root stays UNKNOWN until a reviewer binds the useful checks and selected
Check body (or the intended negative read) to the generated artifact.
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
REQUEST = HERE / "request.json"
SOURCE_BINDING = HERE / "c1-source-binding.json"
PATCH = HERE / "replay-test-only.patch"
C1_SHA = "1658f4cadfa83139e41180ce3865e23f79d889aa"
C1_TREE = "bfb5eb9db13ffb91ec4585b7c7ef41ddfe0008fb"
STD_SHA = "70ba5befc617627073738e26cb1466bd4fb76e41"
STD_TREE = "6ea9d3425f6d0478cfc2517cbdd2fb7d7b32a53f"
STD_COMMIT_TREE = "84ab170ccdcc29fba69e55e0a46e6acdf52d9704"
PATCH_SHA = "f2689c76720e95f98a88bdd17a2bf4cf13a7348d40dedcf9c009aa0b20db0df5"
REQUEST_SHA = "9c0524996be2491fbb1a4ef5bb2faee9d5651cadda9053604e6cd21cb1aa38ad"
ROOT_CAP_SECONDS = 2400
INVALID_EXPORT_STATES = {
    "MISSING", "EMPTY", "INVALID_OR_PARTIAL", "NULL", "WRONG_TOP_LEVEL_TYPE",
    "WRONG_SOURCE_OR_SELECTOR",
}
PATCHED_FILE_HASHES = {
    "library/core/src/slice/sort/shared/smallsort/verify.rs": "3a8aa452408f3048c80a73dde8a4fd28f4a3b647b0a171512e186c93f99c4c33",
    "library/core/src/slice/sort/shared/smallsort/verify/replay_uninit_controls.rs": "c186a086dadba038ff5ad7ca823e52e1e807758a92b1a46cf4c807fc07d96a39",
}
PINNED_RUST_TOOLCHAIN = "nightly-2026-10-23"


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
    validation = receipt.get("post_run_validation", {})
    source = validation.get("c1_source_valid", {})
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
    if req.get("tool_export_sha") != C1_SHA or req.get("tool_export_tree") != C1_TREE:
        raise ValueError("request does not pin the frozen C1 source")
    if req.get("selected_library_tree") != STD_TREE or len(req.get("roots", [])) != 12:
        raise ValueError("request library pin or exact 12-root inventory mismatch")
    if any(r.get("status") != "NOT_RUN" or r.get("generated_property_binding") is not None for r in req["roots"]):
        raise ValueError("request must remain NOT_RUN with unbound generated properties")
    return req


def git(repo: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(repo), *args], check=True, text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.stdout.strip()


def verify_source(repo: Path) -> dict[str, Any]:
    """Check C1 by immutable git object IDs, even when overlay files are present."""
    req = load_request()
    binding = json.loads(SOURCE_BINDING.read_text())
    if binding.get("export_sha") != C1_SHA or binding.get("export_tree") != C1_TREE:
        raise ValueError("source binding does not identify C1")
    if git(repo, "cat-file", "-t", C1_SHA) != "commit":
        raise ValueError("frozen C1 commit object is unavailable")
    if git(repo, "rev-parse", f"{C1_SHA}^{{tree}}") != C1_TREE:
        raise ValueError("frozen C1 tree mismatch")
    head = git(repo, "rev-parse", "HEAD")
    if head != C1_SHA:
        raise ValueError("build source checkout must be the exact frozen C1 commit")
    if git(repo, "status", "--porcelain"):
        raise ValueError("frozen C1 export checkout must be clean")
    actual_files = {}
    for rel, expected in binding["files"].items():
        # git show is text-safe here but hashes must be over exact bytes.
        data = subprocess.run(["git", "-C", str(repo), "show", f"{C1_SHA}:{rel}"],
                              check=True, stdout=subprocess.PIPE).stdout
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected:
            raise ValueError(f"C1 bound source mismatch: {rel}")
        actual_files[rel] = digest
    for rel, expected in binding["subtrees"].items():
        if git(repo, "rev-parse", f"{C1_SHA}:{rel}") != expected:
            raise ValueError(f"C1 bound subtree mismatch: {rel}")
    return {"c1_sha": C1_SHA, "c1_tree": C1_TREE, "bound_files": len(actual_files),
            "bound_subtrees": len(binding["subtrees"]), "request_sha256": sha256(REQUEST),
            "std_commit": STD_SHA, "std_tree": STD_TREE, "patch_sha256": sha256(PATCH),
            "proof_status": "NOT_RUN"}


def prepare_std(repo: str, destination: Path) -> dict[str, Any]:
    """Create an isolated std checkout, pin exact base, then apply only test patch."""
    if destination.exists() and any(destination.iterdir()):
        raise ValueError(f"refusing to reuse non-empty std checkout: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        destination.mkdir()
    subprocess.run(["git", "clone", "--no-hardlinks", str(repo), str(destination)], check=True)
    git(destination, "checkout", "--detach", STD_SHA)
    if git(destination, "rev-parse", "HEAD^{tree}") != STD_COMMIT_TREE:
        raise ValueError("selected std snapshot commit tree mismatch")
    if git(destination, "rev-parse", "HEAD:library") != STD_TREE:
        raise ValueError("selected std library subtree mismatch")
    subprocess.run(["git", "-C", str(destination), "apply", "--check", str(PATCH)], check=True)
    subprocess.run(["git", "-C", str(destination), "apply", str(PATCH)], check=True)
    status = subprocess.run(["git", "-C", str(destination), "status", "--porcelain=v1", "-z"],
                            check=True, stdout=subprocess.PIPE).stdout
    changed = [entry[3:].decode() for entry in status.split(b"\0") if entry]
    expected = ["library/core/src/slice/sort/shared/smallsort/verify.rs",
                "library/core/src/slice/sort/shared/smallsort/verify/replay_uninit_controls.rs"]
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
    """Validate export envelope only; never infer success or intended-failure credit."""
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
            "review_required": ["selected Check body", "useful checks/ensures and covers",
                                "negative intended source[1] read, where applicable"]}


def execute(argv: list[str], cwd: Path, env: dict[str, str], out: Path,
            timeout_seconds: float = ROOT_CAP_SECONDS) -> dict[str, Any]:
    """Run one exact command while retaining exit, timeout, and signal evidence."""
    started = time.time()
    result: dict[str, Any] = {"started_unix": started, "original_exit_code": None,
                              "timed_out": False, "runner_error": None, "signal": None}
    try:
        with (out / "stdout.log").open("wb") as stdout, (out / "stderr.log").open("wb") as stderr:
            p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr,
                                 start_new_session=True)
            try:
                code = p.wait(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                result["timed_out"] = True
                result["runner_error"] = f"{timeout_seconds:g} second cap elapsed; process group terminated"
                os.killpg(p.pid, signal.SIGTERM)
                try:
                    code = p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    code = p.wait()
            result["original_exit_code"] = code
            if code < 0:
                result["signal"] = -code
    except OSError as e:
        result["runner_error"] = f"runner_exec_error: {e}"
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
    expected_paths = ["library/core/src/slice/sort/shared/smallsort/verify.rs",
                      "library/core/src/slice/sort/shared/smallsort/verify/replay_uninit_controls.rs"]
    if sorted(changed_paths) != sorted(expected_paths):
        raise ValueError(f"std checkout must contain only the exact test-only overlay paths: {changed_paths}")
    std_file_hashes = {rel: sha256(std / rel) for rel in expected_paths}
    if std_file_hashes != PATCHED_FILE_HASHES:
        raise ValueError("std checkout patched source bytes do not match the embedded exact test overlay")
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("exact built Kani executable is missing or not executable")
    out.mkdir(parents=True, exist_ok=False)
    argv = [str(binary) if x == "<EXACT_C1_KANI_BINARY>" else x for x in row["argv"]]
    argv = [x.replace("<OUTPUT_ROOT>", str(out.parent)) for x in argv]
    env = os.environ.copy()
    env.update(row["environment"])
    execution = execute(argv, std, env, out)
    export = out / "export.json"
    receipt = {
        "schema": "kani3300-replay-receipt-v1", "root_id": root_id,
        "request_sha256": sha256(REQUEST), "c1_sha": C1_SHA, "c1_tree": C1_TREE,
        "source_identity": source_identity,
        "std_base_commit": STD_SHA, "std_base_commit_tree": STD_COMMIT_TREE,
        "std_library_tree": STD_TREE, "test_patch_sha256": sha256(PATCH),
        "argv": argv, "environment": {k: env.get(k) for k in row["environment"]},
        "expected_result": row["expected_result"], "expected_mode": row["expected_mode"],
        **execution,
        "export": {"state": "PENDING_PARSE", "outcome": "UNKNOWN"},
        "runtime_identity_file": "runtime-identities.json",
        "outcome": "UNKNOWN", "generated_property_binding": None,
        "runtime_proof_status": "NOT_RUN_UNTIL_REVIEWED",
        "negative_observation": ("REVIEW_REQUIRED" if root_id.startswith("raw-negative") else None),
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
                "c1_source_valid": post_source_state,
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
