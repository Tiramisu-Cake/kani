#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Portable lifecycle and source-integrity helpers for the Kani C2 Gate A CI overlay."""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import platform
import selectors
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

SCHEMA = "kani3300-gatea-lifecycle-v1"
EXPECTED_ROWS = ("ubuntu-24.04", "ubuntu-24.04-arm", "macos-15")
JOB_SECONDS = 360 * 60
RESERVE_SECONDS = 600
REGRESSION_CAP_SECONDS = 20400
METADATA_CAP_BYTES = 16 * 1024 * 1024
PACKAGE_CAP_BYTES = 384 * 1024 * 1024
RUNTIME_INVENTORY_CAP_BYTES = 32 * 1024 * 1024 * 1024
RUNTIME_FILE_CAP_BYTES = 16 * 1024 * 1024 * 1024
DIFF_CAP_BYTES = 1024 * 1024
HASH_CHUNK = 1024 * 1024
ENV_ALLOWLIST = (
    "GITHUB_SHA", "GITHUB_REF", "GITHUB_REF_NAME", "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_WORKFLOW",
    "GITHUB_REPOSITORY", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion",
    "RUNNER_NAME",
)


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _json_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _load(path: Path) -> Any:
    with path.open("rb") as f:
        raw = f.read(METADATA_CAP_BYTES + 1)
    if len(raw) > METADATA_CAP_BYTES:
        raise ValueError("metadata input exceeds 16 MiB")
    return json.loads(raw.decode("utf-8"))


def _write(path: Path, obj: Any) -> None:
    data = _json_bytes(obj)
    if len(data) > METADATA_CAP_BYTES:
        raise ValueError("metadata output exceeds 16 MiB")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with tmp.open("wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(str(tmp), str(path))


def _terminate_process_group(proc: subprocess.Popen, grace_seconds: float = 0.5) -> None:
    """TERM then KILL the original process group, even if its leader has exited."""
    if os.name != "posix":
        if proc.poll() is None:
            try:
                proc.terminate()
            except OSError:
                pass
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except OSError:
        pass
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        try:
            os.killpg(proc.pid, 0)
        except ProcessLookupError:
            return
        except OSError:
            break
        time.sleep(0.02)
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass


def _bounded_process(argv: List[str], cap: int = DIFF_CAP_BYTES, timeout: Optional[float] = 15) -> Tuple[bytes, bytes, int, bool]:
    """Capture bounded output and terminate the process group if it exceeds cap or deadline."""
    kwargs: Dict[str, Any] = {"stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
    if os.name == "posix":
        kwargs["start_new_session"] = True
    proc = subprocess.Popen(argv, **kwargs)
    assert proc.stdout is not None and proc.stderr is not None
    for pipe in (proc.stdout, proc.stderr):
        os.set_blocking(pipe.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ, "out")
    selector.register(proc.stderr, selectors.EVENT_READ, "err")
    chunks = {"out": bytearray(), "err": bytearray()}
    truncated = False
    deadline = time.monotonic() + timeout if timeout is not None else None
    try:
        while selector.get_map():
            if deadline is not None and time.monotonic() > deadline:
                truncated = True
                break
            for key, _ in selector.select(0.1):
                try:
                    block = os.read(key.fileobj.fileno(), 65536)
                except OSError:
                    block = b""
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                target = chunks[key.data]
                remaining = max(0, cap + 1 - len(target))
                target.extend(block[:remaining])
                if len(target) > cap or sum(len(v) for v in chunks.values()) > cap:
                    truncated = True
                    break
            if truncated:
                break
    except BaseException:
        _terminate_process_group(proc)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        selector.close()
        proc.stdout.close()
        proc.stderr.close()
        raise
    if truncated:
        _terminate_process_group(proc)
    try:
        proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        truncated = True
    selector.close()
    proc.stdout.close()
    proc.stderr.close()
    return bytes(chunks["out"][:cap]), bytes(chunks["err"][:cap]), int(proc.returncode or 0), truncated


def _run_git(root: Path, *args: str, cap: int = DIFF_CAP_BYTES) -> str:
    out, err, code, truncated = _bounded_process(["git", "-C", str(root)] + list(args), cap=cap)
    if truncated:
        raise RuntimeError("git %s output exceeded bounded capture" % " ".join(args))
    if code:
        raise RuntimeError("git %s failed: %s" % (" ".join(args), err.decode("utf-8", "replace")[:2000]))
    return out.decode("utf-8", "replace").strip()


def _identity(root: Path) -> Dict[str, Any]:
    head = _run_git(root, "rev-parse", "HEAD")
    tree = _run_git(root, "rev-parse", "HEAD^{tree}")
    status, err, code, truncated = _bounded_process(["git", "-C", str(root), "status", "--porcelain=v1", "--untracked-files=all"], cap=DIFF_CAP_BYTES)
    status_text = status.decode("utf-8", "replace")
    lines = status_text.splitlines()
    return {"head": head, "tree": tree, "clean": code == 0 and not truncated and not bool(status_text),
            "status": lines[:10000], "status_truncated": truncated or len(lines) > 10000}


def _expected_map(binding: Dict[str, Any], key: str) -> Dict[str, str]:
    value = binding.get(key, {})
    if not isinstance(value, dict):
        raise ValueError("binding.%s must be an object" % key)
    result = {}
    for name, expected in value.items():
        if isinstance(expected, dict):
            expected = expected.get("sha256") or expected.get("hash") or expected.get("oid")
        if not isinstance(name, str) or not isinstance(expected, str):
            raise ValueError("binding.%s entries must map paths to hash strings" % key)
        result[name] = expected
    return result


def _sha256(path: Path, max_bytes: int = 1024 * 1024 * 1024) -> Tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while True:
            block = f.read(HASH_CHUNK)
            if not block:
                break
            size += len(block)
            if size > max_bytes:
                raise ValueError("file exceeds bounded hash size: %s" % path)
            h.update(block)
    return h.hexdigest(), size


def _gitlink_index(root: Path, rel: str) -> Optional[str]:
    out = _run_git(root, "ls-files", "-s", "--", rel)
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[0] == "160000" and fields[2] == "0":
            return fields[1]
    return None


def _check_source(root: Path, binding: Dict[str, Any], phase: str) -> Dict[str, Any]:
    ident = _identity(root)
    mismatches: List[str] = []
    if not ident["clean"]:
        mismatches.append("source worktree/index is not clean (includes untracked files)")
    expected_sha = binding.get("export_sha")
    expected_tree = binding.get("export_tree")
    if ident["head"] != expected_sha:
        mismatches.append("HEAD expected %s got %s" % (expected_sha, ident["head"]))
    if ident["tree"] != expected_tree:
        mismatches.append("tree expected %s got %s" % (expected_tree, ident["tree"]))
    file_results: Dict[str, Any] = {}
    for rel, expected in _expected_map(binding, "files").items():
        path = root / rel
        if not path.is_file():
            file_results[rel] = {"expected": expected, "actual": None, "ok": False}
            mismatches.append("missing bound file %s" % rel)
            continue
        actual, size = _sha256(path)
        ok = actual.lower() == expected.lower()
        file_results[rel] = {"expected": expected, "actual": actual, "bytes": size, "ok": ok}
        if not ok:
            mismatches.append("file hash mismatch %s" % rel)
    subtree_results: Dict[str, Any] = {}
    for rel, expected in _expected_map(binding, "subtrees").items():
        try:
            actual = _run_git(root, "rev-parse", "HEAD:" + rel)
        except RuntimeError:
            actual = None
        ok = actual is not None and actual.lower() == expected.lower()
        subtree_results[rel] = {"expected": expected, "actual": actual, "ok": ok}
        if not ok:
            mismatches.append("subtree identity mismatch %s" % rel)
    submodule_results: Dict[str, Any] = {}
    for rel, expected in _expected_map(binding, "submodule_pins").items():
        indexed = _gitlink_index(root, rel)
        initialized = False
        try:
            top = subprocess.run(["git", "-C", str(root / rel), "rev-parse", "--show-toplevel"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                                 timeout=5).stdout.decode().strip()
            initialized = Path(top).resolve() == (root / rel).resolve()
        except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired):
            pass
        actual = indexed
        if phase != "pre-setup" and initialized:
            try:
                actual = subprocess.run(["git", "-C", str(root / rel), "rev-parse", "HEAD"], stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, check=True).stdout.decode().strip()
            except (subprocess.CalledProcessError, OSError):
                actual = None
        if phase != "pre-setup" and not initialized:
            actual = None
        ok = actual is not None and actual.lower() == expected.lower()
        submodule_results[rel] = {"expected": expected, "index": indexed, "actual": actual,
                                  "initialized": initialized, "ok": ok}
        if not ok:
            mismatches.append("submodule pin mismatch %s" % rel)
    symlink_results: Dict[str, Any] = {}
    symlinks = binding.get("symlinks", {})
    if not isinstance(symlinks, dict):
        raise ValueError("binding.symlinks must be an object")
    for rel, expected_target in symlinks.items():
        path = root / rel
        try:
            actual_target = os.readlink(str(path))
        except OSError:
            actual_target = None
        ok = actual_target == expected_target
        symlink_results[rel] = {"expected": expected_target, "actual": actual_target, "ok": ok}
        if not ok:
            mismatches.append("symlink target mismatch %s" % rel)
    diff, diff_err, diff_code, diff_truncated = _bounded_process(
        ["git", "-C", str(root), "diff", "--no-ext-diff", "--binary", "HEAD"], cap=DIFF_CAP_BYTES)
    if diff_code != 0:
        mismatches.append("git diff failed: %s" % diff_err.decode("utf-8", "replace")[:512])
    if diff_truncated:
        mismatches.append("source diff capture exceeded 1 MiB")
    untracked: List[Dict[str, Any]] = []
    for entry in ident["status"]:
        if entry.startswith("?? "):
            rel = entry[3:]
            try:
                digest, size = _sha256(root / rel, max_bytes=32 * 1024 * 1024)
                untracked.append({"path": rel, "sha256": digest, "bytes": size})
            except Exception as e:
                untracked.append({"path": rel, "sha256": "UNKNOWN", "error": str(e)[:256]})
            if len(untracked) >= 10000:
                break
    return {"phase": phase, "timestamp_utc": utc_now(), **ident,
            "file_hashes": file_results, "subtrees": subtree_results,
            "submodule_pins": submodule_results, "symlinks": symlink_results,
            "diff": diff.decode("utf-8", "replace"), "diff_bytes": len(diff),
            "diff_truncated": diff_truncated, "untracked": untracked, "ok": not mismatches,
            "mismatches": mismatches}


def _platform_metadata(row: str, runner_image: Optional[str]) -> Dict[str, Any]:
    uname = platform.uname()
    ram = None
    try:
        if hasattr(os, "sysconf"):
            ram = int(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
    except (ValueError, OSError, AttributeError):
        pass
    if ram is None and platform.system() == "Darwin":
        try:
            p = subprocess.run(["sysctl", "-n", "hw.memsize"], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=3, check=True)
            ram = int(p.stdout.strip())
        except Exception:
            pass
    disk = None
    try:
        usage = shutil.disk_usage(os.getcwd())
        disk = {"total_bytes": usage.total, "free_bytes": usage.free}
    except OSError:
        pass
    return {"matrix_os": row, "runner_name": os.environ.get("RUNNER_NAME", "UNKNOWN"),
            "runner_os": os.environ.get("RUNNER_OS", platform.system()),
            "runner_arch": os.environ.get("RUNNER_ARCH", platform.machine()), "platform": platform.platform(),
            "system": uname.system, "release": uname.release, "version": uname.version,
            "machine": uname.machine, "processor": platform.processor() or "UNKNOWN",
            "host_triple": os.environ.get("HOST", "UNKNOWN"), "ram_bytes": ram if ram is not None else "UNKNOWN",
            "disk": disk if disk is not None else "UNKNOWN", "image": runner_image or
            os.environ.get("ImageOS", "UNKNOWN"), "image_version": os.environ.get("ImageVersion", "UNKNOWN")}


def command_init(args: argparse.Namespace) -> int:
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    started = float(args.started_epoch) if args.started_epoch is not None else time.time()
    overlay = args.overlay_sha or os.environ.get("GITHUB_SHA", "UNKNOWN")
    run_id = args.run_id or os.environ.get("GITHUB_RUN_ID", "UNKNOWN")
    attempt = str(args.run_attempt or os.environ.get("GITHUB_RUN_ATTEMPT", "1"))
    prohibited = [k for k in ("RUSTFLAGS", "KANI_FLAGS", "CBMC_FLAGS", "EXTRA_X_PY_BUILD_ARGS", "BASH_ENV")
                  if os.environ.get(k)]
    if "RUST_TEST_THREADS" in os.environ:
        prohibited.append("RUST_TEST_THREADS")
    state = {"schema": SCHEMA, "initialized_utc": utc_now(), "job_started_epoch": started,
             "platform": _platform_metadata(args.platform, args.runner_image),
             "identities": {"run_id": run_id, "run_attempt": attempt,
                            "job_id": args.job_id or os.environ.get("GITHUB_JOB", "UNKNOWN"),
                            "overlay_sha": overlay, "export_sha": "UNKNOWN", "export_tree": "UNKNOWN"},
             "allowlisted_environment": {key: os.environ[key] for key in ENV_ALLOWLIST if key in os.environ},
             "statuses": {"setup": "NOT_RUN", "preflight": "NOT_RUN", "observer": "NOT_RUN", "regression": "NOT_RUN"},
             "source_checks": [], "problems": []}
    if attempt != "1":
        state["problems"].append("run attempt must be 1; got %s" % attempt)
    if overlay != "UNKNOWN":
        try:
            control_head = _run_git(Path.cwd(), "rev-parse", "HEAD")
            state["identities"]["control_head"] = control_head
            if control_head != overlay:
                state["problems"].append("control checkout HEAD differs from GITHUB_SHA")
        except Exception as e:
            state["problems"].append("cannot verify control checkout SHA: %s" % str(e)[:512])
    if prohibited:
        state["problems"].append("unexpected external overrides set: %s" % ", ".join(prohibited))
    try:
        binding = _load(Path(args.binding))
        state["identities"]["export_sha"] = binding.get("export_sha", "UNKNOWN")
        state["identities"]["export_tree"] = binding.get("export_tree", "UNKNOWN")
        state["binding"] = str(Path(args.binding).resolve())
    except Exception as e:
        state["problems"].append("binding unavailable: %s" % e)
    _write(output / "lifecycle.json", state)
    print(json.dumps({"lifecycle": str(output / "lifecycle.json"), "job_started_epoch": started,
                      "overlay_sha": overlay, "export_sha": state["identities"]["export_sha"]}))
    return 2 if state["problems"] else 0


def command_check(args: argparse.Namespace) -> int:
    root = Path(args.source_dir).resolve()
    state_path = Path(args.output) / "lifecycle.json"
    state = _load(state_path)
    binding = _load(Path(args.binding))
    check = _check_source(root, binding, args.phase)
    state.setdefault("source_checks", []).append(check)
    if len(state["source_checks"]) > 8:
        state["source_checks"] = state["source_checks"][-8:]
    state["source_root"] = str(root)
    state["source_identity_ok"] = all(c.get("ok") for c in state["source_checks"])
    _write(state_path, state)
    print(json.dumps(check, sort_keys=True))
    return 0 if check["ok"] else 2


def command_budget(args: argparse.Namespace) -> int:
    state = _load(Path(args.output) / "lifecycle.json")
    now = float(args.now_epoch) if args.now_epoch is not None else time.time()
    elapsed = max(0, int(now - float(state["job_started_epoch"])))
    remaining = JOB_SECONDS - elapsed - RESERVE_SECONDS
    allowed = max(0, min(REGRESSION_CAP_SECONDS, remaining))
    obj = {"job_seconds": JOB_SECONDS, "elapsed_seconds": elapsed, "reserve_seconds": RESERVE_SECONDS,
            "regression_cap_seconds": REGRESSION_CAP_SECONDS, "allowed_seconds": allowed,
            "run": allowed > 0, "status": "READY" if allowed > 0 else "INCOMPLETE_NO_BUDGET"}
    state["budget"] = obj
    _write(Path(args.output) / "lifecycle.json", state)
    print(allowed)
    return 0 if allowed > 0 else 3


def _inventory_one(name: str, executable: Optional[str]) -> Dict[str, Any]:
    if not executable:
        return {"path": "UNKNOWN", "sha256": "UNKNOWN", "bytes": "UNKNOWN", "version": "UNKNOWN"}
    path = Path(executable).resolve()
    if not path.is_file():
        return {"path": str(path), "sha256": "UNKNOWN", "bytes": "UNKNOWN", "version": "UNKNOWN"}
    try:
        sha, size = _sha256(path)
    except Exception:
        sha, size = "UNKNOWN", "UNKNOWN"
    version = _version(str(path), ["--version"])
    return {"path": str(path), "sha256": sha, "bytes": size, "version": version}


def _version(path: str, args: List[str]) -> Any:
    try:
        out, err, code, truncated = _bounded_process([path] + args, cap=8192, timeout=8)
        if truncated or code != 0:
            return "UNKNOWN (version output/deadline cap)"
        lines = (out + err).decode("utf-8", "replace").splitlines()
        return lines[:20] if lines else "UNKNOWN"
    except Exception:
        return "UNKNOWN"


def runtime_inventory(source_dir: Optional[Path] = None) -> Dict[str, Any]:
    """CI-only bounded inventory; local invocation is intentionally refused."""
    if os.environ.get("GITHUB_ACTIONS", "").lower() != "true":
        return {"status": "SKIPPED_NOT_CI", "tools": {}}
    names = ("kani", "kani-compiler", "kani-driver", "kani-compiler-rt", "cbmc", "goto-instrument",
             "kissat", "minisat", "cadical", "cvc5", "z3", "rustc", "cargo")
    tools = {name: _inventory_one(name, shutil.which(name)) for name in names}
    root = source_dir
    if root is None:
        root = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd())) / "export"
        if not root.exists():
            root = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd()))
    payload_root = root / "target" / "kani"
    inventory_files: Dict[str, Any] = {}
    inventory_total = 0
    inventory_limit_hit = False
    if payload_root.is_dir():
        count = 0
        for base, dirs, files in os.walk(str(payload_root)):
            dirs.sort()
            files.sort()
            for filename in files:
                path = Path(base) / filename
                try:
                    size = path.stat().st_size
                    inventory_total += size
                    if size > RUNTIME_FILE_CAP_BYTES or inventory_total > RUNTIME_INVENTORY_CAP_BYTES or count >= 10000:
                        inventory_limit_hit = True
                        break
                    digest, _ = _sha256(path, max_bytes=RUNTIME_FILE_CAP_BYTES)
                    rel = str(path.relative_to(root))
                    inventory_files[rel] = {"sha256": digest, "bytes": size}
                    count += 1
                    low = filename.lower()
                    if os.access(str(path), os.X_OK) and any(word in low for word in ("kani", "cbmc", "goto-instrument", "kissat", "minisat", "cadical", "cvc5", "z3")):
                        tools.setdefault("payload_binaries", {})[rel] = {
                            "sha256": digest, "bytes": size,
                            "version": _version(str(path), ["--version"])}
                except Exception as e:
                    inventory_files[str(path)] = {"sha256": "UNKNOWN", "error": str(e)[:256]}
                    if "bounded hash size" in str(e):
                        inventory_limit_hit = True
                        break
            if inventory_limit_hit:
                break
        tools["payload_files"] = inventory_files
    runtime_layout: Dict[str, Any] = {}
    for name, rel in (("verification", "lib"), ("playback", "playback/lib"), ("no_core", "no_core/lib")):
        directory = payload_root / rel
        try:
            members = sorted(path.name for path in directory.iterdir() if path.is_file()) if directory.is_dir() else []
        except OSError:
            members = []
        runtime_layout[name] = {"path": str(directory), "files": members[:10000], "present": bool(members)}
    rustup = shutil.which("rustup")
    if rustup:
        actual_rustc = _version(rustup, ["which", "--toolchain", "nightly-2026-10-23", "rustc"])
        if isinstance(actual_rustc, list) and actual_rustc:
            rustc_path = actual_rustc[0].strip()
            if Path(rustc_path).is_file():
                tools["rustc"] = _inventory_one("rustc", rustc_path)
                tools["rustc"]["version"] = _version(rustc_path, ["-vV"])
                try:
                    host = next((line.split(":", 1)[1].strip() for line in tools["rustc"]["version"] if line.startswith("host:")), None)
                    if host:
                        tools["rustc"]["host_triple"] = host
                except (TypeError, IndexError):
                    pass
    required = ("kani-compiler", "kani-driver", "cbmc", "goto-instrument", "kissat", "cvc5", "z3", "rustc")
    payload_bins = tools.get("payload_binaries", {})
    for name in required:
        if tools.get(name, {}).get("sha256") in (None, "UNKNOWN"):
            match = next((item for path, item in payload_bins.items() if Path(path).name == name), None)
            if match:
                tools[name] = {"path": str(root / next(path for path in payload_bins if Path(path).name == name)), **match}
    missing = []
    for name in required:
        item = tools.get(name, {})
        version = item.get("version")
        if item.get("sha256") in (None, "UNKNOWN") or not isinstance(version, list) or not version:
            missing.append(name)
    model_path = root / "library" / "kani" / "kani_lib.c"
    try:
        model_hash, model_size = _sha256(model_path, max_bytes=RUNTIME_FILE_CAP_BYTES)
        tools["kani_model_c"] = {"path": str(model_path), "sha256": model_hash, "bytes": model_size}
    except Exception:
        tools["kani_model_c"] = {"path": str(model_path), "sha256": "UNKNOWN", "bytes": "UNKNOWN"}
        missing.append("kani-model-library/kani_lib.c")
    for layout_name, entry in runtime_layout.items():
        if not entry["present"]:
            missing.append("kani-sysroot-%s-libraries" % layout_name)
    if inventory_limit_hit:
        missing.append("runtime-inventory-cap-exceeded")
    if any(item.get("sha256") == "UNKNOWN" for item in inventory_files.values()):
        missing.append("runtime-inventory-cap-or-hash-error")
    return {"status": "COLLECTED", "tools": tools, "payload_root": str(payload_root),
            "runtime_layout": runtime_layout, "inventory_limit_hit": inventory_limit_hit,
            "payload_total_bytes": inventory_total, "required_missing": missing}


def _directory_bytes(root: Path) -> int:
    total = 0
    for base, dirs, files in os.walk(str(root)):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(base, d))]
        for name in files:
            try:
                total += os.path.getsize(os.path.join(base, name))
            except OSError:
                continue
            if total > PACKAGE_CAP_BYTES:
                return total
    return total


def _enforce_metadata_cap(receipt: Dict[str, Any], state: Dict[str, Any]) -> bool:
    """Keep the combined JSON metadata under its cap, explicitly invalidating any compacted evidence."""
    def size() -> int:
        return len(_json_bytes(receipt)) + len(_json_bytes(state))

    if size() <= METADATA_CAP_BYTES:
        return True
    receipt["status"] = "INCOMPLETE_OR_FAILED"
    state["source_identity_ok"] = False
    state.setdefault("problems", []).append("metadata compaction invalidated completeness")
    receipt.setdefault("problems", []).append("TRUNCATED: combined metadata exceeded 16 MiB; diagnostics compacted")
    for check in state.get("source_checks", []):
        diff = check.get("diff", "")
        if len(diff.encode("utf-8", "replace")) > 65536:
            check["diff"] = diff[:65536]
            check["diff_truncated"] = True
            check["ok"] = False
    if isinstance(receipt.get("runtime_inventory", {}).get("tools", {}).get("payload_files"), dict):
        receipt["runtime_inventory"]["tools"]["payload_files"] = {"status": "TRUNCATED_METADATA_CAP"}
        receipt["runtime_inventory"].setdefault("required_missing", []).append("runtime-inventory-metadata-cap")
    if size() > METADATA_CAP_BYTES:
        # The observer's stage conclusions and original partial status remain intact.
        for check in state.get("source_checks", []):
            check.pop("diff", None)
            check.pop("untracked", None)
            check["diff_truncated"] = True
            check["ok"] = False
        if isinstance(receipt.get("lifecycle"), dict):
            receipt["lifecycle"]["source_checks"] = [
                {k: check.get(k) for k in ("phase", "timestamp_utc", "head", "tree", "clean", "ok", "mismatches")}
                for check in state.get("source_checks", [])]
            receipt["lifecycle"]["source_identity_ok"] = False
    if isinstance(receipt.get("lifecycle"), dict) and not state.get("source_identity_ok", False):
        receipt["lifecycle"]["source_identity_ok"] = False
    if size() > METADATA_CAP_BYTES:
        if isinstance(receipt.get("lifecycle"), dict):
            receipt["lifecycle"]["source_checks"] = []
            receipt["lifecycle"]["metadata_truncated"] = True
        state["source_checks"] = []
        state["source_identity_ok"] = False
    return size() <= METADATA_CAP_BYTES


def _other_metadata_bytes(root: Path, exclude: Iterable[Path]) -> int:
    excluded = {p.resolve() for p in exclude}
    total = 0
    for base, dirs, files in os.walk(str(root)):
        dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(base, d))]
        for name in files:
            path = Path(base) / name
            if path.resolve() in excluded or path.suffix.lower() not in (".json", ".toml", ".txt"):
                continue
            try:
                total += path.stat().st_size
            except OSError:
                pass
    return total


def _status_value(value: Optional[str]) -> str:
    return value or "UNKNOWN"


def command_finalize(args: argparse.Namespace) -> int:
    out = Path(args.output)
    state_path = out / "lifecycle.json"
    state = _load(state_path) if state_path.exists() else {"schema": SCHEMA, "problems": []}
    receipt_path = out / "receipt.json"
    if receipt_path.exists():
        receipt = _load(receipt_path)
    else:
        receipt = {"schema": "kani3300-gatea-observer-v1", "status": "NOT_RUN",
                   "formal_proof_credit": "NOT_ESTABLISHED", "script_exit": None,
                   "stages": {}, "stage_order_seen": [], "problems": []}
    for key in ("setup", "preflight", "observer", "regression"):
        value = getattr(args, key + "_status")
        if value is not None:
            state.setdefault("statuses", {})[key] = value
    statuses = state.get("statuses", {})
    if args.reason:
        state.setdefault("problems", []).append(args.reason)
    if args.source_dir:
        try:
            root = Path(args.source_dir).resolve()
            binding = _load(Path(args.binding)) if args.binding else {}
            phase = _check_source(root, binding, "post-regression")
            state.setdefault("source_checks", []).append(phase)
            state["source_identity_ok"] = phase["ok"] and all(c.get("ok") for c in state["source_checks"])
            receipt["source_identity"] = phase
        except Exception as e:
            state["source_identity_ok"] = False
            state.setdefault("problems", []).append("final source check failed: %s" % e)
    receipt["lifecycle"] = {"schema": SCHEMA, "platform": state.get("platform", {}),
                            "identities": state.get("identities", {}), "statuses": state.get("statuses", {}),
                            "source_checks": state.get("source_checks", []),
                            "source_identity_ok": state.get("source_identity_ok", False),
                            "budget": state.get("budget", {}), "problems": state.get("problems", [])}
    receipt.setdefault("run_id", state.get("identities", {}).get("run_id", "UNKNOWN"))
    receipt.setdefault("run_attempt", state.get("identities", {}).get("run_attempt", "UNKNOWN"))
    receipt.setdefault("matrix_os", state.get("platform", {}).get("matrix_os", "UNKNOWN"))
    receipt.setdefault("overlay_sha", state.get("identities", {}).get("overlay_sha", "UNKNOWN"))
    receipt.setdefault("export_sha", state.get("identities", {}).get("export_sha", "UNKNOWN"))
    receipt.setdefault("export_tree", state.get("identities", {}).get("export_tree", "UNKNOWN"))
    setup_ok = statuses.get("setup") in ("SUCCESS", "COMPLETE", "PASS", "success")
    receipt["runtime_inventory"] = runtime_inventory(Path(state.get("source_root")) if state.get("source_root") else None) if setup_ok else {"status": "SKIPPED_SETUP_FAILED", "tools": {}}
    host = receipt.get("runtime_inventory", {}).get("tools", {}).get("rustc", {}).get("host_triple")
    if host and state.get("platform"):
        state["platform"]["host_triple"] = host
        receipt["lifecycle"]["platform"] = state["platform"]
    current_package_bytes = _directory_bytes(out)
    if current_package_bytes > PACKAGE_CAP_BYTES:
        receipt.setdefault("problems", []).append("artifact package exceeds 384 MiB cap")
    statuses = receipt["lifecycle"]["statuses"]
    if (not receipt["lifecycle"]["source_identity_ok"] or
            any(statuses.get(k) not in ("SUCCESS", "COMPLETE", "PASS", "success") for k in ("setup", "preflight", "observer", "regression")) or
            state.get("problems") or
            receipt.get("runtime_inventory", {}).get("required_missing") or
            current_package_bytes > PACKAGE_CAP_BYTES):
        if receipt.get("status") == "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW":
            receipt["status"] = "INCOMPLETE_OR_FAILED"
        elif receipt.get("status") in (None, "NOT_RUN"):
            receipt["status"] = "NOT_RUN" if statuses.get("regression") in ("NOT_RUN", "SKIPPED", "skipped") else "INCOMPLETE_OR_FAILED"
    metadata_ok = _enforce_metadata_cap(receipt, state)
    if not metadata_ok:
        receipt["status"] = "INCOMPLETE_OR_FAILED"
        state.setdefault("problems", []).append("INCOMPLETE: combined metadata remains over 16 MiB; prior receipt preserved")
        state["finalization_status"] = "INCOMPLETE_METADATA_CAP"
        _write(state_path, state)
        raise ValueError("combined lifecycle and receipt metadata exceed 16 MiB; final receipt not written")
    old_size = sum((p.stat().st_size if p.exists() else 0) for p in (receipt_path, state_path))
    projected_package = _directory_bytes(out) - old_size + len(_json_bytes(receipt)) + len(_json_bytes(state))
    receipt["artifact_package_bytes_at_finalize"] = projected_package
    projected_package = _directory_bytes(out) - old_size + len(_json_bytes(receipt)) + len(_json_bytes(state))
    if projected_package > PACKAGE_CAP_BYTES:
        state.setdefault("problems", []).append("INCOMPLETE: artifact package would exceed 384 MiB; prior receipt preserved")
        state["finalization_status"] = "INCOMPLETE_PACKAGE_CAP"
        _write(state_path, state)
        raise ValueError("artifact package would exceed 384 MiB; finalization stopped before upload")
    metadata_size = (_other_metadata_bytes(out, (receipt_path, state_path)) +
                     len(_json_bytes(receipt)) + len(_json_bytes(state)))
    if metadata_size > METADATA_CAP_BYTES:
        state.setdefault("problems", []).append("INCOMPLETE: all JSON/TOML/TXT metadata exceeds 16 MiB")
        state["finalization_status"] = "INCOMPLETE_METADATA_CAP"
        _write(state_path, state)
        raise ValueError("metadata files exceed 16 MiB cap; finalization stopped")
    _write(receipt_path, receipt)
    _write(state_path, state)
    print(json.dumps({"receipt": str(receipt_path), "status": receipt.get("status"), "package_bytes": projected_package}))
    return 0 if receipt.get("status") == "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW" else 1


def _find_row_receipts(root: Path, row: str) -> List[Path]:
    found = set()
    candidates = [root / row / "receipt.json", root / (row + ".json")]
    for p in candidates:
        if p.is_file():
            found.add(p.resolve())
    for p in root.glob("*/receipt.json"):
        try:
            obj = _load(p)
            if obj.get("matrix_os") == row:
                found.add(p.resolve())
        except Exception:
            continue
    return sorted(found)


def _row_complete(receipt: Dict[str, Any], expected_stages: List[Dict[str, Any]]) -> bool:
    if receipt.get("status") != "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW":
        return False
    if receipt.get("script_exit") != 0:
        return False
    termination = receipt.get("termination") or {}
    if termination.get("kind") not in (None, "exit", "EXIT"):
        return False
    stream = receipt.get("event_stream", {})
    if stream.get("complete") is not True or stream.get("truncated") is not False:
        return False
    if not isinstance(stream.get("sha256"), str) or len(stream["sha256"]) != 64:
        return False
    if not isinstance(stream.get("bytes"), int) or not 0 <= stream["bytes"] <= 256 * 1024 * 1024:
        return False
    if receipt.get("lifecycle", {}).get("source_identity_ok") is not True:
        return False
    if receipt.get("runtime_inventory", {}).get("required_missing"):
        return False
    inventory = receipt.get("runtime_inventory", {})
    if inventory.get("status") != "COLLECTED":
        return False
    for tool in ("kani-compiler", "kani-driver", "cbmc", "goto-instrument", "kissat", "cvc5", "z3", "rustc"):
        item = inventory.get("tools", {}).get(tool, {})
        if item.get("sha256") in (None, "UNKNOWN") or not isinstance(item.get("version"), list) or not item["version"]:
            return False
    statuses = receipt.get("lifecycle", {}).get("statuses", {})
    if any(statuses.get(key) not in ("success", "SUCCESS", "COMPLETE", "PASS")
           for key in ("setup", "preflight", "observer", "regression")):
        return False
    if receipt.get("problems"):
        return False
    stages = receipt.get("stages")
    expected_stage_ids = [stage["id"] for stage in expected_stages]
    if not isinstance(stages, dict) or list(receipt.get("stage_order_seen", [])) != expected_stage_ids:
        return False
    if set(stages) != set(expected_stage_ids):
        return False
    def normalize_command(value: Any) -> str:
        if not isinstance(value, str):
            return ""
        normalized = " ".join(value.split())
        return normalized[5:] if normalized.startswith("time ") else normalized

    for expected in expected_stages:
        sid = expected["id"]
        stage = stages[sid]
        if not isinstance(stage, dict):
            return False
        if stage.get("status") != "EXIT_ZERO" or stage.get("exit") != 0:
            return False
        if normalize_command(stage.get("command")) != normalize_command(expected.get("command")):
            return False
        if expected.get("mode", "") and stage.get("mode", "") != expected.get("mode", ""):
            return False
        if stage.get("counts_required") is not bool(expected.get("counts_required")):
            return False
        if stage.get("source_line", stage.get("line")) != expected.get("line"):
            return False
        counts = stage.get("counts")
        if stage.get("counts_required"):
            if not isinstance(counts, list) or not counts:
                return False
            for entry in counts:
                values = entry.get("counts", {})
                if any(not isinstance(values.get(key), int) or values[key] < 0 or values[key] > 100_000_000
                       for key in ("passed", "failed", "ignored", "filtered")):
                    return False
                if values.get("failed", 1) != 0:
                    return False
                if values.get("filtered", 1) != 0:
                    return False
    for field in ("export_sha", "export_tree", "overlay_sha", "run_id"):
        if not receipt.get(field) or receipt[field] == "UNKNOWN":
            return False
    return True


def command_aggregate(args: argparse.Namespace) -> int:
    root = Path(args.receipts_dir)
    expected_overlay = args.overlay_sha or os.environ.get("GITHUB_SHA")
    expected_run_id = os.environ.get("GITHUB_RUN_ID")
    binding_path = Path(args.binding) if args.binding else Path(__file__).with_name("binding.json")
    binding = _load(binding_path)
    expected_stages = binding.get("stages", [])
    expected_stage_ids = [stage.get("id") for stage in expected_stages]
    if len(expected_stage_ids) != 33 or len(set(expected_stage_ids)) != 33 or any(not isinstance(value, str) for value in expected_stage_ids):
        raise ValueError("binding must define exactly 33 ordered stage IDs")
    rows: Dict[str, Any] = {}
    common: Dict[str, Any] = {}
    problems: List[str] = []
    for row in EXPECTED_ROWS:
        paths = _find_row_receipts(root, row)
        if not paths:
            rows[row] = {"status": "MISSING", "ok": False}
            problems.append("missing row %s" % row)
            continue
        if len(paths) != 1:
            rows[row] = {"status": "DUPLICATE", "ok": False, "paths": [str(p) for p in paths]}
            problems.append("duplicate receipts for %s" % row)
            continue
        path = paths[0]
        try:
            receipt = _load(path)
        except Exception as e:
            rows[row] = {"status": "INVALID_RECEIPT", "ok": False, "path": str(path), "error": str(e)}
            problems.append("invalid receipt for %s" % row)
            continue
        if not isinstance(receipt, dict):
            rows[row] = {"status": "INVALID_RECEIPT", "ok": False, "path": str(path),
                         "error": "receipt JSON root must be an object"}
            problems.append("invalid receipt for %s" % row)
            continue
        try:
            ok = _row_complete(receipt, expected_stages)
        except (KeyError, TypeError, AttributeError, ValueError):
            ok = False
        identities = {key: receipt.get(key) for key in ("run_id", "run_attempt", "overlay_sha", "export_sha", "export_tree")}
        rows[row] = {"status": receipt.get("status", "UNKNOWN"), "ok": ok, "path": str(path), "identities": identities}
        for key in ("run_id", "overlay_sha", "export_sha", "export_tree"):
            val = identities.get(key)
            if val is not None:
                if key in common and common[key] != val:
                    problems.append("incoherent %s across rows" % key)
                common.setdefault(key, val)
        if receipt.get("matrix_os") != row:
            problems.append("matrix row identity mismatch for %s" % row)
        if receipt.get("export_sha") != binding.get("export_sha") or receipt.get("export_tree") != binding.get("export_tree"):
            problems.append("source identity mismatch for %s" % row)
        if expected_run_id and receipt.get("run_id") != expected_run_id:
            problems.append("run identity mismatch for %s" % row)
        if not ok:
            problems.append("row incomplete or failed: %s" % row)
        if str(receipt.get("run_attempt", "")) != "1":
            problems.append("run attempt is not 1 for %s" % row)
    if args.matrix_result != "success":
        problems.append("matrix job result is %s" % args.matrix_result)
    if expected_overlay and common.get("overlay_sha") != expected_overlay:
        problems.append("overlay SHA does not match expected dispatch SHA")
    successful = not problems and len(rows) == 3 and all(v.get("ok") for v in rows.values())
    result = {"schema": "kani3300-gatea-aggregate-v1", "status": "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW" if successful else "INCOMPLETE_OR_FAILED",
              "formal_proof_credit": "NOT_ESTABLISHED", "expected_rows": list(EXPECTED_ROWS),
              "rows": rows, "coherent_identities": common, "problems": problems}
    output = Path(args.output)
    if output.exists() and output.is_dir() or not output.suffix:
        output = output / "aggregate.json"
    _write(output, result)
    print(json.dumps(result, sort_keys=True))
    return 0 if successful else 1


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    q = sub.add_parser("init")
    q.add_argument("--binding", required=True); q.add_argument("--output", required=True)
    q.add_argument("--platform", required=True); q.add_argument("--run-id"); q.add_argument("--run-attempt")
    q.add_argument("--job-id"); q.add_argument("--overlay-sha"); q.add_argument("--runner-image")
    q.add_argument("--started-epoch", type=float); q.set_defaults(func=command_init)
    q = sub.add_parser("check")
    q.add_argument("--binding", required=True); q.add_argument("--source-dir", required=True)
    q.add_argument("--output", required=True); q.add_argument("--phase", required=True, choices=("pre-setup", "post-setup", "post-regression"))
    q.set_defaults(func=command_check)
    q = sub.add_parser("budget")
    q.add_argument("--output", required=True); q.add_argument("--now-epoch", type=float); q.set_defaults(func=command_budget)
    q = sub.add_parser("finalize")
    q.add_argument("--output", required=True); q.add_argument("--binding"); q.add_argument("--source-dir"); q.add_argument("--reason")
    for key in ("setup", "preflight", "observer", "regression"):
        q.add_argument("--%s-status" % key, dest=key + "_status")
    q.set_defaults(func=command_finalize)
    q = sub.add_parser("aggregate")
    q.add_argument("--receipts-dir", required=True); q.add_argument("--output", required=True); q.add_argument("--overlay-sha")
    q.add_argument("--binding"); q.add_argument("--matrix-result", default="UNKNOWN")
    q.set_defaults(func=command_aggregate)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = parser().parse_args(argv)
    try:
        return args.func(args)
    except Exception as e:
        print("lifecycle error: %s" % e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
