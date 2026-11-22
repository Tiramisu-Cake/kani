# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Bounded receipt for the actual stock Kani tool setup used by a job.

This module only observes a completed build.  It probes the launcher version and resolves dependencies through the pinned
driver's PATH lookup.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Any


TOOL_SHA = "bcdc1a0f8dc566654da1f18b4e502f0f4e7ad40a"
TOOL_TREE = "15816aaf3b6dfa4855452e34825073db8ca6760f"
PIN_FILES = (
    ".cargo/config.toml",
    "Cargo.lock",
    "Cargo.toml",
    ".gitmodules",
    "kani-dependencies",
    "rust-toolchain.toml",
)
CHUNK_BYTES = 1024 * 1024


class AttestationError(RuntimeError):
    """The setup could not be bound to the expected stock tool inputs."""


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise AttestationError("setup deadline exhausted during tool attestation")
    return left


def _run(argv: list[str], deadline: float, *, env: dict[str, str] | None = None) -> str:
    try:
        completed = subprocess.run(
            argv, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", timeout=_remaining(deadline),
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise AttestationError(f"timed out running {argv[0]} during tool attestation") from exc
    except OSError as exc:
        raise AttestationError(f"cannot run {argv[0]} during tool attestation: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[:1000]
        raise AttestationError(
            f"{argv[0]} exited {completed.returncode} during tool attestation"
            + (f": {detail}" if detail else "")
        )
    return completed.stdout.strip()


def _git(tool: Path, *args: str, deadline: float) -> str:
    return _run(["git", "-C", str(tool), *args], deadline)


def _hash_file(path: Path, deadline: float) -> dict[str, Any]:
    try:
        if not path.is_file():
            raise AttestationError(f"required tool input is missing or not a file: {path}")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            while True:
                _remaining(deadline)
                block = stream.read(CHUNK_BYTES)
                if not block:
                    break
                digest.update(block)
            after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise AttestationError(f"tool input changed while hashing: {path}")
        return {"sha256": digest.hexdigest(), "bytes": after.st_size}
    except OSError as exc:
        raise AttestationError(f"cannot hash tool input {path}: {exc}") from exc


def _binary(name: str, expected: Path | None = None) -> Path:
    found = shutil.which(name)
    if not found:
        raise AttestationError(f"required runtime executable not found on PATH: {name}")
    resolved = Path(found).resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise AttestationError(f"runtime executable is not an executable file: {resolved}")
    if expected is not None and resolved != expected.resolve(strict=True):
        raise AttestationError(f"{name} resolved to {resolved}; stock setup requires {expected}")
    return resolved


def _executable(path: Path, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise AttestationError(f"required {label} is missing: {path}") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise AttestationError(f"required {label} is not executable: {resolved}")
    return resolved


def _version_from_pin(tool: Path) -> str:
    text = (tool / "kani-dependencies").read_text(encoding="utf-8")
    match = re.search(r'^CBMC_VERSION="([0-9]+\.[0-9]+\.[0-9]+)"\s*$', text, re.M)
    if not match:
        raise AttestationError("kani-dependencies has no literal CBMC_VERSION pin")
    return match.group(1)


def attest(tool: Path, deadline: float) -> dict[str, Any]:
    """Attest the completed pinned stock build before verification starts.

    ``deadline`` is an absolute ``time.monotonic()`` timestamp shared with
    setup/build supervision.  The returned mapping is JSON serializable.
    """
    tool = Path(tool).resolve(strict=True)
    _remaining(deadline)
    commit = _git(tool, "rev-parse", "HEAD", deadline=deadline)
    tree = _git(tool, "rev-parse", "HEAD^{tree}", deadline=deadline)
    if commit != TOOL_SHA or tree != TOOL_TREE:
        raise AttestationError(f"tool identity mismatch: expected {TOOL_SHA}/{TOOL_TREE}, got {commit}/{tree}")
    dirty = _git(tool, "status", "--porcelain", "--untracked-files=no", deadline=deadline)
    if dirty:
        raise AttestationError("tool checkout has tracked modifications after stock build")

    pin_files: dict[str, dict[str, Any]] = {}
    for rel in PIN_FILES:
        pin_files[rel] = _hash_file(tool / rel, deadline)

    # Pin the actual Rust compiler selected by this checkout's rust-toolchain.
    channel_match = re.search(
        r'^\s*channel\s*=\s*["\']([^"\']+)["\']\s*$',
        (tool / "rust-toolchain.toml").read_text(encoding="utf-8"), re.M,
    )
    if not channel_match:
        raise AttestationError("rust-toolchain.toml has no literal toolchain channel")
    channel = channel_match.group(1)
    rustc_name = _run(["rustup", "which", "rustc", "--toolchain", channel], deadline).splitlines()[-1]
    rustc = _executable(Path(rustc_name), "pinned rustc")
    rustc_verbose = _run([str(rustc), "--version", "--verbose"], deadline)
    version_line = rustc_verbose.splitlines()[0] if rustc_verbose else ""
    if not re.fullmatch(r"rustc \S+-nightly \([^)]+\)", version_line):
        raise AttestationError(f"rustc version does not identify nightly {channel}: {rustc_verbose[:400]}")
    release = version_line.removeprefix("rustc ")

    # Stock source contract: scripts/kani execs this driver, which discovers
    # its sibling compiler in bin_folder(); CBMC and goto-instrument use PATH.
    launcher_path = _executable(tool / "scripts/kani", "launcher")
    launcher = _hash_file(launcher_path, deadline)
    driver_path = tool / "target/kani/bin/kani-driver"
    compiler_path = tool / "target/kani/bin/kani-compiler"
    driver = _executable(driver_path, "built kani-driver")
    compiler = _executable(compiler_path, "built kani-compiler")
    cbmc = _binary("cbmc")
    goto_instrument = _binary("goto-instrument")
    cbmc_pin = _version_from_pin(tool)
    kissat = _binary("kissat")
    kissat_pin = re.search(r'^KISSAT_VERSION="([0-9.]+)"$', (tool / "kani-dependencies").read_text(), re.M)
    kissat_version = _run([str(kissat), "--version"], deadline)
    if not kissat_pin or kissat_version != kissat_pin[1]:
        raise AttestationError(f"Kissat version mismatch: {kissat_version[:100]}")
    launcher_version = _run([str(launcher_path), "--version", "--verbose"], deadline)
    if f"using rustc {release}" not in launcher_version:
        raise AttestationError("built launcher and pinned rustc release differ")
    cbmc_version = _run([str(cbmc), "--version"], deadline)
    observed_cbmc = cbmc_version.split()[0] if cbmc_version.split() else ""
    if observed_cbmc != cbmc_pin:
        raise AttestationError(f"CBMC version mismatch: pin {cbmc_pin}, observed {cbmc_version[:400]}")
    goto_version = _run([str(goto_instrument), "--version"], deadline)
    observed_goto = goto_version.split()[0] if goto_version.split() else ""
    if observed_goto != cbmc_pin:
        raise AttestationError(f"goto-instrument version mismatch: CBMC pin {cbmc_pin}, observed {goto_version[:400]}")

    binaries = {
        "rustc": {"path": str(rustc), **_hash_file(rustc, deadline), "version": rustc_verbose},
        "kani_driver": {"path": str(driver), **_hash_file(driver, deadline)},
        "kani_compiler": {"path": str(compiler), **_hash_file(compiler, deadline)},
        "launcher": {"path": str(launcher_path), **launcher, "version": launcher_version},
        "kissat": {"path": str(kissat), **_hash_file(kissat, deadline), "version": kissat_version},
        "cbmc": {"path": str(cbmc), **_hash_file(cbmc, deadline), "version": cbmc_version},
        "goto_instrument": {"path": str(goto_instrument), **_hash_file(goto_instrument, deadline), "version": goto_version},
    }
    return {
        "schema": "ch8-kani5196-tool-attestation-v1",
        "status": "COMPLETE",
        "tool": {"commit": commit, "tree": tree, "clean_tracked": True},
        "pins": pin_files,
        "rust_toolchain": {"channel": channel},
        "rustc_release": release,
        "dependency_versions": {"cbmc": cbmc_pin, "kissat": kissat_pin[1]},
        "runtime_path": os.environ.get("PATH", ""),
        "lookup_contract": {
            "launcher": "scripts/kani",
            "driver": "target/kani/bin/kani-driver (launcher exec target)",
            "kani_compiler": "target/kani/bin/kani-compiler (driver sibling lookup)",
            "cbmc": "PATH lookup: cbmc",
            "goto_instrument": "PATH lookup: goto-instrument",
            "cbmc_pinned_version": cbmc_pin,
        },
        "binaries": binaries,
    }


def verify(receipt, tool, request, deadline):
    """Re-resolve and hash the complete setup before and after verification."""
    if not isinstance(receipt, dict):
        raise AttestationError("tool attestation is missing")
    expected = {k: v for k, v in receipt.items() if k != "setup_elapsed_seconds"}
    elapsed = receipt.get("setup_elapsed_seconds")
    if (receipt.get("status") != "COMPLETE" or type(elapsed) not in (int, float)
            or not 0 <= elapsed <= request["limits"]["setup_and_build_seconds"]
            or receipt.get("rust_toolchain") != {"channel": request["pins"]["tool"]["declared_nightly"]}
            or receipt.get("dependency_versions") != request["dependency_versions"]):
        raise AttestationError("tool attestation does not match the frozen setup")
    if attest(tool, deadline) != expected:
        raise AttestationError("tool setup, compiler, executable digest or PATH changed")
