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
import tomllib
from typing import Any


from request import CBMC_VERSION, TOOL

TOOL_SHA, TOOL_TREE = TOOL
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


class AttestationTimeout(AttestationError):
    """A tool probe exhausted its allocated time."""


def _remaining(deadline: float) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise AttestationTimeout("deadline exhausted during tool attestation")
    return left


def _run(argv: list[str], deadline: float, *, env: dict[str, str] | None = None, strip=True) -> str:
    try:
        completed = subprocess.run(
            argv, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace", timeout=_remaining(deadline),
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        raise AttestationTimeout(f"timed out running {argv[0]} during tool attestation") from exc
    except OSError as exc:
        raise AttestationError(f"cannot run {argv[0]} during tool attestation: {exc}") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or completed.stdout).strip()[:1000]
        raise AttestationError(
            f"{argv[0]} exited {completed.returncode} during tool attestation"
            + (f": {detail}" if detail else "")
        )
    return completed.stdout.strip() if strip else completed.stdout


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


RELEASE = r"[0-9]+\.[0-9]+\.[0-9]+"
RELEASE_TOKEN = re.compile(rf"(?<![\w.~+])v?({RELEASE}[^\s()]*)")
# Whitespace and parentheses delimit the full labeled values in the banner.
GOTO_CC_RELEASE_TOKEN = re.compile(r"(?<![\w-])(?:goto-cc[ \t]+|cbmc-)([^\s()]*)")


def _first_line(output):
    return output.partition("\n")[0].removesuffix("\r")


def _require_release(label, output, expected):
    line = _first_line(output)
    # In GCC emulation mode goto-cc also prints the emulated GCC version.
    token = GOTO_CC_RELEASE_TOKEN if label == "goto-cc" else RELEASE_TOKEN
    if set(token.findall(line)) != {expected}:
        raise AttestationError(f"{label} version mismatch: pin {expected}, first line {line[:400]!r}")


def _rustc_identity(output):
    fields = {}
    patterns = {"release": rf"{RELEASE}-nightly", "commit-hash": r"[a-f0-9]{40}",
                "commit-date": r"[0-9]{4}-[0-9]{2}-[0-9]{2}", "host": r"[\w-]+"}
    for name, pattern in patterns.items():
        values = re.findall(rf"^[ \t]*{name}[ \t]*:[ \t]*([^\r\n]*)", output, re.M)
        if len(values) != 1 or not re.fullmatch(pattern, values[0].strip()):
            raise AttestationError(f"rustc version has no unique valid {name}: {_first_line(output)[:400]!r}")
        fields[name] = values[0].strip()
    return fields


def _check_launcher_rustc(output, expected):
    reports = re.findall(r"\brustc[ \t]+(\S[^\r\n]*)", output)
    if len(reports) == 1:
        release, *details = reports[0].split(maxsplit=1)
        if details and release == expected["release"]:
            hashes = re.findall(r"\b[0-9a-f]{7,40}\b", details[0])
            dates = re.findall(r"\b[0-9]{4}-[0-9]{2}-[0-9]{2}\b", details[0])
            if (hashes and all(expected["commit-hash"].startswith(h) for h in hashes)
                    and set(dates) == {expected["commit-date"]}):
                return
    raise AttestationError(f"built launcher and pinned rustc identity differ: {output[:400]!r}")


def attest(tool: Path, deadline: float, *, include_goto_cc=False, version_first_lines=None) -> dict[str, Any]:
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
    rustc_name = _run(["rustup", "which", "rustc", "--toolchain", channel], deadline)
    rustc_names = rustc_name.splitlines()
    if not rustc_names:
        raise AttestationError(f"rustup did not resolve rustc for {channel}")
    rustc = _executable(Path(rustc_names[-1]), "pinned rustc")

    # Stock source contract: scripts/kani execs this driver, which discovers
    # its sibling compiler in bin_folder(); CBMC and goto-instrument use PATH.
    launcher_path = _executable(tool / "scripts/kani", "launcher")
    driver_path = tool / "target/kani/bin/kani-driver"
    compiler_path = tool / "target/kani/bin/kani-compiler"
    driver = _executable(driver_path, "built kani-driver")
    compiler = _executable(compiler_path, "built kani-compiler")
    cbmc_pin = _version_from_pin(tool)
    if cbmc_pin != CBMC_VERSION:
        raise AttestationError(f"CBMC dependency pin mismatch: expected {CBMC_VERSION}, got {cbmc_pin}")
    kissat_pin = re.search(r'^KISSAT_VERSION="([0-9.]+)"$', (tool / "kani-dependencies").read_text(), re.M)
    if not kissat_pin:
        raise AttestationError("kani-dependencies has no literal KISSAT_VERSION pin")
    kani_pin = tomllib.loads((tool / "kani-driver/Cargo.toml").read_text(encoding="utf-8"))["package"]["version"]
    versioned = {"rustc": rustc, "launcher": launcher_path, "kissat": _binary("kissat"),
                 "cbmc": _binary("cbmc"), "goto_instrument": _binary("goto-instrument")}
    if include_goto_cc:
        versioned["goto_cc"] = _binary("goto-cc")
    versions = {}
    for key, path in versioned.items():
        verbose = ["--verbose"] if key in {"rustc", "launcher"} else []
        output = _run([str(path), "--version", *verbose], deadline, strip=False)
        if version_first_lines is not None:
            version_first_lines[key] = _first_line(output)
        versions[key] = output

    identity = _rustc_identity(versions["rustc"])
    # The stock export embeds this rustc display string from its own build.
    rustc_banner = re.search(r"^[ \t]*rustc[ \t]+([^\r\n]+)", versions["rustc"], re.M)
    release = rustc_banner[1].strip() if rustc_banner else ""
    if not release or release.split()[0] != identity["release"]:
        raise AttestationError(f"rustc banner and verbose release differ: {release[:400]!r}")
    _check_launcher_rustc(versions["launcher"], identity)
    # Kani's parenthesized Git description can contain a different tag version.
    _require_release("Kani", _first_line(versions["launcher"]).partition("(")[0], kani_pin)
    for key, label, pin in (("kissat", "Kissat", kissat_pin[1]), ("cbmc", "CBMC", cbmc_pin),
                            ("goto_instrument", "goto-instrument", cbmc_pin),
                            ("goto_cc", "goto-cc", cbmc_pin)):
        if key in versions:
            _require_release(label, versions[key], pin)

    binaries = {key: {"path": str(path), **_hash_file(path, deadline)} for key, path in
                (versioned | {"kani_driver": driver, "kani_compiler": compiler}).items()}
    for key, version in versions.items():
        binaries[key]["version"] = version.strip()
    return {
        "schema": "smallsort-cal1-tool-attestation-v1",
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


def _runtime_identity(receipt):
    binaries = receipt.get("binaries")
    if not isinstance(binaries, dict) or any(not isinstance(binary, dict) for binary in binaries.values()):
        raise AttestationError("tool attestation has no valid binary inventory")
    rustc_version = binaries.get("rustc", {}).get("version")
    if not isinstance(rustc_version, str):
        raise AttestationError("tool attestation has no rustc version")
    # Re-probing checks the pinned releases. Compare the binary records and
    # structured Rust identity without relying on stable display text.
    identity = {key: value for key, value in receipt.items() if key not in {"setup_elapsed_seconds", "rustc_release"}}
    identity["binaries"] = {key: {field: value for field, value in binary.items() if field != "version"}
                            for key, binary in binaries.items()}
    identity["rustc"] = _rustc_identity(rustc_version)
    return identity
