#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""CI phases. Verification failures are data; setup/compiler/curation errors fail CI."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import resource
import shutil
import signal
import subprocess
import sys

CANDIDATE = "955cd015649aa79be511fe1732d48fdc8535741f"
BASELINE = "a0a2386001a15fecfe2facc2f6cd87f3dee13b60"
FIXTURE = "tests/expected/uninit/maybe-uninit-initialized/main.rs"
FIXTURE_SHA = "df6292d1fdc472cb41e6e7d707a6bc4f8b190a3f206a7f208e635a8d0b5f9e5c"
A = "array_value_as_used_by_merge_output"
B = "partial_copy_preserves_written_byte"
HERE = Path(__file__).resolve().parent


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")


def command(argv, cwd, output, timeout, env=None):
    """Keep logs private; kill/reap the whole case process group on timeout."""
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("wb") as stream:
        try:
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stream,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        except OSError as error:
            return {"exit": "NOT_RUN", "error": str(error), "argv": argv}
        try:
            code = child.wait(timeout=timeout)
            return {"exit": code if code >= 0 else None,
                    "signal": -code if code < 0 else None, "argv": argv}
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            # Also kill descendants if the driver exited while its children remained.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            return {"exit": "TIMEOUT", "wait_returncode": child.returncode, "argv": argv}


def text_command(argv, cwd):
    return subprocess.check_output(argv, cwd=cwd, text=True, timeout=60).strip()


def manifest_tree(root):
    return [{"file": str(p.relative_to(root)), "bytes": p.stat().st_size,
             "sha256": digest(p)} for p in sorted(root.rglob("*")) if p.is_file()]


def extract_roots(directory, selectors):
    """Join actual metadata to the linked solver file via ArtifactType conversion."""
    files = list((directory / "model").rglob("*.kani-metadata.json"))
    assert len(files) == 1, "expected one crate metadata/unit"
    metadata = json.loads(files[0].read_text())
    assert metadata["test_harnesses"] == [], "unexpected test roots"
    rows = metadata["proof_harnesses"]
    assert sorted(row["pretty_name"] for row in rows) == sorted(selectors), "actual roots differ from requested roots"
    roots = []
    for row in rows:
        attrs = row["attributes"]
        assert attrs["kind"] == "Proof" and attrs["stubs"] == [] and attrs["verified_stubs"] == [], "unexpected harness mode/stubs"
        assert row["is_automatically_generated"] is False, "unexpected automatic root"
        assert row["mangled_name"] and row["goto_file"], "missing actual mangled root/model"
        symtab = Path(row["goto_file"])
        assert symtab.is_absolute() and symtab.name.endswith(".symtab.out"), "unbound model path"
        linked = symtab.with_name(symtab.name[:-len(".symtab.out")] + ".out").resolve(strict=True)
        assert linked.is_relative_to((directory / "model").resolve()), "model outside case"
        roots.append({"pretty_name": row["pretty_name"], "mangled_name": row["mangled_name"],
                      "solver_input": str(linked), "solver_input_sha256": digest(linked),
                      "metadata_file": str(files[0]), "metadata_sha256": digest(files[0])})
    write(directory / "roots.json", roots)
    return roots


def preflight(repo, source):
    expected = CANDIDATE if source == "candidate" else BASELINE
    assert text_command(["git", "rev-parse", "HEAD"], repo) == expected, "source SHA"
    if source == "candidate":
        assert text_command(["git", "rev-parse", "HEAD^{tree}"], repo) == "1c724bf33763251340efbdf9a8486a6278cafdc4", "candidate tree"
    assert digest(repo / FIXTURE) == FIXTURE_SHA, "fixture SHA"
    assert not text_command(["git", "status", "--porcelain", "--untracked-files=no"], repo), "dirty source"
    for name in os.environ:
        assert not (name.startswith(("KANI_", "D0_", "CARGO_ENCODED_RUSTFLAGS"))
                    or name in {"RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"}), "inherited flags: " + name
    assert len(os.sched_getaffinity(0)) >= 2, "paired cases need >=2 CPUs"
    assert not text_command(["git", "diff", BASELINE, CANDIDATE, "--", "library"], repo), "library sources differ"
    rust = text_command(["rustc", "+nightly-2026-10-23", "-vV"], repo)
    assert "7189d39d9ce936881b8132c6addeaf3e295cd455" in rust, "rustc commit"
    assert "host: x86_64-unknown-linux-gnu" in rust, "rustc target"
    tools = {}
    for name, version in (("cbmc", "6.11.0"), ("goto-instrument", "6.11.0"), ("kissat", "4.0.1")):
        path = Path(shutil.which(name) or "").resolve()
        actual = text_command([str(path), "--version"], repo)
        assert actual.split()[0] == version, name + " version"
        tools[name] = {"path": str(path), "sha256": digest(path), "version": actual}
    sysroot = Path(text_command(["rustc", "+nightly-2026-10-23", "--print", "sysroot"], repo))
    layout = text_command(["rustc", "+nightly-2026-10-23", "-Z", "unstable-options", "--print", "target-spec-json",
                           "--target", "x86_64-unknown-linux-gnu"], repo)
    spec = json.loads(layout)
    assert str(spec["target-pointer-width"]) == "64" and spec["data-layout"].startswith("e"), "layout"
    return {"source": expected, "tree": text_command(["git", "rev-parse", "HEAD^{tree}"], repo),
            "fixture_sha256": FIXTURE_SHA,
            "baseline": BASELINE, "candidate": CANDIDATE,
            "diagnostic_diff_sha256": hashlib.sha256(subprocess.check_output(
                ["git", "diff", "--binary", "--unified=0", BASELINE, CANDIDATE], cwd=repo)).hexdigest(),
            "rustc_vV": rust, "tools": tools,
            "rust_sysroot": manifest_tree(sysroot), "target_spec": spec,
            "cpu_affinity": sorted(os.sched_getaffinity(0)), "machine": platform.machine(),
            "memory": Path("/proc/meminfo").read_text().splitlines()[:3],
            "limits": {"address_space": resource.getrlimit(resource.RLIMIT_AS),
                       "cpu": resource.getrlimit(resource.RLIMIT_CPU), "case_timeout_seconds": 600},
            "build_recipe": ["cargo", "build-dev", "--", "--release"]}


def prepare(repo, source, out):
    state = {"setup": "NOT_RUN", "build": "NOT_RUN", "errors": []}
    try:
        identity = preflight(repo, source)
        state["setup"] = 0
        write(out / "identity.json", identity)
        result = command(["cargo", "build-dev", "--", "--release"], repo, out / "build.log", 2400)
        state["build"] = result
        assert result["exit"] == 0, "build failed"
        identity["binaries"] = manifest_tree(repo / "target/kani/bin")
        identity["kani_sysroot"] = manifest_tree(repo / "target/kani/lib")
        write(out / "identity.json", identity)
    except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as error:
        state["errors"].append(str(error))
    write(out / "phases.json", state)
    return int(bool(state["errors"]))


def run_cases(repo, source, out, common):
    state = json.loads((out / "phases.json").read_text())
    if state["errors"]:
        return 1
    identity = json.loads((out / "identity.json").read_text())
    # Both builds use their own compiler and driver, and the exact same immutable
    # candidate-built Kani libraries (source library files are identical).
    reference = common / "candidate/identity.json"
    try:
        candidate = json.loads(reference.read_text())
        for key in ("rustc_vV", "rust_sysroot", "tools", "target_spec"):
            assert candidate[key] == identity[key], "tool/sysroot mismatch: " + key
        if source == "baseline":
            libs = repo / "target/kani/lib"
            shutil.rmtree(libs)
            shutil.copytree(repo.parent / "candidate/target/kani/lib", libs, symlinks=True)
        assert manifest_tree(repo / "target/kani/lib") == candidate["kani_sysroot"], "Kani sysroot mismatch"
        identity["effective_kani_sysroot"] = candidate["kani_sysroot"]
        identity["sysroot_origin"] = CANDIDATE
        write(out / "identity.json", identity)
        compiler = repo / "target/kani/bin/kani-compiler"
        compiler.rename(compiler.with_name("kani-compiler.d0-real"))
        # Copy rather than symlink: argv[0]'s directory is the compiler directory.
        shutil.copy2(HERE / "compiler_supervisor.py", compiler)
        shutil.copy2(HERE / "capture_cbmc.py", compiler.parent / "capture_cbmc.py")
        compiler.chmod(0o755)
        shim = out / "shim"
        shim.mkdir()
        (shim / "cbmc").symlink_to(HERE / "capture_cbmc.py")
        for case in (("A", "B", "AB", "BA", "D") if source == "candidate" else ("A", "B", "pair")):
            directory = out / "cases" / case
            directory.mkdir(parents=True)
            selectors = [A] if case == "A" else [B] if case == "B" else [A, B]
            argv = [str(repo / "scripts/kani"), FIXTURE, "-Z", "uninit-checks", "-Z", "unstable-options",
                    "--no-slice-formula", "-Z", "export-json", "--export-json", str(directory / "results.json"),
                    "--output-format", "regular", "--keep-temps", "--target-dir", str(directory / "model"), "--verbose"]
            for harness in selectors:
                argv.extend(["--harness", harness])
            argv.extend(["--exact", "--cbmc-args", "--trace"])
            env = dict(os.environ, RUSTFLAGS="--emit=mir --edition=2021",
                       D0_REAL_CBMC=identity["tools"]["cbmc"]["path"],
                       D0_CAPTURE_DIR=str(directory / "cbmc-private"), PATH=str(shim) + os.pathsep + os.environ["PATH"])
            if source == "candidate":
                env.update(KANI_D0_CASE=case, KANI_D0_DIR=str(directory / "compiler"))
            result = command(argv, repo, directory / "verification.log", 600, env)
            children = [json.loads(p.read_text()) for p in (directory / "compiler-process").glob("*.json")]
            compiles = [row for row in children if row["is_compile"]]
            compile_ok = len(compiles) == 1 and all(row["state"] == "COMPLETE" and row["exit"] == 0
                                                  and row["signal"] is None for row in compiles)
            root_error = None
            try:
                roots = extract_roots(directory, selectors)
            except (OSError, ValueError, TypeError, KeyError, AssertionError) as error:
                roots = "UNKNOWN"
                root_error = str(error)
            write(directory / "phases.json", {"setup": 0, "compiler": compiles or "UNKNOWN",
                  "compiler_ok": compile_ok, "verification": result, "curation": "NOT_RUN",
                  "actual_roots": roots, "root_error": root_error,
                  "explicit_environment": {k: env[k] for k in ("RUSTFLAGS", "D0_REAL_CBMC", "D0_CAPTURE_DIR", "KANI_D0_CASE", "KANI_D0_DIR") if k in env}})
    except (OSError, ValueError, AssertionError, subprocess.SubprocessError) as error:
        state["errors"].append(str(error))
    write(out / "phases.json", state)
    return int(bool(state["errors"]))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("phase", choices=("build", "cases"))
    ap.add_argument("source", choices=("candidate", "baseline"))
    ap.add_argument("repo", type=Path)
    ap.add_argument("output", type=Path)
    args = ap.parse_args()
    repo, root = args.repo.resolve(), args.output.resolve()
    out = root / args.source
    out.mkdir(parents=True, exist_ok=True)
    return prepare(repo, args.source, out) if args.phase == "build" else run_cases(repo, args.source, out, root)


if __name__ == "__main__":
    raise SystemExit(main())
