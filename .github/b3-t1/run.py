#!/usr/bin/env python3
"""CI only. Run in an expendable Actions checkout, never in a developer tree."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from common import A, B, LOCK_ROOTS, PERF_ROWS, digest, event, execute, write_json
from shim import finish_row


def run(argv, log, cwd, env=None, expected=(0,)):
    log = Path(log)
    log.parent.mkdir(parents=True, exist_ok=True)
    print(f"T1 {os.environ.get('T1_ARM', 'setup')}: {log.name}", flush=True)
    with log.open("wb") as output:
        result = execute(list(map(str, argv)), cwd=cwd, env=env, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode not in expected:
        raise RuntimeError(f"{log.name}: exit {result.returncode} (see artifact)")
    return result.returncode


def value(argv, log, cwd):
    run(argv, log, cwd)
    return Path(log).read_text().strip()


def lock_paths(source):
    paths = {source / root / "Cargo.lock" for root in LOCK_ROOTS}
    # Also retain the checked-in compiler lock; it is not the workspace resolver's lock.
    paths.add(source / "kani-compiler/Cargo.lock")
    return sorted(paths)


def lock_hashes(source):
    return {str(p.relative_to(source)): digest(p) for p in lock_paths(source)}


def check_locks(source, expected):
    actual = lock_hashes(source)
    if actual != expected:
        raise RuntimeError("Cargo.lock drift; comparison invalid")


def collect_arm(arm, source, locks, tools):
    check_locks(source, locks)
    records = {}
    for path in sorted((arm / "records").glob("*.json")):
        data = json.loads(path.read_text())
        if data["key"] in records:
            raise ValueError("duplicate artifact key")
        records[data["key"]] = data["record"]
    rows = {}
    for path in sorted((arm / "rows").glob("*.json")):
        row = json.loads(path.read_text())
        name = row.pop("row")
        if name in rows:
            raise ValueError("duplicate row")
        rows[name] = row
    if set(rows) != set(PERF_ROWS + ["control"]):
        raise ValueError("missing/unexpected perf rows")
    events = [json.loads(p.read_text()) for p in (arm / "events").glob("*.json")]
    if any(e["event"] in {"capture-error", "exception"} for e in events):
        raise ValueError("capture error or exception; inspect command events")
    # A stock script lacks set -e; a failed build must not be hidden by later compiletest output.
    # compiletest reports failed tests with std::process::exit(1) (tools/compiletest/src/main.rs).
    for e in events:
        if e["event"] == "exit" and e["exit"] != 0:
            argv = e["argv"]
            allowed = ("kani" in argv and e["exit"] == 1) or (
                "compiletest" in argv and e["exit"] == 1) or (
                len(argv) > 1 and argv[1].endswith("kani-perf.sh") and e["exit"] == 1) or (
                any(a.endswith("scripts/kani") for a in argv) and e["exit"] == 1)
            if not allowed:
                raise ValueError(f"unexpected failed command: {argv}: {e['exit']}")
    (arm / "locks").mkdir()
    for p in lock_paths(source):
        dest = arm / "locks" / p.relative_to(source)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)
    write_json(arm / "index.json", {"complete": True, "records": records, "rows": rows,
                                   "tools": tools, "locks": locks})


def main(source, out):
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
        raise RuntimeError("CI-only runner requires GitHub Actions Linux")
    bundle = Path(__file__).resolve().parent
    if bundle.is_relative_to(source):
        raise RuntimeError("orchestration must be copied outside switching source tree")
    out.mkdir(parents=True, exist_ok=False)
    os.environ.update(T1_SOURCE=str(source), T1_ARM_DIR=str(out / "setup"), T1_ARM="setup")
    candidate = value(["git", "rev-parse", "HEAD"], out / "setup/ci-candidate.log", source)
    if candidate != os.environ.get("GITHUB_SHA"):
        raise RuntimeError("checkout does not match dispatched CI candidate")
    write_json(out / "setup/bundle-hashes.json", {
        p.name: digest(p) for p in sorted(bundle.iterdir()) if p.is_file()})
    run(["git", "checkout", "--detach", "--force", A], out / "setup/checkout.log", source)
    parent = value(["git", "rev-parse", B + "^"], out / "setup/parent.log", source)
    if parent != A:
        raise RuntimeError("B source parent mismatch")
    # Full history came from actions/checkout; only the stock setup fetches submodules.
    run(["bash", "-o", "pipefail", "scripts/setup/install_rustup.sh"], out / "setup/rustup.log", source)
    os.environ["PATH"] = str(Path.home() / ".cargo/bin") + ":" + os.environ["PATH"]
    run(["bash", "scripts/setup/ubuntu-24.04/install_deps.sh"], out / "setup/deps.log", source)
    env = dict(os.environ, GIT_LFS_SKIP_SMUDGE="1")
    run(["git", "submodule", "update", "--init", "--depth", "1"], out / "setup/submodules.log", source, env)
    expected_s2n = value(["git", "rev-parse", A + ":tests/perf/s2n-quic"], out / "setup/s2n-pin.log", source)
    actual_s2n = value(["git", "rev-parse", "HEAD"], out / "setup/s2n-head.log", source / "tests/perf/s2n-quic")
    if actual_s2n != expected_s2n:
        raise RuntimeError("s2n source identity mismatch")
    real = {name: shutil.which(name) for name in ("cargo", "cbmc", "goto-cc", "goto-instrument", "kissat")}
    if not all(real.values()):
        raise RuntimeError("required backend tools missing")
    write_json(out / "setup/real-tools.json", real)
    for cmd, name in [(["rustc", "-Vv"], "rustc-Vv"), ([real["cbmc"], "--version"], "cbmc-version"),
                      (["uname", "-a"], "uname"), (["nproc"], "nproc"), (["df", "-h"], "df"),
                      (["cat", "/proc/meminfo"], "memory"), (["cat", "/etc/os-release"], "os-release")]:
        run(cmd, out / "setup" / (name + ".log"), source)
    write_json(out / "setup/runner-image.json", {k: os.environ.get(k) for k in (
        "ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA")})
    if os.environ.get("GITHUB_RUN_ATTEMPT") != "1":
        raise RuntimeError("retries/re-runs are outside this one-attempt request")
    shim_dir = bundle / "bin"
    shim_dir.mkdir()
    for name in ("cargo", "cbmc", "goto-cc", "goto-instrument", "kissat"):
        (shim_dir / name).symlink_to(bundle / "shim.py")
    os.environ.update(T1_REAL_CARGO=real["cargo"], T1_REAL_GOTO_CC=real["goto-cc"],
                      T1_REAL_GOTO_INSTRUMENT=real["goto-instrument"],
                      RUST_TEST_THREADS="1", KANI_PERF_TEST_TIMEOUT="2400")
    os.environ["PATH"] = str(shim_dir) + ":" + os.environ["PATH"]
    baseline_locks = None
    backend_hashes = {k: digest(v) for k, v in real.items() if k != "cargo"}
    sysroot = Path(value(["rustc", "--print", "sysroot"], out / "setup/sysroot.log", source))
    std_locks = {str(p.relative_to(sysroot)): digest(p)
                 for p in (sysroot / "lib/rustlib/src").rglob("Cargo.lock")}
    if not std_locks:
        raise RuntimeError("rust-src lock inventory missing")
    write_json(out / "setup/rust-src-locks.json", std_locks)
    for rel in std_locks:
        dest = out / "setup/rust-src-locks" / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sysroot / rel, dest)
    for arm_name, sha in (("A1", A), ("B1", B), ("A2", A)):
        arm = out / arm_name
        os.environ.update(T1_ARM=arm_name, T1_ARM_DIR=str(arm))
        for key in ("T1_ROW", "T1_TARGET"):
            os.environ.pop(key, None)
        run(["git", "checkout", "--detach", "--force", sha], arm / "checkout.log", source)
        if value(["git", "rev-parse", "HEAD"], arm / "source-sha.log", source) != sha:
            raise RuntimeError("arm source revision mismatch")
        # The stock perf cleanup deletes overlay destinations, including checksum.rs.
        # Restore the pinned submodule before copying the same overlays for the next arm.
        run(["git", "checkout", "--detach", "--force", expected_s2n], arm / "s2n-checkout.log", source / "tests/perf/s2n-quic")
        # Both paths, compiler/sysroot caches and every compiletest target are freshly rebuilt.
        for folder in (source / "target", source / "build", source / "t1-control"):
            if folder.exists():
                shutil.rmtree(folder)
        if arm_name == "A1":
            # Only A1 may resolve/download dependencies. This initial release build also
            # fetches build-std dependencies not included by ordinary cargo fetch.
            os.environ["T1_LOCKED"] = "0"
            run(["cargo", "build-dev", "--", "--release"], arm / "bootstrap-release.log", source)
            for i, root in enumerate(LOCK_ROOTS):
                manifest = source / root / "Cargo.toml"
                if not manifest.is_file():
                    raise RuntimeError(f"expected workspace root missing: {root}")
                if not manifest.with_name("Cargo.lock").is_file():
                    run([real["cargo"], "generate-lockfile", "--manifest-path", manifest], arm / f"resolve-{i}.log", source)
                run([real["cargo"], "fetch", "--locked", "--manifest-path", manifest], arm / f"fetch-{i}.log", source)
            baseline_locks = lock_hashes(source)
            for p in lock_paths(source):
                dest = out / "frozen-locks" / p.relative_to(source)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dest)
        else:
            for p in lock_paths(source):
                p.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(out / "frozen-locks" / p.relative_to(source), p)
        os.environ.update(T1_LOCKED="1", CARGO_NET_OFFLINE="true")
        check_locks(source, baseline_locks)
        # Exact stock workload, release build + overlays + compiletest. Expected compiletest
        # failure is retained (shim does not report proofs). No retry/||true/pipe used here.
        run(["bash", "scripts/kani-perf.sh"], arm / "perf.log", source, expected=(1,))
        check_locks(source, baseline_locks)
        control = source / "t1-control"
        control.mkdir()
        shutil.copy2(bundle / "reproducer.rs", control / "main.rs")
        os.environ.update(T1_ROW="control", T1_TARGET=str(control))
        code = run([source / "scripts/kani", control / "main.rs", "--harness", "array_typed_copy", "--keep-temps"],
                   arm / "control.log", source, expected=(1,))
        finish_row("control", control, code)
        os.environ.pop("T1_ROW")
        os.environ.pop("T1_TARGET")
        paths = {"kani-driver": source / "target/kani/bin/kani-driver",
                 "kani-compiler": source / "target/kani/bin/kani-compiler"}
        paths["rustc"] = Path(value(["rustup", "which", "rustc"], arm / "rustc-path.log", source))
        paths["cargo"] = Path(value(["rustup", "which", "cargo"], arm / "cargo-path.log", source))
        tools = {**backend_hashes, **{name: digest(p) for name, p in paths.items()}}
        if {rel: digest(sysroot / rel) for rel in std_locks} != std_locks:
            raise RuntimeError("rust-src Cargo.lock drift")
        tools.update({"rust-src-lock:" + rel: h for rel, h in std_locks.items()})
        if {k: digest(real[k]) for k in backend_hashes} != backend_hashes:
            raise RuntimeError("backend binary drift")
        write_json(arm / "tools.json", {k: {"path": str(v), "sha256": digest(v)} for k, v in {**real, **paths}.items()})
        run(["rustc", "-Vv"], arm / "rustc-Vv.log", source)
        collect_arm(arm, source, baseline_locks, tools)
    os.environ["T1_ARM_DIR"] = str(out / "comparison")
    # Comparator exit 3 means the model/control census awaits explicit structural review.
    return run([sys.executable, bundle / "compare.py", out, real["goto-instrument"]],
               out / "comparison.log", source, expected=(0, 2, 3))


if __name__ == "__main__":
    try:
        sys.exit(main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()))
    except Exception as error:
        if len(sys.argv) > 2:
            write_json(Path(sys.argv[2]) / "INCOMPLETE.json", {"status": "INCOMPLETE", "error": repr(error), "sat": "NOT_RUN"})
        print(f"T1 INCOMPLETE: {error}", file=sys.stderr)
        sys.exit(2)
