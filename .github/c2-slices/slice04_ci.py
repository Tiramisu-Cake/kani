#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""CI-only exact-head regression runner. No invocation during preparation."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SUMMARY = re.compile(r"test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;")
TEST = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)(?:\b.*)?$", re.M)
COMMANDS = {
    "fmt": ["./scripts/kani-fmt.sh", "--check"],
    "build": ["cargo", "build-dev"],
    "clippy": ["cargo", "clippy", "--workspace", "--tests", "--", "-D", "warnings"],
    "units": ["cargo", "test", "-p", "kani-compiler", "active_call_tests", "--", "--color", "never"],
    "immutable-units": ["cargo", "test", "-p", "kani-compiler", "immutable_allocations::tests", "--", "--color", "never"],
    'argument-size-units': ['cargo', 'test', '-p', 'kani-compiler', 'argument_size_tests', '--', '--color', 'never'],
    'marker-category-units': ['cargo', 'test', '-p', 'kani-compiler', 'marker_category_tests', '--', '--color', 'never'],
}


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(value, indent=2) + "\n")
    temp.replace(path)


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def ci_path(path):
    return path.startswith((".github/workflows/", ".github/c2-slices/"))


def inputs():
    config = json.loads((HERE / "inputs.json").read_text())
    data = (HERE / "test-manifest.json").read_bytes()
    if hashlib.sha256(data).hexdigest() != config["test_manifest_sha256"]:
        raise ValueError("test manifest SHA-256 mismatch")
    manifest = json.loads(data)
    if not isinstance(manifest, dict) or not isinstance(manifest.get("groups"), list):
        raise ValueError("invalid manifest object/groups")
    if manifest["source_sha"] != config["source_sha"]:
        raise ValueError("source-stage-target mismatch")
    return config, manifest


def suites(manifest):
    result = {}
    for group in manifest["groups"]:
        key = (group["suite"], group["mode"])
        entries = result.setdefault(key, {})
        for item in group["selectors"]:
            old = entries.setdefault(item["selector"], item)
            if old != item:
                raise ValueError("conflicting duplicate selector")
    return result


def snapshot(label, out):
    config, _ = inputs()
    source = config["source_sha"]
    head = git("rev-parse", "HEAD").decode().strip()
    parent = git("rev-parse", "HEAD^").decode().strip()
    tree = git("rev-parse", source + "^{tree}").decode().strip()
    changed = git("diff", "--name-only", source, "HEAD").decode().splitlines()
    worktree_status = git("status", "--porcelain=v1", "--untracked-files=normal").decode()
    problems = []
    if worktree_status:
        problems.append("worktree is not clean (including untracked source/test paths)")
    if parent != source or tree != config["source_tree"]:
        problems.append("overlay parent/source tree mismatch")
    if git("rev-parse", source + "^").decode().strip() != config["source_parent"]:
        problems.append("source parent mismatch")
    if any(not ci_path(p) for p in changed):
        problems.append("overlay changes non-CI paths")
    files = []
    for entry in git("ls-tree", "-rz", source).split(b"\0"):
        if not entry:
            continue
        info, raw_path = entry.split(b"\t", 1)
        mode, kind, blob = info.decode().split()
        name = os.fsdecode(raw_path)
        if ci_path(name):
            continue
        path = ROOT / name
        row = {"path": name, "mode": mode, "blob": blob}
        try:
            if kind == "commit":
                initialized = (path / ".git").exists()
                actual = subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"]).decode().strip() if initialized else None
                row.update(initialized=initialized, actual=actual)
                if actual is not None and actual != blob:
                    problems.append("submodule SHA mismatch: " + name)
            else:
                st = path.lstat()
                data = os.fsencode(os.readlink(path)) if stat.S_ISLNK(st.st_mode) else path.read_bytes()
                actual_mode = "120000" if stat.S_ISLNK(st.st_mode) else ("100755" if st.st_mode & 0o111 else "100644")
                actual_blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                row.update(sha256=hashlib.sha256(data).hexdigest(), actual_blob=actual_blob, actual_mode=actual_mode)
                if actual_blob != blob or actual_mode != mode:
                    problems.append("source file mismatch: " + name)
        except OSError as error:
            row["error"] = repr(error)
            problems.append("source file missing/unreadable: " + name)
        files.append(row)
    record = {"label": label, "source_sha": source, "source_tree": tree,
              "overlay_sha": head, "overlay_parent": parent, "files": files,
              "status_porcelain": worktree_status,
              "diff_name_status": git("diff", "--name-status", "HEAD").decode(),
              "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "problems": problems}
    save(out / ("source-" + label + ".json"), record)
    if problems:
        raise ValueError("; ".join(problems))


def check_output(output, expected):
    if expected is None:
        return []
    problems = []
    counts = [tuple(map(int, m)) for m in SUMMARY.findall(output)]
    want = (sum(not ignored for ignored in expected.values()), 0, sum(expected.values()))
    if counts != [want]:
        problems.append(f"native count mismatch/missing: {counts}, expected {[want]}")
    tests = TEST.findall(output)
    found = {name: verdict for name, verdict in tests}
    if len(found) != len(tests) or set(found) != set(expected):
        problems.append("native selected test names mismatch/missing")
    for name, ignored in expected.items():
        if found.get(name) != ("ignored" if ignored else "ok"):
            problems.append("unexpected native result: " + name)
    if "Process timed out after" in output:
        problems.append("native per-fixture timeout")
    return problems


def execute(name, argv, out, expected=None, timeout=None):
    base = out / name
    base.mkdir(parents=True, exist_ok=True)
    record = {"name": name, "argv": argv, "cwd": str(ROOT), "exit": None,
              "termination_reason": "RUNNING", "result": "UNKNOWN", "expected": expected,
              "started_unix": time.time(), "environment": {key: os.environ.get(key) for key in
                  ("RUST_TEST_THREADS", "RUST_BACKTRACE", "KANI_FAIL_ON_UNEXPECTED_DESCRIPTION", "PATH")}}
    save(base / "result.json", record)
    print("START", name, json.dumps(argv), flush=True)
    child = None
    try:
        with (base / "stdout.txt").open("w") as stdout, (base / "stderr.txt").open("w") as stderr:
            child = subprocess.Popen(argv, cwd=ROOT, stdout=stdout, stderr=stderr, start_new_session=True)
            record["exit"] = child.wait(timeout=timeout)
        record["termination_reason"] = "SIGNAL" if record["exit"] < 0 else "EXIT"
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        record["termination_reason"] = "TIMEOUT" if isinstance(error, subprocess.TimeoutExpired) else "INTERRUPTED"
        record["exception"] = repr(error)
        if child is not None:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGKILL)
            record["exit"] = child.wait()
    except OSError as error:
        record.update(termination_reason="LAUNCH_ERROR", exception=repr(error))
    output = "\n".join((base / p).read_text(errors="replace") if (base / p).exists() else "" for p in ("stdout.txt", "stderr.txt"))
    record["native_counts"] = [list(map(int, m)) for m in SUMMARY.findall(output)]
    record["native_tests"] = TEST.findall(output)
    record["problems"] = check_output(output, expected)
    good = record["exit"] == 0 and record["termination_reason"] == "EXIT" and not record["problems"]
    record["result"] = "EXIT_ZERO_COUNTS_MATCH_REQUIRES_REVIEW" if good else "FAIL_OR_UNKNOWN"
    record["finished_unix"] = time.time()
    save(base / "result.json", record)
    print("END", name, record["result"], record["exit"], record["problems"], flush=True)
    if record["termination_reason"] == "INTERRUPTED":
        raise KeyboardInterrupt()
    return good


def main():
    out = Path(os.environ["C2_EVIDENCE_DIR"]).resolve()
    action = sys.argv[1]
    config, manifest = inputs()
    if action in ("before", "after"):
        snapshot(action, out)
        if action == "before":
            save(out / "inputs.json", config)
            save(out / "test-manifest.json", manifest)
            for name in [*COMMANDS, *("suite-" + s for s, _ in suites(manifest))]:
                save(out / name / "result.json", {"name": name, "result": "NOT_RUN", "exit": None, "termination_reason": "NOT_STARTED"})
        return
    if action in COMMANDS:
        expected = None
        if action == "units":
            expected = {"kani_middle::points_to::points_to_analysis::active_call_tests::" + n: False for n in manifest["active_call_units"]}
        elif action == "immutable-units":
            expected = {"codegen_cprover_gotoc::context::immutable_allocations::tests::" + n: False for n in manifest["immutable_unit_names"]}
        elif action in config["additional_units"]:
            expected = {n: False for n in config["additional_units"][action]["native_names"]}
        good = execute(action, COMMANDS[action], out, expected)
    elif action == "suites":
        good = True
        for (suite, mode), selectors in suites(manifest).items():
            name = "suite-" + suite
            argv = ["cargo", "run", "-p", "compiletest", "--quiet", "--", "--suite", suite, "--mode", mode,
                    "--build-base", str(out / "build-tests" / suite), "--logfile", str(out / (name + ".native.log")),
                    "--color", "never", "--exact", "--force-rerun", "--no-fail-fast", "--timeout", "2400", *selectors]
            expected = {n: s["existing_path_ignore"] for n, s in selectors.items()}
            result = execute(name, argv, out, expected)
            good = result and good
    else:
        raise ValueError("unknown action: " + action)
    if not good:
        sys.exit(1)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        if os.environ.get("C2_EVIDENCE_DIR"):
            save(Path(os.environ["C2_EVIDENCE_DIR"]) / "runner-errors" / (sys.argv[1] + ".json"),
                 {"result": "FAIL_OR_UNKNOWN", "termination_reason": "RUNNER_ERROR", "exception": repr(error)})
        raise
