#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Collect compact results for the stock-compiler correctness probes."""

import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
BASE = "0aac16ef62da9e9d5645782d458593e5d78143ba"
UNINIT = "Undefined Behavior: Reading from an uninitialized pointer"
OUT = Path(os.environ.get("CONFIRM_EVIDENCE_DIR", "/tmp/confirm-main-evidence"))


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT).decode().strip()


def snapshot(label):
    changed = git("diff", "--name-only", BASE, "HEAD").splitlines()
    allowed = (".github/workflows/", ".github/confirm-main/",
               "tests/expected/uninit/pattern-offset/",
               "tests/expected/uninit/recursive-delayed/",
               "tests/script-based-pre/autoharness-uninit-padding/",
               "tests/script-based-pre/delayed-harness-order/")
    problems = [p for p in changed if not p.startswith(allowed)]
    if git("diff", "HEAD", "--"):
        problems.append("tracked working files changed")
    control = git("rev-parse", "HEAD")
    if git("rev-parse", "HEAD^") != BASE:
        control = git("rev-parse", "HEAD^")
        if (git("rev-parse", "HEAD^^") != BASE
                or git("rev-parse", "HEAD^{tree}") != git("rev-parse", "HEAD^^{tree}")):
            problems.append("expected stock-based control or one same-tree trigger child")
    # New compiler/library files can change module resolution without a tracked diff.
    untracked = git("ls-files", "--others", "--exclude-standard").splitlines()
    problems.extend("untracked source: " + p for p in untracked
                    if p.endswith((".rs", ".toml", ".py", ".sh", ".yml")))
    binaries = {}
    for path in (ROOT / "target/kani/bin").glob("*"):
        if path.is_file():
            binaries[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    value = {"base": BASE, "base_tree": git("rev-parse", BASE + "^{tree}"),
             "head": git("rev-parse", "HEAD"), "tree": git("rev-parse", "HEAD^{tree}"),
             "control": control,
             "changed_paths": changed, "problems": problems, "binaries_sha256": binaries}
    save(OUT / ("source-" + label + ".json"), value)
    return not problems


def execute(argv, cwd, timeout):
    started = time.monotonic()
    record = {"argv": argv, "cwd": str(cwd), "timeout_seconds": timeout,
              "exit": None, "termination": "NOT_RUN",
              "environment": {name: os.environ.get(name) for name in (
                  "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "KANIFLAGS", "KANI_LOG",
                  "RUST_BACKTRACE", "NO_COLOR")}}
    text = ""
    with tempfile.TemporaryFile() as log:
        try:
            proc = subprocess.Popen(argv, cwd=cwd, stdout=log, stderr=subprocess.STDOUT,
                                    start_new_session=True)
            try:
                record["exit"] = proc.wait(timeout=timeout)
                record["termination"] = "EXITED"
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                record["exit"] = proc.wait()
                record["termination"] = "TIMEOUT"
        except OSError as error:
            record["termination"] = "SPAWN_ERROR"
            record["error"] = str(error)
        log.seek(0)
        digest = hashlib.sha256()
        size = 0
        head = b""
        tail = b""
        for chunk in iter(lambda: log.read(65536), b""):
            digest.update(chunk)
            size += len(chunk)
            head = (head + chunk)[:4096]
            tail = (tail + chunk)[-8192:]
        record.update(output_bytes=size, output_sha256=digest.hexdigest())
        text = (head + (b"\n[output excerpt]\n" if size > 12288 else b"\n") + tail).decode(errors="replace")
    record["elapsed_seconds"] = round(time.monotonic() - started, 3)
    record["output_excerpt"] = text
    return record


def completed(data, names, code, automatic=False):
    if not isinstance(data, dict) or data.get("schema_version") != "0.1.0":
        raise ValueError("missing or unsupported export schema")
    if data.get("run_state") != "COMPLETE" or data.get("outcome") != {"kind": "COMPLETED"}:
        raise ValueError("incomplete native run")
    selection = data.get("harness_selection")
    if not isinstance(selection, dict) or selection.get("unmatched_filters") != []:
        raise ValueError("unmatched or missing harness selection")
    harnesses = data.get("harnesses")
    if not isinstance(harnesses, list) or len(harnesses) != len(names):
        raise ValueError("wrong harness count")
    result = {}
    for harness in harnesses:
        if not isinstance(harness, dict) or not isinstance(harness.get("name"), str):
            raise ValueError("invalid harness object")
        name = harness["name"].rsplit("::", 1)[-1]
        if name in result or name not in names:
            raise ValueError("wrong or duplicate harness name")
        if harness.get("is_automatically_generated") is not automatic:
            raise ValueError("wrong harness kind")
        outcome = harness.get("outcome")
        if outcome not in ({"kind": "COMPLETED", "verdict": "SUCCESS"},
                           {"kind": "COMPLETED", "verdict": "FAILURE"}):
            raise ValueError("nonterminal harness")
        checks = harness["checks"]
        if (not isinstance(checks, dict) or type(checks.get("total")) is not int
                or checks["total"] <= 0 or type(harness.get("n_properties")) is not int
                or harness["n_properties"] < checks["total"]):
            raise ValueError("missing properties")
        for key in ("undetermined", "error", "unknown", "other"):
            if checks.get(key) != []:
                raise ValueError("incomplete property status")
        if harness.get("unsupported_constructs") != []:
            raise ValueError("unsupported construct")
        failed = harness["failed_properties"]
        if (not isinstance(failed, list) or any(not isinstance(p, dict) for p in failed)
                or harness.get("n_failed") != len(failed)):
            raise ValueError("inconsistent failed property count")
        if bool(failed) != (outcome["verdict"] == "FAILURE"):
            raise ValueError("inconsistent verdict")
        result[name] = {"verdict": outcome["verdict"], "checks_total": checks["total"],
                        "n_properties": harness["n_properties"], "failed_properties": failed}
    expected_exit = int(any(h["verdict"] == "FAILURE" for h in result.values()))
    if code != expected_exit:
        raise ValueError("original exit disagrees with verification results")
    return result


def uninit_failure(harness):
    failed = harness["failed_properties"]
    return (harness["verdict"] == "FAILURE" and bool(failed)
            and all(p.get("status") == "FAILURE" and p.get("description", "").startswith(UNINIT)
                    for p in failed))


def native(row, scratch):
    target = scratch / row["id"]
    target.mkdir()
    export = target / "export.json"
    argv = [str(ROOT / "scripts/kani"), *row.get("prefix", []), str(ROOT / row["file"]),
            "-Z", "uninit-checks", "-Z", "export-json", "--export-json", str(export),
            "--output-format=regular", "--target-dir", str(target / "target"),
            *row.get("flags", [])]
    record = execute(argv, ROOT, 180)
    record.update(id=row["id"], classification="INCONCLUSIVE", harnesses={})
    try:
        if record["termination"] != "EXITED":
            raise ValueError("native process did not exit normally")
        if (row["id"] == "F3" and record["exit"] not in (None, 0)
                and not export.exists() and "Checking harness" not in record["output_excerpt"]
                and re.search(r"thread ['\"](?:rustc|main|<unnamed>)['\"] has overflowed its stack",
                              record["output_excerpt"])):
            record["classification"] = "DEFECT_PRESENT"
            return record
        data = json.loads(export.read_text())
        record["export_sha256"] = hashlib.sha256(export.read_bytes()).hexdigest()
        result = completed(data, row["names"], record["exit"], row.get("automatic", False))
        record["harnesses"] = result
        if row["id"] == "F1":
            good, bad = result["read_data"], result["read_padding"]
            if good["verdict"] != "SUCCESS":
                raise ValueError("initialized-byte control failed")
            record["classification"] = ("DEFECT_PRESENT" if bad["verdict"] == "SUCCESS" else
                                        "DEFECT_ABSENT_FOR_TEST" if uninit_failure(bad) else "INCONCLUSIVE")
        else:
            harness = next(iter(result.values()))
            if row["id"] == "F2" and harness["verdict"] == "SUCCESS":
                record["classification"] = "DEFECT_PRESENT"
            elif uninit_failure(harness):
                record["classification"] = "CONTROL_PASS" if row["id"] == "padding-control" else "DEFECT_ABSENT_FOR_TEST"
    except (ValueError, KeyError, TypeError, OSError) as error:
        record["error"] = str(error)
    return record


ROWS = [
    {"id": "padding-control", "file": "tests/expected/uninit/access-padding-uninit/access-padding-uninit.rs",
     "names": ["check_uninit_padding"]},
    {"id": "F1", "file": "tests/script-based-pre/autoharness-uninit-padding/fixture.rs",
     "names": ["read_data", "read_padding"], "prefix": ["autoharness", "-Z", "autoharness"],
     "automatic": True, "flags": ["--include-pattern", "::read_(data|padding)$"]},
    {"id": "F2", "file": "tests/expected/uninit/pattern-offset/pattern-offset.rs",
     "names": ["read_requires_nonnull_at_nonzero_offset"]},
    {"id": "F3", "file": "tests/expected/uninit/recursive-delayed/recursive-delayed.rs",
     "names": ["recursive_call_reached_from_delayed_ub"], "flags": ["-Z", "ghost-state"]},
]


def run():
    OUT.mkdir(parents=True, exist_ok=True)
    # Stack-overflow reproduction can terminate the compiler with SIGABRT.
    import resource
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    records = []
    with tempfile.TemporaryDirectory(prefix="confirm-main-") as directory:
        for row in ROWS:
            record = native(row, Path(directory))
            records.append(record)
            save(OUT / (row["id"] + ".json"), record)
            print(row["id"], record["classification"], flush=True)
    f4 = execute(["bash", "test.sh"], ROOT / "tests/script-based-pre/delayed-harness-order", 900)
    f4.update(id="F4", classification="INCONCLUSIVE")
    receipt = OUT / "F4-native.json"
    if receipt.exists():
        try:
            data = json.loads(receipt.read_text())
            f4["native"] = data
            expected_exits = {"DEFECT_PRESENT": 1, "DEFECT_ABSENT_FOR_TEST": 0, "INCONCLUSIVE": 2}
            classification = data.get("classification")
            if (classification in expected_exits and f4["termination"] == "EXITED"
                    and f4["exit"] == expected_exits[classification]):
                f4["classification"] = classification
        except (ValueError, KeyError, OSError):
            pass
    save(OUT / "F4.json", f4)
    records.append(f4)
    print("F4", f4["classification"], flush=True)
    control_ok = records[0]["classification"] == "CONTROL_PASS"
    if not control_ok:
        for record in records[1:]:
            record["classification"] = "INCONCLUSIVE"
            record["control_error"] = "explicit-padding control did not pass"
            save(OUT / (record["id"] + ".json"), record)
    summary = {r["id"]: r["classification"] for r in records}
    save(OUT / "summary.json", summary)
    return int(not control_ok or "INCONCLUSIVE" in summary.values())


def finish():
    clean = snapshot("after")
    summary = {}
    for name in ("padding-control", "F1", "F2", "F3", "F4"):
        path = OUT / (name + ".json")
        if not path.exists():
            save(path, {"id": name, "classification": "INCONCLUSIVE", "termination": "NOT_RUN",
                        "exit": None, "job_status": os.environ.get("CONFIRM_JOB_STATUS")})
        value = json.loads(path.read_text())
        if not clean:
            value["classification"] = "INCONCLUSIVE"
            value["source_error"] = "source identities changed"
            save(path, value)
        summary[name] = value["classification"]
    save(OUT / "summary.json", summary)
    return int(not clean or "INCONCLUSIVE" in summary.values())


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] in ("before", "after"):
        sys.exit(0 if snapshot(sys.argv[1]) else 1)
    if len(sys.argv) == 2 and sys.argv[1] == "run":
        sys.exit(run())
    if len(sys.argv) == 2 and sys.argv[1] == "finish":
        sys.exit(finish())
    sys.exit("usage: confirm.py before|run|after|finish")
