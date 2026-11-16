#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Exercise collector failures using synthetic data and Python subprocesses."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("confirm", Path(__file__).with_name("confirm.py"))
confirm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(confirm)


def export(failure=False):
    failed = ([{"description": confirm.UNINIT + " of type `u8`", "status": "FAILURE"}]
              if failure else [])
    return {"schema_version": "0.1.0", "run_state": "COMPLETE", "outcome": {"kind": "COMPLETED"},
            "harness_selection": {"unmatched_filters": []},
            "harnesses": [{"name": "check", "is_automatically_generated": False,
                           "outcome": {"kind": "COMPLETED", "verdict": "FAILURE" if failure else "SUCCESS"},
                           "n_properties": 1, "n_failed": len(failed), "failed_properties": failed,
                           "unsupported_constructs": [],
                           "checks": {"total": 1, "undetermined": [], "error": [], "unknown": [], "other": []}}]}


def rejects(data, names=("check",), code=0):
    try:
        confirm.completed(data, names, code)
    except (ValueError, KeyError, TypeError):
        return
    raise AssertionError("malformed or mismatched result was accepted")


good = export()
assert confirm.completed(good, ["check"], 0)["check"]["verdict"] == "SUCCESS"
bad = export(True)
assert confirm.uninit_failure(confirm.completed(bad, ["check"], 1)["check"])
rejects(good, code=1)
rejects(good, names=["different_target"])
for state in ("PARTIAL", "INCOMPLETE", "NO_HARNESSES_SELECTED", "NOT_RUN", None, 3):
    value = copy.deepcopy(good)
    value["run_state"] = state
    rejects(value)
for value in (None, [], {}, {"schema_version": None}, "SUCCESS"):
    rejects(value)
for key, value in (("harnesses", None), ("harnesses", []), ("harnesses", "check"),
                   ("outcome", None), ("harness_selection", None)):
    data = copy.deepcopy(good)
    data[key] = value
    rejects(data)
for key, value in (("outcome", {"kind": "TIMEOUT"}), ("outcome", {"kind": "CRASHED"}),
                   ("failed_properties", [None]), ("unsupported_constructs", [{}]),
                   ("is_automatically_generated", True), ("checks", {"total": None}),
                   ("checks", None)):
    data = copy.deepcopy(good)
    data["harnesses"][0][key] = value
    rejects(data)

with tempfile.TemporaryDirectory() as directory:
    cwd = Path(directory)
    record = confirm.execute([sys.executable, "-c", "print('success')"], cwd, 2)
    assert record["exit"] == 0 and record["termination"] == "EXITED"
    record = confirm.execute([sys.executable, "-c", "raise SystemExit(7)"], cwd, 2)
    assert record["exit"] == 7 and record["termination"] == "EXITED"
    record = confirm.execute([sys.executable, "-c", "import time; time.sleep(10)"], cwd, 0.02)
    assert record["exit"] < 0 and record["termination"] == "TIMEOUT"
    record = confirm.execute([str(cwd / "missing-command")], cwd, 2)
    assert record["exit"] is None and record["termination"] == "SPAWN_ERROR"
    for content in (None, "null", "{}", '{"run_state":"PARTIAL"}', '"NOT_RUN"'):
        def fake(argv, workdir, timeout):
            if content is not None:
                Path(argv[argv.index("--export-json") + 1]).write_text(content)
            return {"exit": 0, "termination": "EXITED", "output_excerpt": ""}
        with tempfile.TemporaryDirectory(dir=cwd) as scratch, patch.object(confirm, "execute", fake):
            row = {"id": "F2", "file": "unused.rs", "names": ["check"]}
            assert confirm.native(row, Path(scratch))["classification"] == "INCONCLUSIVE"
    for message, classification in (
        ("thread 'rustc' has overflowed its stack", "DEFECT_PRESENT"),
        ("compiler exited with status 1", "INCONCLUSIVE"),
        ("Checking harness check...\nthread 'main' has overflowed its stack", "INCONCLUSIVE"),
    ):
        def crash(argv, workdir, timeout):
            return {"exit": 1, "termination": "EXITED", "output_excerpt": message}
        with tempfile.TemporaryDirectory(dir=cwd) as scratch, patch.object(confirm, "execute", crash):
            row = {"id": "F3", "file": "unused.rs", "names": ["check"]}
            assert confirm.native(row, Path(scratch))["classification"] == classification

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=root, stderr=subprocess.STDOUT).decode().strip()
    def commit(*args):
        git("-c", "user.name=Collector test", "-c", "user.email=test@example.invalid",
            "commit", "-q", "--no-gpg-sign", *args, "-m", "Synthetic identity check")
        return git("rev-parse", "HEAD")
    git("init", "-q")
    (root / "README.md").write_text("stock\n")
    git("add", ".")
    base = commit()
    source = root / ".github/workflows/probe.yml"
    source.parent.mkdir(parents=True)
    source.write_text("control\n")
    git("add", ".")
    control = commit()
    with patch.object(confirm, "ROOT", root), patch.object(confirm, "BASE", base), \
            patch.object(confirm, "OUT", root / "evidence"):
        assert confirm.snapshot("control")
        commit("--allow-empty")
        assert confirm.snapshot("trigger")
        assert json.loads((root / "evidence/source-trigger.json").read_text())["control"] == control
        git("checkout", "-q", control)
        source.write_text("different tree\n")
        git("add", ".github")
        commit()
        assert not confirm.snapshot("changed-trigger")

print(json.dumps({"status": "PASS", "checks": ["completed success and failure", "original exits",
    "timeouts", "spawn errors", "partial and missing exports", "null and wrong types",
    "NOT_RUN", "unsupported constructs", "source-stage-target selection mismatch",
    "compiler stack overflow versus generic or verification-stage crash",
    "stock-based control and single same-tree trigger child; changed-tree rejection"]}))
