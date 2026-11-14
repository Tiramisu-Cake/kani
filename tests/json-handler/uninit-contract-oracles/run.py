#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Run eight exact JSON regression oracles in temporary directories."""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import checker

HERE = Path(__file__).resolve().parent


def command(case, directory):
    return ["kani", str(checker.ROOT / case["input"]),
            "-Z", "uninit-checks", "-Z", "function-contracts", "-Z", "export-json",
            "-Z", "unstable-options", "--harness", case["root"], "--exact", "--jobs", "1",
            "--target-dir", str(directory / "target"),
            "--export-json", str(directory / "export.json"), "--output-format=regular",
            "--cbmc-args", "--object-bits", "12"]


def execute_case(case, parent):
    directory = Path(tempfile.mkdtemp(prefix=case["id"] + "-", dir=parent))
    source = checker.ROOT / case["input"]
    before = checker.sha256(source)
    checker.require(before == case["sha256"], "source hash differs before invocation")
    argv = command(case, directory)
    env = os.environ.copy()
    env["RUSTFLAGS"] = "--edition 2021 -D warnings"
    env["NO_COLOR"] = "1"
    receipt = {"input": case["input"], "root": case["root"], "input_sha256": before,
               "build_prefix": str(checker.ROOT), "cwd": str(checker.ROOT), "started_epoch": time.time(),
               "original_exit": None, "timed_out": False, "error": None}
    with (directory / "regular.out").open("wb") as output:
        try:
            # The existing coordinator/CI capture owns process watchdogs.
            # The JSON exporter relativizes source paths against Kani's cwd.
            # Keep them checkout-relative; outputs remain invocation-specific.
            result = subprocess.run(argv, cwd=checker.ROOT, env=env,
                                    stdout=output, stderr=subprocess.STDOUT, check=False)
            receipt["original_exit"] = result.returncode
        except subprocess.TimeoutExpired as error:
            receipt["timed_out"] = True
            receipt["error"] = repr(error)
        except OSError as error:
            receipt["error"] = repr(error)
    receipt["finished_epoch"] = time.time()
    receipt["input_sha256_after"] = checker.sha256(source)
    receipt["regular_sha256"] = checker.sha256(directory / "regular.out")
    export = directory / "export.json"
    receipt["export_sha256"] = checker.sha256(export) if export.exists() else None
    observation = {"case": case["id"], "status": "FAIL"}
    data = None
    try:
        checker.require(before == receipt["input_sha256_after"], "source changed during invocation")
        data = checker.load_export(export)
        observation["status"] = checker.check_directory(directory, case, receipt)
    except (checker.Rejected, OSError, ValueError, KeyError, TypeError) as error:
        observation.update(status="FAIL", reason=str(error))
    # compiletest parses lines beginning with '{' as rustc diagnostics.
    print("Oracle observation: " + json.dumps(observation), flush=True)
    if observation["status"] != "PASS":
        print(f"Original exit: {receipt['original_exit']}; process error: {receipt['error']}",
              flush=True)
        for line in (directory / "regular.out").read_text(errors="replace").splitlines():
            print("Kani output: " + line, flush=True)
    stop = case["id"] == "lawful-modifies" and reached_unsupported(data)
    return observation["status"], stop


def reached_unsupported(data):
    if not isinstance(data, dict) or not isinstance(data.get("harnesses"), list):
        return False
    for h in data["harnesses"]:
        if not isinstance(h, dict) or not isinstance(h.get("unsupported_constructs"), list):
            continue
        if any(isinstance(p, dict) and p.get("status") in checker.REACHED_UNSUPPORTED
               for p in h["unsupported_constructs"]):
            return True
    return False


def main():
    manifest = checker.load_export(HERE / "oracles.json")
    cases = manifest["cases"]
    checker.require(len(cases) == 8 and len({c["id"] for c in cases}) == 8,
                    "exact eight-case manifest required")
    # All input hashes are checked before spending any verifier resources.
    for case in cases:
        checker.require(checker.sha256(checker.ROOT / case["input"]) == case["sha256"],
                        f"wrong source: {case['id']}")
    with tempfile.TemporaryDirectory(prefix="kani-uninit-contract-oracles-") as parent:
        statuses = []
        for case in cases:
            status, stop = execute_case(case, parent)
            statuses.append(status)
            if stop:
                print("STOP: lawful-modifies reached Unsupported", flush=True)
                break
        return 0 if len(statuses) == 8 and all(status == "PASS" for status in statuses) else 1


if __name__ == "__main__":
    sys.exit(main())
