#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Run six contract-mode regression roots in temporary directories."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile

from observe import observe


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def invoke(command, work, log, timeout):
    with subprocess.Popen(command, cwd=work, stdout=log, stderr=subprocess.STDOUT,
                          start_new_session=True) as process:
        try:
            return process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise


def collect(kani, output):
    suite = Path(__file__).resolve().parent
    manifest = json.loads((suite / "roots.json").read_text())
    output.mkdir(parents=True, exist_ok=False)  # Reject stale evidence.
    report = {"mode_qualification": False, "binding_status": "BINDING_PENDING", "roots": []}
    errors = []
    stopped = False
    for root in manifest["roots"]:
        if stopped:
            report["roots"].append({"harness": root["harness"], "execution_status": "NOT_RUN"})
            continue
        work = output / root["harness"]
        work.mkdir()
        source = work / root["file"]
        shutil.copyfile(suite / root["file"], source)
        export = work / "export.json"
        command = [kani, str(source), "-Z", "uninit-checks",
                   "-Z", "function-contracts", "-Z", "stubbing", "-Z", "export-json",
                   "-Z", "unstable-options", "--exact", "--harness", root["harness"],
                   "--harness-timeout", str(manifest["proposed_harness_timeout_s"]),
                   "--export-json", str(export), "--output-format=regular",
                   "--cbmc-args", "--object-bits", str(manifest["object_bits"])]
        before = hashlib.sha256(source.read_bytes()).hexdigest()
        exit_code = None
        try:
            # Preserve the real full JSON document, including all failed-property descriptions.
            with (work / "run.log").open("wb") as log:
                exit_code = invoke(command, work, log, manifest["proposed_harness_timeout_s"] + 60)
            if (hashlib.sha256(source.read_bytes()).hexdigest() != before
                    or hashlib.sha256((suite / root["file"]).read_bytes()).hexdigest() != before):
                raise ValueError("source changed during invocation")
            data = json.loads(export.read_text())
            observed = observe(data, root, exit_code, (work / "run.log").read_text())
            observed["execution_status"] = "COMPLETED"
            observed["original_exit"] = exit_code
            report["roots"].append(observed)
            if observed["expectation_met"] is False:
                errors.append(root["harness"] + ": expected " + root["expected_result"]
                              + " was not observed")
        except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired) as error:
            errors.append(root["harness"] + ": " + str(error))
            report["roots"].append({"harness": root["harness"], "execution_status": "COLLECTION_ERROR",
                                    "error": str(error), "original_exit": exit_code})
            # No downstream verifier acceptance after build/export/incomplete-result errors.
            stopped = True
    report["collection_errors"] = errors
    write_json(output / "observations.json", report)
    print("Mode observations: " + json.dumps(report), flush=True)
    if errors:
        for root in report["roots"]:
            if root.get("execution_status") == "COLLECTION_ERROR" or root.get("expectation_met") is False:
                log = output / root["harness"] / "run.log"
                if log.exists():
                    for line in log.read_text(errors="replace").splitlines():
                        print(root["harness"] + ": " + line, flush=True)
    for error in errors:
        print(error)
    return int(bool(errors))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kani", default="kani")
    arguments = parser.parse_args(argv)
    with tempfile.TemporaryDirectory(prefix="kani-uninit-contract-modes-") as temporary:
        result = collect(arguments.kani, Path(temporary) / "results")
    return result


if __name__ == "__main__":
    raise SystemExit(main())
