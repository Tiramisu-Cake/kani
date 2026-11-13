#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Coordinator/CI entry point. Each exact root gets a fresh source/model/export directory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess

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
                   "--keep-temps", "--export-json", str(export), "--output-format=regular",
                   "--cbmc-args", "--object-bits", str(manifest["object_bits"])]
        write_json(work / "input.json", {"root": root, "argv": command,
                   "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest()})
        try:
            # Preserve the real full JSON document, including all failed-property descriptions.
            with (work / "run.log").open("wb") as log:
                exit_code = invoke(command, work, log, manifest["proposed_harness_timeout_s"] + 60)
            data = json.loads(export.read_text())
            observed = observe(data, root, exit_code, (work / "run.log").read_text())
            observed["execution_status"] = "COMPLETED"
            observed["export"] = str(export)
            write_json(work / "observation.json", observed)
            report["roots"].append(observed)
            if observed["expectation_met"] is False:
                errors.append(root["harness"] + ": expected " + root["expected_result"]
                              + " was not observed")
        except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired) as error:
            errors.append(root["harness"] + ": " + str(error))
            report["roots"].append({"harness": root["harness"], "execution_status": "COLLECTION_ERROR",
                                    "error": str(error)})
            # No downstream verifier acceptance after build/export/incomplete-result errors.
            stopped = True
    report["collection_errors"] = errors
    write_json(output / "observations.json", report)
    print("Mode observations saved to", output, "; transformed binding/qualification remains pending")
    for error in errors:
        print(error)
    return int(bool(errors))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kani", default="kani")
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    raise SystemExit(collect(arguments.kani, arguments.output.resolve()))
