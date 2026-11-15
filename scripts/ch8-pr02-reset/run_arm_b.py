#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Run exact SEL1 issue/companion cases and emit a bounded execution receipt."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys


class ResultError(ValueError):
    pass


def validate_export(payload: object, case: dict, context: dict) -> None:
    if context.get("stage") != "B":
        raise ResultError("stage mismatch")
    if context.get("source_sha") != context.get("expected_source_sha"):
        raise ResultError("source SHA mismatch")
    if context.get("source_tree") != context.get("expected_source_tree"):
        raise ResultError("source tree mismatch")
    if context.get("target") != context.get("expected_target"):
        raise ResultError("target mismatch")
    if not isinstance(payload, dict):
        raise ResultError("export root must be an object")
    top_outcome = payload.get("outcome")
    if not isinstance(top_outcome, dict) or top_outcome.get("kind") != "COMPLETED" or payload.get("run_state") != "COMPLETE":
        raise ResultError("export is not a complete run")
    if payload.get("target") != context["expected_target"]:
        raise ResultError("export target mismatch")
    selection = payload.get("harness_selection")
    if not isinstance(selection, dict) or type(selection.get("matched_count")) is not int or selection["matched_count"] != 1:
        raise ResultError("export must select exactly one harness")
    if not isinstance(payload.get("harnesses"), list) or len(payload["harnesses"]) != 1:
        raise ResultError("export must contain exactly one harness")
    harness = payload["harnesses"][0]
    if not isinstance(harness, dict):
        raise ResultError("harness entry must be an object")
    if harness.get("name") != case["name"] or harness.get("file") != case["source_file"]:
        raise ResultError("harness name or normalized source file mismatch")
    if harness.get("is_automatically_generated") is not case["automatic"]:
        raise ResultError("automatic harness identity mismatch")
    outcome = harness.get("outcome")
    if not isinstance(outcome, dict) or outcome.get("kind") != "COMPLETED" or outcome.get("verdict") != "SUCCESS":
        raise ResultError("harness outcome is not completed success")
    summary = payload.get("summary")
    if (not isinstance(summary, dict)
            or any(type(summary.get(key)) is not int for key in ("total", "successful", "failed"))
            or summary.get("total") != 1 or summary.get("successful") != 1 or summary.get("failed") != 0):
        raise ResultError("top-level summary mismatch")


def evaluate_case(exit_code: int | None, output: str, export_path: Path,
                  case: dict, context: dict) -> tuple[bool, str, str | None]:
    if exit_code is None:
        return False, "timeout/NOT_RUN", None
    if exit_code != 0:
        return False, f"nonzero exit {exit_code}", None
    if not export_path.is_file():
        return False, "missing export", None
    try:
        payload = json.loads(export_path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        return False, f"invalid export: {type(exc).__name__}", None
    try:
        validate_export(payload, case, context)
    except (ResultError, AttributeError, TypeError) as exc:
        return False, str(exc), hashlib.sha256(export_path.read_bytes()).hexdigest()
    expected_summary = ("Complete - 1 successfully verified functions, 0 failures, 1 total."
                        if case["automatic"] else
                        "Complete - 1 successfully verified harnesses, 0 failures, 1 total.")
    summaries = [line.strip() for line in output.splitlines()
                 if "VERIFICATION:" in line or line.startswith("Complete -")]
    if expected_summary not in summaries or "VERIFICATION:- SUCCESSFUL" not in summaries:
        return False, "regular output summary mismatch", hashlib.sha256(export_path.read_bytes()).hexdigest()
    return True, "COMPLETED_SUCCESS", hashlib.sha256(export_path.read_bytes()).hexdigest()


def run_case(binary: Path, fixture: Path, out: Path, mode: str, selector: str | None,
             case: dict, context: dict):
    if mode == "autoharness":
        argv = [str(binary), "autoharness", "-Zautoharness", fixture.name,
                "--run-sanity-checks", "-Zunstable-options", "-Zuninit-checks",
                "-Zuninit-checks", "-Z", "export-json", "--export-json",
                str(out), "--harness-timeout", "600s", "--jobs", "1",
                "--output-format=regular"]
    else:
        argv = [str(binary), "-Z", "uninit-checks", fixture.name,
                "--harness", selector, "--exact", "-Z", "export-json",
                "--export-json", str(out), "--harness-timeout", "600s",
                "--jobs", "1", "--output-format=regular", "-Z", "unstable-options"]
    env = {**os.environ, "NO_COLOR": "1"}
    if mode == "autoharness":
        env["RUSTFLAGS"] = "--edition=2021 --cap-lints=warn"
        env["RUST_BACKTRACE"] = "full"
    try:
        result = subprocess.run(argv, cwd=fixture.parent, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=600)
        code = result.returncode
        output = result.stdout
    except subprocess.TimeoutExpired as exc:
        code = None
        raw = exc.stdout or b""
        output = raw.decode(errors="replace") if isinstance(raw, bytes) else raw
    print(output, end="" if output.endswith("\n") else "\n")
    export_ok, result_reason, export_sha = evaluate_case(code, output, out, case, context)
    export_validation_exit = None
    summaries = [line.strip() for line in output.splitlines()
                 if "VERIFICATION:" in line or line.startswith("Complete -")]
    if export_ok:
        validator = binary.parent / "validate_json_export.py"
        validated = subprocess.run([sys.executable, str(validator), str(out)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, timeout=60)
        export_validation_exit = validated.returncode
        if validated.returncode != 0:
            export_ok = False
            result_reason = "JSON schema validation failed"
    expected_summary = ("Complete - 1 successfully verified functions, 0 failures, 1 total."
                        if mode == "autoharness" else
                        "Complete - 1 successfully verified harnesses, 0 failures, 1 total.")
    ok = export_ok
    return {"argv": argv, "exit_code": code, "summary": summaries,
            "expected_summary": expected_summary, "export_json_sha256": export_sha,
            "export_validation_exit": export_validation_exit, "result": result_reason,
            "accepted": ok}


def main() -> int:
    repo, control = map(Path, sys.argv[1:3])
    fixtures = control / "scripts/ch8-pr02-reset/fixtures"
    work = Path(os.environ["RUNNER_TEMP"]) / "ch8-pr02-reset-b"
    work.mkdir(parents=True, exist_ok=True)
    binary = repo / "scripts/kani"
    req = json.loads((control / "CI-REQUEST.json").read_text())
    pin = req["pins"]["sel1"]
    actual_sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    if actual_sha != pin["sha"]:
        raise SystemExit("source checkout SHA mismatch before issue run")
    with tempfile.TemporaryDirectory(prefix="ch8-b-index-") as temp_dir:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(temp_dir) / "index")}
        subprocess.run(["git", "-C", str(repo), "read-tree", "HEAD"], env=env, check=True)
        subprocess.run(["git", "-C", str(repo), "add", "--all"], env=env, check=True)
        actual_tree = subprocess.check_output(["git", "-C", str(repo), "write-tree"], env=env, text=True).strip()
    if actual_tree != pin["patched_tree"]:
        raise SystemExit("source patched tree mismatch before issue run")
    context = {"stage": "B", "source_sha": actual_sha, "source_tree": actual_tree,
               "expected_source_sha": pin["sha"], "expected_source_tree": pin["patched_tree"],
               "target": req["expected_target"], "expected_target": req["expected_target"]}
    cases = [
        ("issue-4854-autoharness", "issue-4854-autoharness.rs", "autoharness", None,
         {"name": "reassemble_ptr_fragments_in_static", "source_file": "issue-4854-autoharness.rs", "automatic": True},
         "8a5b94bfb1af4eca980c1e20358ea66c9ecbc7f3df2b7e4d7b3af43c5c828bd2"),
        ("issue-4854-explicit-proof-companion", "issue-4854-explicit-proof-companion.rs", "proof",
         "explicit_proof_observes_initialized_null",
         {"name": "explicit_proof_observes_initialized_null", "source_file": "issue-4854-explicit-proof-companion.rs", "automatic": False},
         "7b8c87634051e6bb26ba0d0b0a42ebc5b5a8e01ab4878b5c6f227d5d346fc009"),
    ]
    receipts = []
    for case_id, filename, mode, selector, case, expected_sha in cases:
        fixture = fixtures / filename
        digest = hashlib.sha256(fixture.read_bytes()).hexdigest()
        if digest != expected_sha:
            raise SystemExit(f"fixture SHA mismatch for {filename}")
        result = run_case(binary, fixture, work / f"{case_id}.json", mode, selector, case, context)
        receipts.append({"id": case_id, "fixture": filename,
                         "fixture_sha256": digest, "stage": context["stage"],
                         "source_sha": actual_sha, "source_tree": actual_tree,
                        "target": context["target"], "harness_name": case["name"],
                        "normalized_source_file": case["source_file"], **result})
        (work / "result.json").write_text(json.dumps({"schema": "ch8-pr02-reset-b-result-v1",
            "runtime": "IN_PROGRESS", "cases": receipts}, indent=2) + "\n")
        if not result["accepted"]:
            raise SystemExit(f"{case_id}: expected successful completed single-function result")
    (work / "result.json").write_text(json.dumps({"schema": "ch8-pr02-reset-b-result-v1",
        "runtime": "COMPLETED", "cases": receipts}, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
