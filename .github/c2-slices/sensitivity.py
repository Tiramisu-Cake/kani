#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""CI-only Kani oracle sensitivity checks; never run while preparing a patch."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

HERE = Path(__file__).resolve().parent
MANIFEST_PATH = HERE / "sensitivity-manifest.json"
VARIANT_IDS = {
    "positive-remove-useful-assertion",
    "negative-extra-reached-failure",
    "negative-repair-user-write",
    "golden-invert-required-count",
}
SOURCE_SHA = "3f5242bb1539fb88196d7e503b722f0905f2b46c"
TEST_LINE = re.compile(r"^test (.+?) \.\.\. (ok|FAILED|ignored)(?:\b.*)?$", re.M)
TEST_SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
    re.M,
)
NATIVE_SUMMARY = re.compile(
    r"^SUMMARY:\r?\n[ \t]*\*\* (\d+) of (\d+) failed(?: \((\d+) unreachable\))?\s*$", re.M
)
VERIFICATION = re.compile(r"^VERIFICATION:- (SUCCESSFUL|FAILED)$", re.M)
STATUS_FOR_DESCRIPTION = re.compile(
    r"^[ \t]*- Status: (SUCCESS|FAILURE)\r?\n[ \t]*- Description: \"([^\r\n]*)\"[ \t]*$", re.M
)
COMPLETION = re.compile(
    r"^Complete - (\d+) successfully verified harnesses, (\d+) failures, (\d+) total\.$",
    re.M,
)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _load_manifest(expected_sha):
    raw = MANIFEST_PATH.read_bytes()
    if _sha(raw) != expected_sha:
        raise ValueError("sensitivity manifest SHA-256 mismatch")
    manifest = json.loads(raw)
    variants = manifest.get("variants") if isinstance(manifest, dict) else None
    if (not isinstance(variants, list) or len(variants) != 4
            or {v.get("id") for v in variants} != VARIANT_IDS):
        raise ValueError("sensitivity manifest variant set mismatch")
    if manifest.get("execution") != "NOT_RUN":
        raise ValueError("sensitivity reference manifest is not a prepared input")
    return manifest, variants


def _require_clean_suite(out):
    result_path = out / "suite-expected" / "result.json"
    if not result_path.is_file():
        raise ValueError("clean expected suite result is missing")
    result = json.loads(result_path.read_text())
    if (result.get("exit") != 0 or result.get("termination_reason") != "EXIT"
            or result.get("result") != "EXIT_ZERO_COUNTS_MATCH_REQUIRES_REVIEW"
            or result.get("problems")):
        raise ValueError("clean expected suite did not pass the recorded gate")


def _git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def _variant_expectation(variant, native):
    """Check the complete native transcript and the specific oracle mutation."""
    problems = []
    n = variant["predicted_native_N"]
    verdict = variant["predicted_native_verdict"]
    summaries = NATIVE_SUMMARY.findall(native)
    verifications = VERIFICATION.findall(native)
    completions = COMPLETION.findall(native)
    if len(summaries) != 1 or int(summaries[0][0]) != n:
        problems.append(f"native SUMMARY count missing/partial/unexpected: {summaries}, expected N={n}")
    want_verification = "SUCCESSFUL" if verdict == "SUCCESS" else "FAILED"
    if verifications != [want_verification]:
        problems.append(f"native VERIFICATION missing/partial/unexpected: {verifications}, expected {[want_verification]}")
    if len(completions) != 1:
        problems.append("native completion record missing or duplicated")
    else:
        successful, failures, total = map(int, completions[0])
        if successful + failures != total or total != 1:
            problems.append("native completion totals do not match the predicted completed harness result")
        if (verdict == "SUCCESS" and failures != 0) or (verdict == "FAILURE" and failures == 0):
            problems.append("native harness completion verdict contradicts VERIFICATION")
    if native.count("SUMMARY:") != 1:
        problems.append("native SUMMARY section missing, partial, or duplicated")
    if re.search(r"UNDETERMINED", native, re.I):
        problems.append("native output contains an undetermined verdict")

    ident = variant["id"]
    status_rows = STATUS_FOR_DESCRIPTION.findall(native)
    if ident == "positive-remove-useful-assertion":
        if "lawful_modifies_preserves_outside.assertion.3" in native:
            problems.append("removed useful assertion still appears in native output")
        if "lawful_modifies_preserves_outside.assertion.2" not in native:
            problems.append("neighboring lawful assertion evidence is missing")
    elif ident == "negative-extra-reached-failure":
        if "Check that *var_7 is assignable" not in native or "s5 independent reached failure" not in native:
            problems.append("original outside-assigns failure or added reached failure was not retained")
        if ("FAILURE", "Check that *var_7 is assignable") not in status_rows:
            problems.append("original outside-assigns check is not recorded as a native failure")
        if ("FAILURE", '"s5 independent reached failure"') not in status_rows:
            problems.append("added reached failure is not recorded as a native failure")
    elif ident == "negative-repair-user-write":
        # Removing *outside renumbers MIR locals (accepted run43715788377).
        # Bind detection to completed SUCCESS/N=0 and the intended golden
        # mismatch below; ephemeral var_N labels are not semantic identities.
        assignable = [(status, desc) for status, desc in status_rows
                      if re.fullmatch(r"Check that \*var_\d+ is assignable", desc)]
        if any(status == "FAILURE" for status, _ in assignable):
            problems.append("repaired user write still reports an assignability failure")
        if not any(status == "SUCCESS" for status, _ in assignable):
            problems.append("permitted out-write check is missing")
    elif ident == "golden-invert-required-count":
        if n != 0 or "** 1 of" in native:
            problems.append("golden inversion did not conflict with completed native N=0")
    return problems


def _validate_compiletest(record, selector, stdout, stderr, native, native_stderr, variant):
    problems = []
    combined = stdout + "\n" + stderr
    all_output = combined + "\n" + native + "\n" + native_stderr
    if record.get("exit") != 1 or record.get("termination_reason") != "EXIT":
        problems.append("compiletest did not complete with the predicted mismatch exit 1")
    test_rows = TEST_LINE.findall(combined)
    summaries = TEST_SUMMARY.findall(combined)
    if test_rows != [(selector, "FAILED")]:
        problems.append(f"selected compiletest verdict missing or unrelated: {test_rows}")
    if summaries != [("FAILED", "0", "1", "0")]:
        problems.append(f"compiletest native test summary missing/partial/unexpected: {summaries}")
    if "test failed: expected output to contain the line(s):" not in combined:
        problems.append("compiletest did not report the intended expected-output mismatch")
    if variant["id"] == "positive-remove-useful-assertion" and "lawful_modifies_preserves_outside.assertion.3" not in combined:
        problems.append("compiletest mismatch does not identify the removed useful assertion")
    if variant["id"] == "negative-extra-reached-failure" and "** 1 of" not in combined:
        problems.append("compiletest mismatch does not identify the original required SUMMARY count")
    if variant["id"] == "negative-repair-user-write" and not (
            "Check that *var_7 is assignable" in combined and "Status: FAILURE" in combined):
        problems.append("compiletest mismatch does not identify the removed outside-assigns failure")
    if variant["id"] == "golden-invert-required-count" and "** 1 of" not in combined:
        problems.append("compiletest mismatch does not identify the inverted golden count")
    if re.search(r"\bUnsupported\b", all_output, re.I):
        problems.append("compiletest output contains Unsupported")
    if re.search(r"Process timed out after|timed out|timeout", all_output, re.I):
        problems.append("compiletest/native output indicates a timeout")
    if re.search(r"error:\s*(?:could not compile|failed to compile)|error\[E\d+\]|rustc[^\n]*error|could not compile|failed to compile",
                 combined, re.I) or re.search(r"\berror(?:\[[Ee]\d+\])?:", native_stderr, re.I):
        problems.append("compiletest output indicates a compile/setup error")
    if not native:
        problems.append("retained per-fixture Kani .out is missing/empty")
    problems.extend(_variant_expectation(variant, native))
    return problems


def _native_output_path(build_base, variant):
    # compiletest expected-mode outputs use build-base/<test-relative-dir>/<stem>/<stem>.out.
    relative = Path(variant["input"])
    if relative.parts[:2] != ("tests", "expected"):
        raise ValueError("variant input is outside tests/expected")
    relative = Path(*relative.parts[2:])
    return build_base / relative.parent / relative.stem / (relative.stem + ".out")


def run_sensitivity(ci, out):
    """Run four independent test/golden mutants after the clean expected-suite gate.

    `ci` is the accepted slice04 runner module (execute/save/snapshot/inputs).
    Mutated test bytes and mode are restored even when execution or parsing fails.
    """
    out = Path(out).resolve()
    sensitivity_dir = out / "sensitivity"
    sensitivity_dir.mkdir(parents=True, exist_ok=True)
    try:
        _require_clean_suite(out)
        config, _ = ci.inputs()
        expected_manifest_sha = config.get("sensitivity", {}).get("manifest_sha256")
        if not isinstance(expected_manifest_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha):
            raise ValueError("sensitivity manifest SHA-256 is missing from runner inputs")
        manifest, variants = _load_manifest(expected_manifest_sha)
        if config.get("source_sha") != SOURCE_SHA:
            raise ValueError("sensitivity runner requires the pinned stage-6 source")
        root = Path(ci.ROOT).resolve()
    except Exception as error:
        ci.save(sensitivity_dir / "result.json", {
            "result": "FAIL_OR_UNKNOWN", "termination_reason": "PREFLIGHT_ERROR",
            "exception": repr(error), "variants": [],
        })
        return False

    all_good = True
    for variant in variants:
        ident = variant["id"]
        record = {"id": ident, "selector": variant["selector"], "result": "NOT_RUN",
                  "exit": None, "termination_reason": "NOT_STARTED", "problems": []}
        ci.save(out / ("sensitivity-" + ident) / "result.json", record)
        target = root / variant["mutated_path"]
        patch_path = HERE / variant["patch"]
        row_out = out / ("sensitivity-" + ident)
        original = None
        mode = None
        try:
            ci.snapshot("sensitivity-" + ident + "-before", out)
            original = target.read_bytes()
            mode = target.stat().st_mode
            if _sha(original) != variant["input_sha256"]:
                raise ValueError("mutated input SHA-256 mismatch")
            patch = patch_path.read_bytes()
            if _sha(patch) != variant["patch_sha256"]:
                raise ValueError("mutation patch SHA-256 mismatch")
            (row_out / "mutation.patch").write_bytes(patch)
            _git(root, "apply", "--check", str(patch_path))
            subprocess.check_call(["git", "apply", str(patch_path)], cwd=root)
            changed = _git(root, "diff", "--name-only", "--") .splitlines()
            if changed != [variant["mutated_path"]]:
                raise ValueError(f"mutation changed unexpected paths: {changed}")
            mutated = target.read_bytes()
            (row_out / "mutated-input.bin").write_bytes(mutated)
            record.update(input_sha256=variant["input_sha256"],
                          mutated_sha256=_sha(mutated), patch_sha256=variant["patch_sha256"],
                          mutated_path=variant["mutated_path"])
            base = sensitivity_dir / ident / "build-base"
            native_log = sensitivity_dir / ident / "compiletest.native.log"
            argv = ["target/debug/compiletest", "--suite", "expected", "--mode", "expected",
                    "--build-base", str(base), "--logfile", str(native_log), "--color", "never",
                    "--exact", "--force-rerun", "--no-fail-fast", "--timeout", "2400",
                    variant["selector"]]
            ci.execute("sensitivity-" + ident, argv, out, expected=None, timeout=2400)
            run = json.loads((out / ("sensitivity-" + ident) / "result.json").read_text())
            record.update(run)
            stdout_path = out / ("sensitivity-" + ident) / "stdout.txt"
            stderr_path = out / ("sensitivity-" + ident) / "stderr.txt"
            stdout = stdout_path.read_text(errors="replace") if stdout_path.exists() else ""
            stderr = stderr_path.read_text(errors="replace") if stderr_path.exists() else ""
            native_path = _native_output_path(base, variant)
            native = native_path.read_text(errors="replace") if native_path.is_file() else ""
            native_err_path = native_path.with_suffix(".err")
            native_stderr = native_err_path.read_text(errors="replace") if native_err_path.is_file() else ""
            problems = _validate_compiletest(run, variant["selector"], stdout, stderr,
                                             native, native_stderr, variant)
            record.update(argv=argv, exit=run.get("exit"),
                          termination_reason=run.get("termination_reason"),
                          compiletest_result=run.get("result"),
                          native_output=str(native_path),
                          native_stderr=str(native_err_path),
                          native_sha256=_sha(native.encode()) if native else None,
                          native_verdict=VERIFICATION.findall(native),
                          native_N=[int(row[0]) for row in NATIVE_SUMMARY.findall(native)],
                          problems=problems,
                          result="DETECTED_EXPECTED_MISMATCH" if not problems else "FAIL_OR_UNKNOWN")
        except Exception as error:
            record.update(result="FAIL_OR_UNKNOWN", problems=[repr(error)])
        finally:
            if original is not None and mode is not None:
                try:
                    target.write_bytes(original)
                    os.chmod(target, mode)
                except Exception as error:
                    record["problems"].append("failed to restore mutated input: " + repr(error))
                    record["result"] = "FAIL_OR_UNKNOWN"
            try:
                ci.snapshot("sensitivity-" + ident + "-after", out)
            except Exception as error:
                record["problems"].append("post-restore source snapshot failed: " + repr(error))
                record["result"] = "FAIL_OR_UNKNOWN"
            record["finished"] = True
            ci.save(out / ("sensitivity-" + ident) / "result.json", record)
        all_good = all_good and record["result"] == "DETECTED_EXPECTED_MISMATCH"
        # Continue through all four independent mutations to retain per-variant evidence.

    final = {"result": "PASS" if all_good else "FAIL_OR_UNKNOWN",
             "source_sha": config.get("source_sha"), "manifest_sha256": expected_manifest_sha,
             "variants": [json.loads((out / ("sensitivity-" + v["id"]) / "result.json").read_text()) for v in variants]}
    ci.save(sensitivity_dir / "result.json", final)
    return all_good
