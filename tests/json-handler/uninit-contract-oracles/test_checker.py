#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Adversarial synthetic documents, not actual Kani evidence or Rust bodies."""

import copy
import contextlib
import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from pathlib import Path

import checker
import run

MANIFEST = checker.load_export(Path(__file__).with_name("oracles.json"))
SEED = checker.load_export(
    checker.ROOT / "tests/json-handler/schema-validation/fixture-completed-failure.json"
)


def regular(data):
    h = data["harnesses"][0]
    # This is a hand-authored synthetic inventory, not an invocation or a golden.
    props = h.pop("synthetic_regular") if "synthetic_regular" in h else []
    text = f"Checking harness {h['name']}...\n\nRESULTS:\n"
    for i, p in enumerate(props, 1):
        text += (f"Check {i}: {p['id']}\n\t - Status: {p['status']}\n"
                 f"\t - Description: \"{p['description']}\"\n"
                 f"\t - Location: {p['location']}\n\n")
    marker = "SUCCESSFUL" if h["outcome"]["verdict"] == "SUCCESS" else "FAILED"
    return text + f"\nSUMMARY:\nVERIFICATION:- {marker}\n"


def fixture(case_id="p2"):
    case = copy.deepcopy(next(c for c in MANIFEST["cases"] if c["id"] == case_id))
    data = copy.deepcopy(SEED)
    data["enabled_unstable_features"] = sorted(checker.FLAGS)
    data["harness_selection"] = {"requested_filters": [case["root"]], "exact": True,
                                  "unmatched_filters": [], "matched_count": 1}
    data["configuration"]["cbmc_args"] = ["--object-bits", "12"]
    data["configuration"]["coverage_enabled"] = False
    h = data["harnesses"][0]
    h.update(name=case["root"], file=case["input"], line=case["root_line"],
             unsupported_constructs=[], warnings=[], warnings_truncated=0)
    h["attributes"].update(should_panic=False, stubs=[], verified_stubs=[])
    h["outcome"] = {"kind": "COMPLETED", "verdict": case["verdict"]}
    negative = case["verdict"] == "FAILURE"
    count = (case["failure_count"] or 2) if negative else 0
    failures = []
    for i in range(count):
        failures.append({"id": f"synthetic::read.safety_check.{i + 1}",
                         "description": f"synthetic u8 payload read layer {i + 1}",
                         "class": "safety_check", "file": case["input"], "line": "14",
                         "trace_available": True, "status": "FAILURE"})
    if case_id == "frame":
        failures[0].update(id="synthetic::frame.assigns.1", description="assignable write *outside (var_7)",
                           line="22", **{"class": "assigns"})
    successes = [{"id": "synthetic::target.assertion.1", "status": "SUCCESS",
                  "description": "useful body/ensures assertion", "location": f"{case['input']}:14:1 in function target"},
                 {"id": "synthetic::root.assertion.1", "status": "SUCCESS",
                  "description": "useful harness assertion", "location": f"{case['input']}:22:1 in function root"}]
    h["failed_properties"] = failures
    h["failure_kind"] = "OTHER" if negative else "NONE"
    h["n_failed"] = count
    h["n_properties"] = count + 2
    h["checks"] = {"total": count + 2, "success": 2, "failure": [p["id"] for p in failures],
                   "unreachable": [], "undetermined": [], "error": [], "unknown": [], "other": []}
    h["covers"] = {"total": 0, "satisfied": [], "unsatisfiable": [], "unreachable": [],
                   "undetermined": [], "error": [], "unknown": [], "other": []}
    h["synthetic_regular"] = successes + [
        {"id": p["id"], "status": "FAILURE", "description": p["description"],
         "location": f"{p['file']}:{p['line']}:1 in function synthetic"} for p in failures
    ]
    data["summary"] = {"total": 1, "successful": int(not negative), "failed": int(negative),
                       "checks_total": count + 2, "checks_success": 2,
                       "covers_total": 0, "covers_satisfied": 0}
    stamp = datetime.strptime(data["started_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    receipt = {"input": case["input"], "root": case["root"], "input_sha256": case["sha256"],
               "original_exit": int(negative), "timed_out": False, "error": None,
               "started_epoch": stamp, "finished_epoch": stamp + 10,
               "build_prefix": str(checker.ROOT), "cwd": str(checker.ROOT)}
    case["binding"] = {"status": "REGRESSION_BOUND", "failures": copy.deepcopy(failures),
                       "required_successes": copy.deepcopy(successes),
                       "operations": {op: "SYNTHETIC mapping only" for op in case["required_operations"]}}
    return data, case, receipt, regular(data)


def hole_fixture(case_id, status):
    data, case, receipt, text = fixture(case_id)
    h = data["harnesses"][0]
    failure = {"id": "synthetic::ensures.assertion.1", "class": "assertion",
               "description": "synthetic ensures reads hole and compares with 17",
               "file": case["input"], "line": str(case["operation_lines"][0]["line"]),
               "status": "FAILURE"}
    record = {"id": failure["id"], "status": "FAILURE", "description": failure["description"],
              "location": f"{failure['file']}:{failure['line']}:1 in function synthetic::ensures"}
    case["binding"]["allowed_consequences"] = [{"failure": failure, "regular": record}]
    h["n_properties"] += 1
    h["checks"]["total"] += 1
    data["summary"]["checks_total"] += 1
    if status == "FAILURE":
        h["failed_properties"].append(dict(failure, trace_available=True))
        h["n_failed"] += 1
        h["checks"]["failure"].append(failure["id"])
    elif status == "UNREACHABLE":
        h["checks"]["unreachable"].append(failure["id"])
    elif status == "SUCCESS":
        h["checks"]["success"] += 1
        data["summary"]["checks_success"] += 1
    else:
        raise AssertionError("unsupported synthetic status")
    h["synthetic_regular"] = checker.regular_properties(text) + [dict(record, status=status)]
    return data, case, receipt, regular(data)


class CheckerTests(unittest.TestCase):
    def reject(self, change, case_id="p2", message=None):
        data, case, receipt, text = fixture(case_id)
        replacement = change(data, case, receipt, text)
        with self.assertRaises(checker.Rejected, msg=message):
            checker.validate(data, case, receipt, replacement if replacement is not None else text)

    def test_complete_bound_fixtures(self):
        for case in MANIFEST["cases"]:
            with self.subTest(case=case["id"]):
                self.assertEqual(checker.validate(*fixture(case["id"])), "PASS")

    def test_unbound_manifest_is_never_pass(self):
        for case in MANIFEST["cases"]:
            data, synthetic, receipt, text = fixture(case["id"])
            synthetic["binding"]["status"] = "BINDING_PENDING"
            with self.subTest(case=case["id"]), self.assertRaisesRegex(checker.Rejected, "BINDING_PENDING"):
                checker.validate(data, synthetic, receipt, text)

    def test_selection_and_source_rejections(self):
        changes = [
            lambda d, c, r, t: d.update(harnesses=[]),
            lambda d, c, r, t: d["harnesses"].append(copy.deepcopy(d["harnesses"][0])),
            lambda d, c, r, t: d["harnesses"][0].update(file="tests/expected/uninit/transfer-qualification/postcondition-hole.rs"),
            lambda d, c, r, t: d["harnesses"][0].update(name="other_root"),
            lambda d, c, r, t: d["harnesses"][0].update(line=999),
            lambda d, c, r, t: d["harness_selection"].update(matched_count=0),
            lambda d, c, r, t: d["harness_selection"].update(exact=False),
            lambda d, c, r, t: d["harness_selection"].update(requested_filters=["other_root"]),
            lambda d, c, r, t: r.update(input_sha256="0" * 64),
            lambda d, c, r, t: r.update(input="other.rs"),
            lambda d, c, r, t: r.update(cwd="/tmp/synthetic-invocation"),
        ]
        for i, change in enumerate(changes):
            with self.subTest(change=i):
                self.reject(change)

    def test_terminal_exit_and_freshness_rejections(self):
        for code in (-15, 2, 124, 137, 0, None):
            with self.subTest(exit=code):
                self.reject(lambda d, c, r, t: r.update(original_exit=code))
        for change in (
            lambda d, c, r, t: r.update(timed_out=True),
            lambda d, c, r, t: r.update(error="codegen error"),
            lambda d, c, r, t: d.update(run_state="INCOMPLETE"),
            lambda d, c, r, t: d.update(run_state="PARTIAL"),
            lambda d, c, r, t: d.update(started_at="2020-01-01T00:00:00Z"),
            lambda d, c, r, t: d["harnesses"][0].update(outcome={"kind": "TIMEOUT"}),
            lambda d, c, r, t: d["harnesses"][0].update(n_failed=None),
        ):
            self.reject(change)

    def test_extra_failure_and_one_of_two_missing(self):
        # Change every counter and both representations consistently. A weaker
        # >=1/subset oracle would accept either of these bad inventories.
        for add in (True, False):
            def change(d, c, r, text):
                h = d["harnesses"][0]
                if add:
                    p = copy.deepcopy(h["failed_properties"][0])
                    p.update(id="synthetic::extra.safety_check.99", description="extra invalid value")
                    h["failed_properties"].append(p)
                else:
                    h["failed_properties"].pop()
                ids = [p["id"] for p in h["failed_properties"]]
                delta = 1 if add else -1
                h["n_failed"] += delta
                h["n_properties"] += delta
                h["checks"]["total"] += delta
                h["checks"]["failure"] = ids
                d["summary"]["checks_total"] += delta
                # Re-render consistently, so exact identity comparison, rather
                # than a stale text/counter mismatch, rejects the mutation.
                props = checker.regular_properties(text)[:2]
                h["synthetic_regular"] = props + [
                    {"id": p["id"], "status": "FAILURE", "description": p["description"],
                     "location": f"{p['file']}:{p['line']}:1 in function synthetic"}
                    for p in h["failed_properties"]]
                return regular(d)
            self.reject(change, "postcondition-hole")

    def test_hole_outer_ensures_failure_or_unreachable(self):
        for case_id in ("p2", "postcondition-hole"):
            for status in ("FAILURE", "UNREACHABLE"):
                with self.subTest(case=case_id, status=status):
                    self.assertEqual(checker.validate(*hole_fixture(case_id, status)), "PASS")

    def test_hole_consequence_does_not_hide_missing_or_extra_failure(self):
        for case_id in ("p2", "postcondition-hole"):
            for status in ("FAILURE", "UNREACHABLE"):
                for mutation in ("missing-read", "extra-failure", "wrong-location", "missing-ensures"):
                    data, case, receipt, text = hole_fixture(case_id, status)
                    h = data["harnesses"][0]
                    props = checker.regular_properties(text)
                    if mutation in ("missing-read", "extra-failure"):
                        if mutation == "missing-read":
                            removed = h["failed_properties"].pop(0)
                            props = [p for p in props if p["id"] != removed["id"]]
                            delta = -1
                        else:
                            extra = dict(h["failed_properties"][0], id="synthetic::unrelated.assertion.99",
                                         description="unrelated failure", **{"class": "assertion"})
                            h["failed_properties"].append(extra)
                            props.append({"id": extra["id"], "status": "FAILURE",
                                          "description": extra["description"], "location": "other.rs:1:1 in function other"})
                            delta = 1
                        h["checks"]["failure"] = [p["id"] for p in h["failed_properties"]]
                        h["n_failed"] += delta
                    elif mutation == "missing-ensures":
                        pid = case["binding"]["allowed_consequences"][0]["failure"]["id"]
                        props = [p for p in props if p["id"] != pid]
                        if status == "FAILURE":
                            h["failed_properties"] = [p for p in h["failed_properties"] if p["id"] != pid]
                            h["checks"]["failure"].remove(pid)
                            h["n_failed"] -= 1
                        else:
                            h["checks"]["unreachable"].remove(pid)
                        delta = -1
                    else:
                        props[-1]["location"] = "wrong.rs:99:1 in function wrong"
                        delta = 0
                    h["n_properties"] += delta
                    h["checks"]["total"] += delta
                    data["summary"]["checks_total"] += delta
                    h["synthetic_regular"] = props
                    with self.subTest(case=case_id, status=status, mutation=mutation), self.assertRaises(checker.Rejected):
                        checker.validate(data, case, receipt, regular(data))

    def test_hole_outer_ensures_success_is_rejected(self):
        for case_id in ("p2", "postcondition-hole"):
            with self.subTest(case=case_id), self.assertRaisesRegex(checker.Rejected, "outer ensures"):
                checker.validate(*hole_fixture(case_id, "SUCCESS"))

    def test_exact_frame_target_type_line_and_function(self):
        def swapped(d, c, r, text):
            p = d["harnesses"][0]["failed_properties"][0]
            p["description"] = p["description"].replace("*outside (var_7)", "shadow (var_8)")
            return text.replace("*outside (var_7)", "shadow (var_8)")
        self.reject(swapped, "frame")
        for key, value in (("class", "assigns"), ("line", "99"), ("file", "wrong.rs"),
                           ("description", "synthetic u16 payload read layer 1")):
            self.reject(lambda d, c, r, t, k=key, v=value: d["harnesses"][0]["failed_properties"][0].update({k: v}))
        self.reject(lambda d, c, r, t: t.replace("in function target", "in function wrong"), "p1")

    def test_unsupported_duplicate_and_counters(self):
        for change in (
            lambda d, c, r, t: d["harnesses"][0]["unsupported_constructs"].append(d["harnesses"][0]["failed_properties"][0]),
            lambda d, c, r, t: d["harnesses"][0]["checks"]["failure"].append(d["harnesses"][0]["checks"]["failure"][0]),
            lambda d, c, r, t: d["harnesses"][0]["failed_properties"].append(d["harnesses"][0]["failed_properties"][0]),
            lambda d, c, r, t: d["harnesses"][0].update(n_properties=999),
            lambda d, c, r, t: d["harnesses"][0]["checks"].update(success=999),
            lambda d, c, r, t: d["summary"].update(checks_success=999),
            lambda d, c, r, t: d["harnesses"][0]["checks"]["unknown"].append("mystery"),
            lambda d, c, r, t: d["harnesses"][0]["failed_properties"][0].update(status="UNKNOWN"),
            lambda d, c, r, t: d["configuration"]["checks"].update(overflow=False),
            lambda d, c, r, t: c["binding"].update(operations={}),
        ):
            self.reject(change)

    def test_positive_useful_unreachable_is_rejected(self):
        def change(d, c, r, text):
            h = d["harnesses"][0]
            h["checks"]["success"] -= 1
            h["checks"]["unreachable"] = ["synthetic::target.assertion.1"]
            d["summary"]["checks_success"] -= 1
            return text.replace("Status: SUCCESS", "Status: UNREACHABLE", 1)
        self.reject(change, "p1")

    def test_service_unreachable_is_allowed(self):
        data, case, receipt, text = fixture()
        h = data["harnesses"][0]
        h["checks"]["success"] -= 1
        h["checks"]["unreachable"] = ["synthetic::root.assertion.1"]
        data["summary"]["checks_success"] -= 1
        case["binding"]["required_successes"] = case["binding"]["required_successes"][:1]
        text = text.replace('Check 2: synthetic::root.assertion.1\n\t - Status: SUCCESS',
                            'Check 2: synthetic::root.assertion.1\n\t - Status: UNREACHABLE')
        self.assertEqual(checker.validate(data, case, receipt, text), "PASS")

    def test_successful_or_unreachable_unsupported_service_branch_is_allowed(self):
        for status in ("SUCCESS", "UNREACHABLE"):
            data, case, receipt, text = fixture()
            h = data["harnesses"][0]
            pid = "synthetic::service.unsupported_construct.1"
            h["n_properties"] += 1
            h["checks"]["total"] += 1
            data["summary"]["checks_total"] += 1
            if status == "SUCCESS":
                h["checks"]["success"] += 1
                data["summary"]["checks_success"] += 1
            else:
                h["checks"]["unreachable"].append(pid)
            p = {"id": pid, "status": status, "description": "unused service branch",
                 "class": "unsupported_construct", "file": None, "line": None, "trace_available": False}
            h["unsupported_constructs"] = [p]
            h["synthetic_regular"] = checker.regular_properties(text) + [
                {"id": pid, "status": status, "description": p["description"], "location": "Unknown file"}]
            text = regular(data)
            with self.subTest(status=status):
                self.assertEqual(checker.validate(data, case, receipt, text), "PASS")
                self.assertFalse(run.reached_unsupported(data))
                p["status"] = "UNREACHABLE" if status == "SUCCESS" else "SUCCESS"
                with self.assertRaisesRegex(checker.Rejected, "Unsupported regular/JSON"):
                    checker.validate(data, case, receipt, text)

    def test_reached_or_nonterminal_unsupported_is_rejected(self):
        for status in ("FAILURE", "UNDETERMINED", "UNKNOWN", "ERROR"):
            data, case, receipt, text = fixture()
            data["harnesses"][0]["unsupported_constructs"] = [
                {"id": "synthetic::service.unsupported_construct.1", "status": status,
                 "description": "unsupported path", "class": "unsupported_construct",
                 "file": None, "line": None, "trace_available": False}]
            with self.subTest(status=status), self.assertRaises(checker.Rejected):
                checker.validate(data, case, receipt, text)

    def test_scenario_process_receipts_without_compilation(self):
        # Mock the CLI boundary only. Keep the actual scenario/consumer and
        # filesystem behavior, including original return codes and absent files.
        for mode in ("ok", "missing", "stale", "signal", "codegen", "oserror", "tampered",
                     "null", "wrong-type", "incomplete", "truncated", "timeout"):
            data, case, sample_receipt, text = fixture()
            if mode == "stale":
                data["started_at"] = "2020-01-01T00:00:00Z"

            def fake(argv, **kwargs):
                if mode == "timeout":
                    raise run.subprocess.TimeoutExpired("synthetic", 180)
                if mode == "oserror":
                    raise OSError("synthetic exec failure")
                kwargs["stdout"].write(text.encode())
                if mode != "missing":
                    exported = copy.deepcopy(data)
                    if mode == "null":
                        exported["harnesses"] = None
                    elif mode == "wrong-type":
                        exported = []
                    elif mode == "incomplete":
                        exported = {"run_state": "INCOMPLETE"}
                    serialized = '{"run_state":' if mode == "truncated" else json.dumps(exported)
                    Path(argv[argv.index("--export-json") + 1]).write_text(serialized)
                class Result:
                    returncode = -15 if mode == "signal" else 2 if mode == "codegen" else 1
                return Result()

            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                with patch.object(run.subprocess, "run", side_effect=fake) as invocation, \
                        patch.object(checker, "check_directory", wraps=checker.check_directory) as checked, \
                        patch.object(run.time, "time", return_value=sample_receipt["started_epoch"] + 0.5), \
                        contextlib.redirect_stdout(io.StringIO()):
                    status, stop = run.execute_case(case, temp)
                directory = next(Path(temp).iterdir())
                self.assertEqual(status, "PASS" if mode in ("ok", "tampered") else "FAIL")
                self.assertFalse(stop)
                self.assertFalse((directory / "invocation.json").exists())
                self.assertFalse((directory / "observation.json").exists())
                if checked.called:
                    receipt = checked.call_args.args[2]
                    self.assertEqual(receipt["original_exit"],
                                     None if mode == "timeout" else
                                     -15 if mode == "signal" else 2 if mode == "codegen" else 1)
                if mode == "tampered":
                    (directory / "export.json").write_text("{}")
                    with self.assertRaises(checker.Rejected):
                        checker.check_directory(directory, case, receipt)

    def test_exporter_cwd_and_compiletest_failure_output(self):
        # Model schema_utils::HarnessExport's relativize_path, rather than
        # handing the consumer an already checkout-relative path. In particular,
        # the old temporary cwd produces ../../.../checkout/tests/... here.
        for manifest_case in MANIFEST["cases"]:
            for mode in ("bound", "pending", "wrong-input", "wrong-root"):
                data, case, sample_receipt, text = fixture(manifest_case["id"])
                if mode == "pending":
                    case["binding"]["status"] = "BINDING_PENDING"

                def fake(argv, **kwargs):
                    exported = copy.deepcopy(data)
                    source = Path(argv[1])
                    if mode == "wrong-input":
                        # Both real inputs have this basename. Matching only
                        # the filename would silently accept the wrong source.
                        source = checker.ROOT / "wrong-input" / source.name
                    exported["harnesses"][0]["file"] = os.path.relpath(source, kwargs["cwd"])
                    if mode == "wrong-root":
                        exported["harnesses"][0]["name"] = "other_root"
                    kwargs["stdout"].write(text.encode())
                    Path(argv[argv.index("--export-json") + 1]).write_text(json.dumps(exported))

                    class Result:
                        returncode = int(case["verdict"] == "FAILURE")
                    return Result()

                with self.subTest(case=case["id"], mode=mode), tempfile.TemporaryDirectory() as temp:
                    output = io.StringIO()
                    with patch.object(run.subprocess, "run", side_effect=fake) as invocation, \
                            patch.object(checker, "check_directory", wraps=checker.check_directory) as checked, \
                            patch.object(run.time, "time", return_value=sample_receipt["started_epoch"] + 0.5), \
                            contextlib.redirect_stdout(output):
                        status, stop = run.execute_case(case, temp)
                    expected = {"bound": "PASS", "pending": "FAIL"}.get(mode, "FAIL")
                    self.assertEqual(status, expected)
                    self.assertFalse(stop)
                    directory = next(Path(temp).iterdir())
                    receipt = checked.call_args.args[2]
                    self.assertEqual(receipt["cwd"], str(checker.ROOT))
                    self.assertEqual(receipt["original_exit"], int(case["verdict"] == "FAILURE"))
                    self.assertEqual(Path(invocation.call_args.args[0][invocation.call_args.args[0].index("--target-dir") + 1]),
                                     directory / "target")
                    # extract_rendered only tries rustc JSON parsing for '{'
                    # at column zero, even for arbitrary exec-mode output.
                    lines = output.getvalue().splitlines()
                    self.assertTrue(lines)
                    self.assertTrue(all(not line.startswith("{") for line in lines))
                    prefix = "Oracle observation: "
                    self.assertTrue(lines[0].startswith(prefix))
                    printed = json.loads(lines[0][len(prefix):])
                    self.assertEqual(printed["status"], expected)
                    if mode in ("wrong-input", "wrong-root"):
                        self.assertEqual(printed["reason"], "same root in wrong input or wrong root")

    def test_lawful_unsupported_stop_and_unreachable_boundary(self):
        data, _, _, _ = fixture("lawful-modifies")
        self.assertFalse(run.reached_unsupported(data))
        prop = {}
        data["harnesses"][0]["unsupported_constructs"] = [prop]
        for status in ("SUCCESS", "UNREACHABLE", "ERROR", None):
            prop["status"] = status
            self.assertFalse(run.reached_unsupported(data))
        for status in ("FAILURE", "UNDETERMINED", "UNKNOWN"):
            prop["status"] = status
            self.assertTrue(run.reached_unsupported(data))
        for malformed in (None, [], {"harnesses": None}, {"harnesses": [None]}):
            self.assertFalse(run.reached_unsupported(malformed))

    def test_main_cleans_temporary_files_on_success_failure_and_exception(self):
        for outcome in ("PASS", "FAIL", "UNKNOWN", OSError("synthetic")):
            directories = []

            def execute(case, parent):
                directories.append(Path(parent))
                (Path(parent) / "diagnostic").write_text("synthetic output")
                if isinstance(outcome, Exception):
                    raise outcome
                return outcome, False

            with self.subTest(outcome=str(outcome)), \
                    patch.object(run, "execute_case", side_effect=execute), \
                    contextlib.redirect_stdout(io.StringIO()):
                if isinstance(outcome, Exception):
                    with self.assertRaises(OSError):
                        run.main()
                else:
                    self.assertEqual(run.main(), 0 if outcome == "PASS" else 1)
                self.assertTrue(directories)
                self.assertTrue(all(not path.exists() for path in directories))

    def test_truncated_regular(self):
        self.reject(lambda d, c, r, t: t.split("SUMMARY:")[0])
        self.reject(lambda d, c, r, t: t.replace("Check 2:", "Check 20:"))

    def test_missing_truncated_and_duplicate_json(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "export.json"
            with self.assertRaises(FileNotFoundError):
                checker.load_export(path)
            for text in ('{"run_state":', '{"run_state":"INCOMPLETE"', '{"a":1,"a":2}'):
                path.write_text(text)
                with self.assertRaises((ValueError, checker.Rejected)):
                    checker.load_export(path)

    def test_recipe_exact_flags_last_backend_and_existing_inputs(self):
        for case in MANIFEST["cases"]:
            argv = run.command(case, Path("/tmp/synthetic"))
            self.assertEqual(argv[-3:], ["--cbmc-args", "--object-bits", "12"])
            self.assertEqual(argv[argv.index("--harness") + 1], case["root"])
            self.assertEqual(argv[argv.index("--jobs") + 1], "1")
            self.assertIn("--exact", argv)
            self.assertEqual(argv[1], str(checker.ROOT / case["input"]))
            self.assertEqual(checker.sha256(argv[1]), case["sha256"])
            for feature in checker.FLAGS:
                self.assertIn(feature, argv[:argv.index("--cbmc-args")])


if __name__ == "__main__":
    unittest.main()
