#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Synthetic tests for complete, root-bound mixed inventory comparisons."""
import unittest
import tempfile
import hashlib
import json
import copy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from compare import Rejected, check_single, compare_pair, compare_selection
import run as mixed_runner
from run import CHECKER, observation, validate_process_result


def failed_metadata(row, prop_class="assertion"):
    return {"id": row["id"], "description": row["description"], "class": prop_class,
            "file": "fixture.rs", "line": "1", "trace_available": False, "status": "FAILURE"}


def root(name, checks, verdict="SUCCESS", complete=True, actual_name=None,
         failure_kind=None, failures=None, unsupported=None):
    failures = failures if failures is not None else [
        failed_metadata(row, "unsupported_construct" if row["id"].startswith("cycle") else "assertion")
        for row in checks if row["status"] == "FAILURE"]
    unsupported = unsupported if unsupported is not None else []
    return {"expected_root": name, "actual_root": actual_name or name,
            "inventory_complete": complete, "verdict": verdict,
            "failure_kind": failure_kind or ("NONE" if verdict == "SUCCESS" else "OTHER"),
            "n_failed": len(failures), "checks": checks,
            "failed_properties": failures, "unsupported_constructs": unsupported}


def check(identifier, status="SUCCESS"):
    return {"id": identifier, "status": status, "description": identifier,
            "location": "fixture.rs:1:1 in function " + identifier}


def run(*roots):
    names = [item["expected_root"] for item in roots]
    return {"run_state": "COMPLETE", "requested_roots": names, "roots": list(roots)}


def observation_fixture():
    source_rel = "tests/json-handler/uninit-part1-composition/mixed.rs"
    case = {"name": "immutable_hole_negative", "root_line": 22,
            "mode": "Assert", "target": None, "expected_verdict": "FAILURE"}
    data = CHECKER.load_export(
        CHECKER.ROOT / "tests/json-handler/schema-validation/fixture-completed-failure.json")
    data = copy.deepcopy(data)
    stamp = datetime.now(timezone.utc).replace(microsecond=0)
    data["started_at"] = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    data["enabled_unstable_features"] = sorted(
        ["uninit-checks", "function-contracts", "export-json", "unstable-options"])
    data["configuration"]["cbmc_args"] = ["--object-bits", "12"]
    data["configuration"]["coverage_enabled"] = False
    for key in ("memory_safety", "overflow", "unwinding", "undefined_function",
                "assertion_reach_checks", "assert_contracts"):
        data["configuration"]["checks"][key] = True
    for key in ("ignore_global_asm", "prove_safety_only"):
        data["configuration"]["checks"][key] = False
    data["harness_selection"] = {"requested_filters": [case["name"]], "exact": True,
                                 "unmatched_filters": [], "matched_count": 1}
    harness = data["harnesses"][0]
    harness.update(name=case["name"], file=source_rel, line=case["root_line"],
                   outcome={"kind": "COMPLETED", "verdict": "FAILURE"},
                   failure_kind="OTHER", n_properties=4, n_failed=2)
    harness["attributes"].update(kind="Proof", should_panic=False, stubs=[], verified_stubs=[])
    success = {"id": "root.assertion.1", "status": "SUCCESS", "description": "legal assertion",
               "location": f"{source_rel}:18:1 in function immutable_hole_negative"}
    failed = {"id": "root.read.1", "description": "bad read", "class": "safety_check",
              "file": source_rel, "line": "24", "trace_available": True, "status": "FAILURE"}
    unsupported = {"id": "root.unsupported.1", "description": "cycle boundary",
                   "class": "unsupported_construct", "file": source_rel, "line": "25",
                   "trace_available": False, "status": "FAILURE"}
    unreachable = {"id": "root.unreachable.1", "status": "UNREACHABLE",
                   "description": "unreachable assertion",
                   "location": f"{source_rel}:26:1 in function immutable_hole_negative"}
    harness["failed_properties"] = [failed, unsupported]
    harness["unsupported_constructs"] = [unsupported]
    harness["checks"] = {"total": 4, "success": 1, "failure": [failed["id"], unsupported["id"]],
                         "unreachable": [unreachable["id"]], "undetermined": [], "error": [],
                         "unknown": [], "other": []}
    harness["covers"] = {"total": 0, "satisfied": [], "unsatisfiable": [], "unreachable": [],
                         "undetermined": [], "error": [], "unknown": [], "other": []}
    data["summary"] = {"total": 1, "successful": 0, "failed": 1, "checks_total": 4,
                       "checks_success": 1, "covers_total": 0, "covers_satisfied": 0}
    regular_rows = [success,
                    {"id": failed["id"], "status": "FAILURE", "description": failed["description"],
                     "location": f"{source_rel}:24:1 in function immutable_hole_negative"},
                    {"id": unsupported["id"], "status": "FAILURE", "description": unsupported["description"],
                     "location": f"{source_rel}:25:1 in function immutable_hole_negative"},
                    unreachable]
    log = f"Checking harness {case['name']}...\n\nRESULTS:\n"
    for index, prop in enumerate(regular_rows, 1):
        log += (f"Check {index}: {prop['id']}\n\t - Status: {prop['status']}\n"
                f"\t - Description: \"{prop['description']}\"\n"
                f"\t - Location: {prop['location']}\n\n")
    log += "\nSUMMARY:\nVERIFICATION:- FAILED\n"
    receipt = {"build_prefix": str(CHECKER.ROOT), "started_epoch": stamp.timestamp() - 0.5,
               "finished_epoch": stamp.timestamp() + 2}
    return data, log, [case["name"]], {case["name"]: case}, receipt


class MixedInventoryTests(unittest.TestCase):
    def setUp(self):
        self.legal = root("legal", [check("legal.assertion.1")])
        cycle_check = check("cycle.unsupported.1", "FAILURE")
        cycle_failure = failed_metadata(cycle_check, "unsupported_construct")
        cycle_unsupported = [dict(cycle_failure, trace_available=False)]
        self.cycle = root("cycle", [cycle_check], "FAILURE", failures=[cycle_failure],
                          unsupported=cycle_unsupported)
        self.expected = {"legal": {"binding": "REGRESSION_BOUND", "expected_verdict": "SUCCESS",
                                   "checks": [check("legal.assertion.1")], "failure_kind": "NONE",
                                   "failed_properties": [], "unsupported_constructs": []},
                         "cycle": {"binding": "REGRESSION_BOUND", "expected_verdict": "FAILURE",
                                   "checks": [cycle_check], "failure_kind": "OTHER",
                                   "failed_properties": [cycle_failure],
                                   "unsupported_constructs": cycle_unsupported}}

    def test_exact_isolated_inventory_passes(self):
        self.assertTrue(check_single(self.legal, self.expected["legal"]))
        self.assertTrue(check_single(self.cycle, self.expected["cycle"]))

    def test_lost_check_rejected(self):
        damaged = root("legal", [])
        with self.assertRaisesRegex(Rejected, "lost check"):
            check_single(damaged, self.expected["legal"])

    def test_extra_failure_rejected(self):
        damaged = root("legal", [check("legal.assertion.1"), check("unexpected", "FAILURE")],
                       "FAILURE")
        with self.assertRaisesRegex(Rejected, "lost check|extra check"):
            check_single(damaged, self.expected["legal"])

    def test_wrong_root_rejected(self):
        with self.assertRaisesRegex(Rejected, "wrong root"):
            compare_selection(run(root("legal", [check("legal.assertion.1")],
                                  actual_name="cycle")), self.expected)

    def test_incomplete_rejected(self):
        with self.assertRaisesRegex(Rejected, "incomplete"):
            compare_selection(run(root("legal", [], complete=False)), self.expected)

    def test_root_local_pair_matches(self):
        self.assertTrue(compare_pair(run(self.legal, self.cycle),
                                    run(self.cycle, self.legal), self.expected))

    def test_failed_metadata_drift_and_unsupported_drift_rejected(self):
        failed_metadata_drift = copy.deepcopy(self.cycle)
        failed_metadata_drift["failed_properties"][0]["file"] = "other.rs"
        failed_metadata_drift["unsupported_constructs"][0]["file"] = "other.rs"
        with self.assertRaisesRegex(Rejected, "inventory changed: cycle"):
            compare_pair(run(self.cycle), run(failed_metadata_drift), {"cycle": self.cycle})
        unsupported_drift = copy.deepcopy(self.cycle)
        unsupported_drift["unsupported_constructs"][0]["line"] = "99"
        unsupported_drift["failed_properties"][0]["line"] = "99"
        with self.assertRaisesRegex(Rejected, "inventory changed: cycle"):
            compare_pair(run(self.cycle), run(unsupported_drift), {"cycle": self.cycle})

    def test_bound_inventory_includes_failure_kind_and_unsupported(self):
        expected = dict(self.expected["cycle"])
        changed = copy.deepcopy(self.cycle)
        changed["failure_kind"] = "PANICS_ONLY"
        with self.assertRaisesRegex(Rejected, "failure kind"):
            check_single(changed, expected)
        changed = copy.deepcopy(self.cycle)
        changed["unsupported_constructs"] = []
        with self.assertRaisesRegex(Rejected, "Unsupported inventory"):
            check_single(changed, expected)

    def test_cycle_failure_cannot_contaminate_legal_root(self):
        contaminated = root("legal", [check("legal.assertion.1"),
                                       check("unexpected", "FAILURE")], "FAILURE")
        with self.assertRaisesRegex(Rejected, "inventory changed: legal"):
            compare_pair(run(self.legal, self.cycle), run(contaminated, self.cycle), self.expected)

    def test_pending_binding_fails_closed(self):
        with self.assertRaisesRegex(Rejected, "BINDING_PENDING"):
            check_single(self.legal, {"binding": "BINDING_PENDING"})

    def test_process_exit_and_timeout_fail_closed(self):
        self.assertIsNone(validate_process_result(1, 1))
        for arguments, message in [((0, 1), "NONVERIFICATION_OR_EXIT_MISMATCH"),
                                   ((-9, 1), "NONVERIFICATION_OR_EXIT_MISMATCH"),
                                   ((1, 1, True), "TIMEOUT"),
                                   ((1, 1, False, "missing executable"),
                                    "PROCESS_START_OR_OUTPUT_ERROR")]:
            with self.subTest(arguments=arguments), self.assertRaisesRegex(Rejected, message):
                validate_process_result(*arguments)

    def test_missing_or_malformed_export_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing.json"
            with self.assertRaises(OSError):
                CHECKER.load_export(missing)
            malformed = Path(temporary) / "malformed.json"
            malformed.write_text('{"run_state": ')
            with self.assertRaises(ValueError):
                CHECKER.load_export(malformed)


class ObservationInvariantTests(unittest.TestCase):
    def observe(self, mutation=None):
        data, regular, selectors, cases, receipt = observation_fixture()
        if mutation:
            mutation(data, regular, receipt)
        return observation(data, regular, selectors, cases, receipt)

    def test_complete_synthetic_export_passes_and_retains_metadata(self):
        result = self.observe()
        root_observation = result["roots"][0]
        self.assertEqual(root_observation["failure_kind"], "OTHER")
        self.assertEqual(root_observation["n_failed"], 2)
        self.assertEqual(len(root_observation["unsupported_constructs"]), 1)
        self.assertEqual(root_observation["failed_properties"][0]["class"], "safety_check")
        expected = {"binding": "REGRESSION_BOUND", "expected_verdict": "FAILURE",
                    "checks": root_observation["checks"],
                    "failure_kind": root_observation["failure_kind"],
                    "failed_properties": root_observation["failed_properties"],
                    "unsupported_constructs": root_observation["unsupported_constructs"]}
        self.assertTrue(check_single(root_observation, expected))

    def test_failed_trace_availability_is_retained_and_compared(self):
        baseline = self.observe()
        changed = self.observe(lambda d, _r, _p:
                               d["harnesses"][0]["failed_properties"][0].update(trace_available=False))
        self.assertTrue(baseline["roots"][0]["failed_properties"][0]["trace_available"])
        self.assertFalse(changed["roots"][0]["failed_properties"][0]["trace_available"])
        with self.assertRaisesRegex(Rejected, "mixed-root inventory changed"):
            compare_pair(baseline, changed,
                         {name: {} for name in baseline["requested_roots"]})

    def test_swapped_success_and_unreachable_ids_rejected(self):
        def swap(data, _regular, _receipt):
            checks = data["harnesses"][0]["checks"]
            checks["unreachable"] = ["root.assertion.1"]
        with self.assertRaisesRegex(Rejected, "unreachable ID mismatch"):
            self.observe(swap)

    def test_failure_counter_and_duplicate_failure_rejected(self):
        with self.assertRaisesRegex(Rejected, "failed-property counter"):
            self.observe(lambda d, _r, _p: d["harnesses"][0].update(n_failed=1))

        def duplicate(data, _regular, _receipt):
            h = data["harnesses"][0]
            h["failed_properties"].append(copy.deepcopy(h["failed_properties"][0]))
            h["n_failed"] += 1
        with self.assertRaisesRegex(Rejected, "duplicate failed-properties"):
            self.observe(duplicate)

    def test_unsupported_inventory_must_match_regular_and_failure_rows(self):
        def drift(data, _regular, _receipt):
            data["harnesses"][0]["unsupported_constructs"][0]["status"] = "SUCCESS"
        with self.assertRaisesRegex(Rejected, "Unsupported inventory mismatch"):
            self.observe(drift)

    def test_stale_export_timestamp_rejected(self):
        with self.assertRaisesRegex(Rejected, "stale export timestamp"):
            self.observe(lambda data, _regular, _receipt: data.update(started_at="2020-01-01T00:00:00Z"))

    def test_null_wrong_type_incomplete_and_wrong_root_rejected(self):
        mutations = [
            (lambda d, _r, _p: d.update(harnesses=None), "schema/presence"),
            (lambda d, _r, _p: d["harnesses"][0].update(unsupported_constructs=None), "schema/presence"),
            (lambda d, _r, _p: d["harnesses"][0].update(n_failed="2"), "schema/presence"),
            (lambda d, _r, _p: d.update(run_state="INCOMPLETE"), "schema/presence"),
            (lambda d, _r, _p: d["harnesses"][0].update(name="wrong_root"), "wrong selected root"),
        ]
        for mutation, message in mutations:
            with self.subTest(message=message), self.assertRaisesRegex(Rejected, message):
                self.observe(mutation)


class ExecuteReceiptTests(unittest.TestCase):
    def setUp(self):
        self.source_rel = "tests/json-handler/uninit-part1-composition/mixed.rs"
        self.source = mixed_runner.ROOT / self.source_rel
        self.source_hash = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest = {"source": self.source_rel, "source_sha256": self.source_hash,
                         "jobs": 1, "object_bits": 12}
        self.case_by_name = {"root": {"expected_verdict": "SUCCESS"}}

    def invoke(self, process_side_effect, export_mode="valid", source_snapshot=None):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)

            def fake_process(argv, stdout, **_kwargs):
                stdout.write(b"mock output\n")
                if isinstance(process_side_effect, BaseException):
                    raise process_side_effect
                if export_mode == "valid":
                    export = Path(argv[argv.index("--export-json") + 1])
                    export.write_text("{}")
                elif export_mode == "malformed":
                    export = Path(argv[argv.index("--export-json") + 1])
                    export.write_text('{"run_state": ')
                return process_side_effect

            real_sha256 = mixed_runner.sha256
            source_calls = 0

            def fake_sha256(path):
                nonlocal source_calls
                if Path(path) == self.source and source_snapshot is not None:
                    source_calls += 1
                    if source_calls == 1:
                        return self.source_hash
                    if source_snapshot == "missing":
                        raise FileNotFoundError("source disappeared during invocation")
                    return "changed-hash"
                return real_sha256(path)

            with mock.patch.object(mixed_runner, "command", return_value=[
                    "fake-kani", "--export-json", str(parent / "mock-run" / "export.json")]), \
                    mock.patch.object(mixed_runner.subprocess, "run", side_effect=fake_process), \
                    mock.patch.object(mixed_runner, "sha256", side_effect=fake_sha256), \
                    mock.patch.object(mixed_runner.CHECKER, "load_export", wraps=CHECKER.load_export), \
                    mock.patch.object(mixed_runner, "observation", return_value={"observed": True}):
                try:
                    result = mixed_runner.execute("fake-kani", self.manifest, ["root"],
                                                  self.case_by_name, parent, "mock-run")
                    error = None
                except Exception as caught:
                    result, error = None, caught
            receipt_path = parent / "mock-run" / "receipt.json"
            receipt = json.loads(receipt_path.read_text())
            return result, error, receipt

    def test_execute_success_persists_original_exit_and_hashes(self):
        result, error, receipt = self.invoke(SimpleNamespace(returncode=0))
        self.assertIsNone(error)
        self.assertEqual(result[0], {"observed": True})
        self.assertEqual(receipt["original_exit"], 0)
        self.assertEqual(receipt["input_sha256_after"], self.source_hash)

    def test_execute_nonverification_exit_keeps_exit(self):
        _, error, receipt = self.invoke(SimpleNamespace(returncode=1))
        self.assertIsInstance(error, Rejected)
        self.assertIn("NONVERIFICATION_OR_EXIT_MISMATCH", str(error))
        self.assertEqual(receipt["original_exit"], 1)
        self.assertIn("NONVERIFICATION_OR_EXIT_MISMATCH", receipt["error"])

    def test_execute_timeout_and_os_error_keep_exception_receipts(self):
        for side_effect, field, expected in [
                (subprocess_timeout(), "timed_out", True),
                (FileNotFoundError("missing fake Kani"), "error", True)]:
            with self.subTest(field=field):
                _, error, receipt = self.invoke(side_effect)
                self.assertIsInstance(error, ValueError)
                self.assertEqual(receipt[field] if field == "timed_out" else
                                 "FileNotFoundError" in receipt[field], expected)
                self.assertIsNone(receipt["original_exit"])

    def test_execute_missing_and_malformed_exports_preserve_exit(self):
        for mode, expected_error in (("missing", "FileNotFoundError"),
                                     ("malformed", "JSONDecodeError")):
            with self.subTest(mode=mode):
                _, error, receipt = self.invoke(SimpleNamespace(returncode=0), export_mode=mode)
                self.assertIsNotNone(error)
                self.assertIn(expected_error, receipt["error"])
                self.assertEqual(receipt["original_exit"], 0)

    def test_execute_changed_or_missing_source_snapshot_keeps_exit(self):
        self.case_by_name["root"]["expected_verdict"] = "FAILURE"
        for snapshot, message in (("changed", "INPUT_HASH_CHANGED"),
                                  ("missing", "SNAPSHOT_ERROR")):
            with self.subTest(snapshot=snapshot):
                _, error, receipt = self.invoke(SimpleNamespace(returncode=1),
                                                source_snapshot=snapshot)
                self.assertIsInstance(error, Rejected)
                self.assertIn(message, str(error))
                self.assertEqual(receipt["original_exit"], 1)
                self.assertIn(message, receipt["error"])
                if snapshot == "missing":
                    self.assertIn("input_sha256_after", receipt["snapshot_errors"])


def subprocess_timeout():
    import subprocess
    return subprocess.TimeoutExpired("fake-kani", 180)


if __name__ == "__main__":
    unittest.main()
