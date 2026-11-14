#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Synthetic checks for all seven reviewed exact manifest bindings."""
import copy
import json
import unittest
from pathlib import Path

from compare import Rejected, check_single, compare_root
from run import CHECKER


HERE = Path(__file__).resolve().parent
MANIFEST = json.loads((HERE / "roots.json").read_text())


def observation(name, checks, verdict="SUCCESS", failure_kind="NONE",
                failures=None, unsupported=None):
    failures = [] if failures is None else failures
    unsupported = [] if unsupported is None else unsupported
    return {
        "expected_root": name,
        "actual_root": name,
        "inventory_complete": True,
        "checks": checks,
        "covers": [],
        "verdict": verdict,
        "failure_kind": failure_kind,
        "failed_properties": failures,
        "unsupported_constructs": unsupported,
        "n_failed": len(failures),
    }


class BindingManifestTests(unittest.TestCase):
    def setUp(self):
        self.cases = {case["name"]: case for case in MANIFEST["roots"]}

    def bound_cycle(self):
        case = self.cases["cycle_root"]
        expected = {
            "binding": case["binding"],
            "expected_verdict": case["expected_verdict"],
            "checks": copy.deepcopy(case["expected_inventory"]),
            "covers": copy.deepcopy(case.get("expected_covers", [])),
            "failure_kind": case["expected_failure_kind"],
            "failed_properties": copy.deepcopy(case["expected_failures"]),
            "unsupported_constructs": copy.deepcopy(case["expected_unsupported_inventory"]),
        }
        actual = observation(case["name"], copy.deepcopy(expected["checks"]),
                             expected["expected_verdict"], expected["failure_kind"],
                             copy.deepcopy(expected["failed_properties"]),
                             copy.deepcopy(expected["unsupported_constructs"]))
        actual["covers"] = copy.deepcopy(expected["covers"])
        return actual, expected

    def test_all_seven_reviewed_roots_have_complete_exact_bindings(self):
        bound = [case for case in self.cases.values()
                 if case["binding"] == "REGRESSION_BOUND"]
        self.assertEqual(len(bound), 7)
        for case in bound:
            self.assertNotIn("binding_pending_reason", case)
            self.assertIsInstance(case["expected_inventory"], list)
            self.assertIsInstance(case["expected_failures"], list)
            self.assertIsInstance(case["expected_unsupported_inventory"], list)
            self.assertIn(case["expected_failure_kind"],
                          {"ERROR", "NONE", "OTHER", "PANICS_ONLY"})
            self.assertTrue(case["expected_inventory"])

    def test_all_reviewed_inventories_survive_root_and_toolchain_install_relocation(self):
        for prefix in ("/root/kani", "/home/runner/work/kani/kani/export", "/tmp/deep checkout/a"):
            for case in self.cases.values():
                def relocated(rows):
                    result = []
                    for row in rows:
                        moved = {}
                        for key, value in row.items():
                            if isinstance(value, str):
                                value = value.replace("tests/json-handler/", prefix + "/tests/json-handler/")
                                value = value.replace("rust-toolchain:", "/opt/rust/toolchains/").replace(
                                    "/library/core/", "/lib/rustlib/src/rust/library/core/")
                            moved[key] = value
                        result.append(CHECKER.normalize_property(moved, prefix))
                    return result

                expected = {"binding": case["binding"], "expected_verdict": case["expected_verdict"],
                            "checks": case["expected_inventory"], "covers": case.get("expected_covers", []),
                            "failure_kind": case["expected_failure_kind"],
                            "failed_properties": case["expected_failures"],
                            "unsupported_constructs": case["expected_unsupported_inventory"]}
                actual = observation(case["name"], relocated(expected["checks"]),
                                     expected["expected_verdict"], expected["failure_kind"],
                                     relocated(expected["failed_properties"]),
                                     relocated(expected["unsupported_constructs"]))
                actual["covers"] = relocated(expected["covers"])
                with self.subTest(prefix=prefix, root=case["name"]):
                    self.assertTrue(check_single(actual, expected))

    def test_exact_synthetic_root_matches_reviewed_binding(self):
        case = self.cases["immutable_legal"]
        checks = [copy.deepcopy(case["expected_inventory"][0])]
        expected = {
            "binding": case["binding"],
            "expected_verdict": case["expected_verdict"],
            "checks": checks,
            "covers": [],
            "failure_kind": "NONE",
            "failed_properties": [],
            "unsupported_constructs": [],
        }
        self.assertTrue(check_single(observation(case["name"], checks), expected))

    def test_status_drift_rejected_against_reviewed_binding(self):
        case = self.cases["immutable_legal"]
        checks = [copy.deepcopy(case["expected_inventory"][0])]
        expected = {
            "binding": case["binding"],
            "expected_verdict": case["expected_verdict"],
            "checks": checks,
            "covers": [],
            "failure_kind": "NONE",
            "failed_properties": [],
            "unsupported_constructs": [],
        }
        damaged = copy.deepcopy(checks)
        damaged[0]["status"] = "UNREACHABLE"
        with self.assertRaisesRegex(Rejected, "status/identity drift"):
            check_single(observation(case["name"], damaged), expected)

    def test_cycle_binding_has_reviewed_r4_stable_message(self):
        case = self.cases["cycle_root"]
        self.assertEqual(case["binding"], "REGRESSION_BOUND")
        self.assertEqual(case["binding_evidence"]["capture_run"], "43506774865")
        self.assertEqual(case["expected_failure_kind"], "OTHER")
        self.assertEqual(len(case["expected_failures"]), 1)
        self.assertEqual(case["expected_failures"], case["expected_unsupported_inventory"])
        failure = case["expected_failures"][0]
        self.assertEqual(failure["id"], "cycle_root.unsupported_construct.1")
        self.assertEqual(failure["status"], "FAILURE")
        self.assertEqual(failure["class"], "unsupported_construct")
        self.assertEqual(failure["file"], "tests/json-handler/uninit-part1-composition/mixed.rs")
        self.assertEqual(failure["line"], "79")
        self.assertIs(failure["trace_available"], True)
        message = failure["description"]
        for required in ("Kani delayed uninitialized-memory analysis detected an interprocedural cycle",
                         "cycle_root [provenance=source]", "cycle_relay",
                         "provenance=registration-override", "origin=kani::internal::run_contract_fn",
                         "mixed.rs:81", "mixed.rs:75"):
            self.assertIn(required, message)
        for forbidden in ("AnalysisKey", "Instance {", "DefId(", "definition: "):
            self.assertNotIn(forbidden, message)

    def test_exact_cycle_inventory_matches_reviewed_binding(self):
        actual, expected = self.bound_cycle()
        self.assertTrue(check_single(actual, expected))

    def test_cycle_missing_or_changed_check_rejected(self):
        for change in ("missing", "status"):
            actual, expected = self.bound_cycle()
            if change == "missing":
                actual["checks"].pop(0)
            else:
                actual["checks"][0]["status"] = "UNREACHABLE"
            with self.subTest(change=change), self.assertRaisesRegex(Rejected, "status/identity drift"):
                check_single(actual, expected)

    def test_cycle_failure_metadata_and_kind_drift_rejected(self):
        for field, value in (("file", "wrong.rs"), ("line", "80"),
                             ("trace_available", False), ("class", "assertion")):
            actual, expected = self.bound_cycle()
            for bucket in ("failed_properties", "unsupported_constructs"):
                actual[bucket][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(Rejected, "full failure inventory"):
                check_single(actual, expected)
        actual, expected = self.bound_cycle()
        actual["failure_kind"] = "PANICS_ONLY"
        with self.assertRaisesRegex(Rejected, "failure kind"):
            check_single(actual, expected)

    def test_cycle_missing_unsupported_inventory_rejected(self):
        actual, expected = self.bound_cycle()
        actual["unsupported_constructs"] = []
        with self.assertRaisesRegex(Rejected, "Unsupported inventory"):
            check_single(actual, expected)

    def test_cycle_diagnostic_drift_is_rejected(self):
        baseline, expected = self.bound_cycle()
        changed = copy.deepcopy(baseline)
        for bucket in ("checks", "failed_properties", "unsupported_constructs"):
            for row in changed[bucket]:
                if row["id"] == "cycle_root.unsupported_construct.1":
                    row["description"] += " changed cycle diagnostic"
        with self.assertRaisesRegex(Rejected, "status/identity drift"):
            check_single(changed, expected)
        self.assertFalse(compare_root(baseline, changed)["accepted"])

    def test_shared_check_drift_is_rejected_with_full_rows(self):
        baseline = observation("immutable_legal", [])
        combined = copy.deepcopy(baseline)
        combined["checks"] = [{
            "id": "std::ptr::read::<u8>.safety_check.5",
            "status": "SUCCESS",
            "description": "dereference check",
            "location": "library/core/src/ptr/mod.rs:1:1 in function std::ptr::read::<u8>",
        }]
        result = compare_root(baseline, combined)
        self.assertFalse(result["accepted"])
        self.assertFalse(result["exact_match"])
        self.assertEqual(result["differences"]["checks"]["added"], combined["checks"])


if __name__ == "__main__":
    unittest.main()
