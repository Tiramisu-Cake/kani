#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Synthetic checks for reviewed manifest bindings and the pending cycle root."""
import copy
import json
import unittest
from pathlib import Path

from compare import Rejected, check_single, compare_root


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

    def test_six_reviewed_roots_have_complete_exact_bindings(self):
        bound = [case for case in self.cases.values()
                 if case["binding"] == "REGRESSION_BOUND"]
        self.assertEqual(len(bound), 6)
        for case in bound:
            self.assertIsInstance(case["expected_inventory"], list)
            self.assertIsInstance(case["expected_failures"], list)
            self.assertIsInstance(case["expected_unsupported_inventory"], list)
            self.assertIn(case["expected_failure_kind"],
                          {"ERROR", "NONE", "OTHER", "PANICS_ONLY"})
            self.assertTrue(case["expected_inventory"])

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

    def test_cycle_stays_pending_with_stable_message_contract(self):
        case = self.cases["cycle_root"]
        self.assertEqual(case["binding"], "BINDING_PENDING")
        reason = case["binding_pending_reason"]
        for required in ("Kani delayed uninitialized-memory analysis detected an interprocedural cycle",
                         "Instance.name()", "trimmed paths", "provenance", "file:line"):
            self.assertIn(required, reason)
        for forbidden in ("AnalysisKey", "Instance Debug", "DefId", "internal IDs"):
            self.assertIn(forbidden, reason)
        with self.assertRaisesRegex(Rejected, "BINDING_PENDING"):
            check_single(observation("cycle_root", []), {"binding": case["binding"]})

    def test_cycle_diagnostic_drift_is_not_accepted_as_t1b(self):
        baseline = observation("cycle_root", [])
        changed = copy.deepcopy(baseline)
        row = {"id": "cycle_root.unsupported_construct.1", "status": "FAILURE",
               "description": "stable cycle message", "location": "mixed.rs:79:1 in function cycle_root"}
        failure = {"id": row["id"], "status": "FAILURE", "description": row["description"],
                   "class": "unsupported_construct", "file": "mixed.rs", "line": "79",
                   "trace_available": True}
        baseline.update(checks=[row], verdict="FAILURE", failure_kind="OTHER",
                        failed_properties=[failure], unsupported_constructs=[failure], n_failed=1)
        changed_row = copy.deepcopy(row)
        changed_row["description"] = "changed cycle diagnostic"
        changed_failure = dict(failure, description=changed_row["description"])
        changed.update(checks=[changed_row], verdict="FAILURE", failure_kind="OTHER",
                        failed_properties=[changed_failure], unsupported_constructs=[changed_failure],
                        n_failed=1)
        self.assertFalse(compare_root(baseline, changed)["accepted"])

    def test_shared_t1b_check_can_be_recorded_without_changing_binding(self):
        baseline = observation("immutable_legal", [])
        combined = copy.deepcopy(baseline)
        combined["checks"] = [{
            "id": "std::ptr::read::<u8>.safety_check.5",
            "status": "SUCCESS",
            "description": "dereference check",
            "location": "library/core/src/ptr/mod.rs:1:1 in function std::ptr::read::<u8>",
        }]
        result = compare_root(baseline, combined)
        self.assertTrue(result["accepted"])
        self.assertFalse(result["exact_match"])
        self.assertEqual(len(result["t1b_evidence"]["added"]), 1)


if __name__ == "__main__":
    unittest.main()
