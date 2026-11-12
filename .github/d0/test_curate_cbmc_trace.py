# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
import copy
import hashlib
import importlib.util
import json
import pathlib
import unittest


SCRIPT = pathlib.Path(__file__).with_name("curate_cbmc_trace.py")
spec = importlib.util.spec_from_file_location("curate_cbmc_trace", SCRIPT)
curator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(curator)


def sample():
    cbmc = [{"program": "synthetic"}, {"result": [
        {"property": "harness.safety_check.1", "description": "A check", "status": "SUCCESS",
         "sourceLocation": {"file": "fixture.rs", "function": "eq", "line": "20", "column": "4"}},
        {"property": "harness.safety_check.2", "description": "B check", "status": "FAILURE",
         "sourceLocation": {"file": "fixture.rs", "function": "eq", "line": "21", "column": "4"},
         "trace": [
             {"stepType": "assignment", "lhs": "tmp_shadow", "sourceLocation": {"file": "goto.c", "line": "10"},
              "value": {"binary": "0001", "width": 4}},
             {"stepType": "assignment", "lhs": "nondet_tmp", "value": {"data": "noise"}},
             {"stepType": "assignment", "lhs": "ptr_eq_operand", "sourceLocation": {"file": "goto.c", "line": "12"},
              "value": {"data": "object:offset intentionally uninterpreted"}},
             {"stepType": "failure", "property": "harness.safety_check.2"},
         ]},
    ]}, {"cProverStatus": "FAILURE"}]
    manifest = {"identity": {"source": "sha-source", "stage": "goto-consumed", "target": "unit-A"},
                "original_exits": {"solver": 10, "verification": 1, "cbmc_status": "FAILURE"}}
    def binding(pid, line, required, trace_lhs):
        return {"property_id": pid, "source": "sha-source", "stage": "goto-consumed", "target": "unit-A",
                "goto_binding": f"goto-symbol-for-{pid}",
                "cbmc_source_location": {"file": "fixture.rs", "function": "eq", "line": line},
                "trace_lhs": trace_lhs, "required_trace_lhs": required}
    bindings = {"identity": copy.deepcopy(manifest["identity"]), "properties": {
        "harness.safety_check.1": binding("harness.safety_check.1", "20", [], {}),
        "harness.safety_check.2": binding("harness.safety_check.2", "21", ["ptr_eq_operand", "tmp_shadow"],
            {"raw_eq_operand": ["ptr_eq_operand"], "shadow_state": ["tmp_shadow"],
             "pointer_witness_transition": []}),
    }}
    trace_hash = hashlib.sha256(json.dumps(cbmc, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()
    manifest["expected_trace_sha256"] = trace_hash
    bindings["expected_trace_sha256"] = trace_hash
    return cbmc, manifest, bindings


class CuratorTests(unittest.TestCase):
    def test_success_curates_exact_bound_records_and_preserves_exits(self):
        report, complete = curator.curate(*sample())
        self.assertTrue(complete)
        self.assertEqual(report["original_exits"], {"solver": 10, "verification": 1, "cbmc_status": "FAILURE"})
        self.assertEqual(report["curated_properties"][0]["runtime_witness"], "N/A")
        failed = report["curated_properties"][1]
        self.assertFalse(failed["causal_claim"])
        self.assertEqual([x["ordinal"] for x in failed["runtime_witness"]], [0, 2, 3])
        self.assertEqual(failed["runtime_witness"][-1]["property_id"], "harness.safety_check.2")
        self.assertEqual(report["records_dropped"], 1)

    def test_missing_trace_is_incomplete(self):
        cbmc, manifest, bindings = sample()
        del cbmc[1]["result"][1]["trace"]
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertTrue(any("no complete trace" in e for e in report["errors"]))

    def test_null_required_binding_is_incomplete(self):
        cbmc, manifest, bindings = sample()
        bindings["identity"]["target"] = None
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertTrue(any("bindings.identity.target" in e for e in report["errors"]))

    def test_wrong_type_status_is_incomplete(self):
        cbmc, manifest, bindings = sample()
        cbmc[1]["result"][1]["status"] = {"FAILURE": True}
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertTrue(any("status: expected non-empty string" in e for e in report["errors"]))

    def test_partial_cbmc_json_is_incomplete_and_keeps_original_exits(self):
        cbmc, manifest, bindings = sample()
        cbmc.pop()
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertEqual(report["original_exits"]["solver"], 10)
        self.assertTrue(any("cProverStatus" in e for e in report["errors"]))

    def test_source_stage_target_mismatch_is_incomplete(self):
        cbmc, manifest, bindings = sample()
        bindings["properties"]["harness.safety_check.2"]["target"] = "unit-other"
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertTrue(any("target does not match" in e for e in report["errors"]))

    def test_required_trace_symbol_missing_is_incomplete(self):
        cbmc, manifest, bindings = sample()
        cbmc[1]["result"][1]["trace"] = cbmc[1]["result"][1]["trace"][:1]
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertEqual(report["coverage"]["harness.safety_check.2"]["observed_required_symbols"], 1)

    def test_trace_with_all_bound_symbols_but_missing_final_failure_is_incomplete(self):
        cbmc, manifest, bindings = sample()
        cbmc[1]["result"][1]["trace"].pop()
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertTrue(any("matching failure step/property" in e for e in report["errors"]))

    def test_null_value_for_required_witness_symbol_is_incomplete(self):
        cbmc, manifest, bindings = sample()
        cbmc[1]["result"][1]["trace"][2]["value"] = None
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertIn("ptr_eq_operand", report["coverage"]["harness.safety_check.2"]["missing_symbols"])

    def test_solver_exit_5_is_terminal_but_unknown_property_is_not_verified(self):
        cbmc, manifest, bindings = sample()
        cbmc[1]["result"][0]["status"] = "UNKNOWN"
        manifest["original_exits"]["solver"] = 5
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertEqual(report["original_exits"]["solver"], 5)
        self.assertFalse(any("nonterminal" in e or "unsupported" in e for e in report["errors"]))

    def test_error_or_timeout_exits_are_nonterminal(self):
        cbmc, manifest, bindings = sample()
        manifest["original_exits"].update({"solver": 6, "verification": "TIMEOUT", "cbmc_status": "ERROR"})
        cbmc[-1]["cProverStatus"] = "ERROR"
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertTrue(any("solver exit 6 is nonterminal" in e for e in report["errors"]))
        self.assertTrue(any("verification exit TIMEOUT is nonterminal" in e for e in report["errors"]))
        self.assertTrue(any("CBMC status ERROR is nonterminal" in e for e in report["errors"]))

    def test_empty_source_binding_is_incomplete(self):
        cbmc, manifest, bindings = sample()
        bindings["properties"]["harness.safety_check.2"]["cbmc_source_location"] = {}
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertTrue(any("must name a source coordinate" in e for e in report["errors"]))

    def test_expected_input_hash_mismatch_is_incomplete(self):
        cbmc, manifest, bindings = sample()
        bindings["expected_trace_sha256"] = "0" * 64
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertTrue(any("expected trace SHA256" in e for e in report["errors"]))

    def test_pretty_output_respects_cap(self):
        cbmc, manifest, bindings = sample()
        old_cap = curator.MAX_OUTPUT_BYTES
        curator.MAX_OUTPUT_BYTES = 2400
        try:
            report, complete = curator.curate(cbmc, manifest, bindings)
        finally:
            curator.MAX_OUTPUT_BYTES = old_cap
        rendered = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode()
        self.assertLessEqual(len(rendered), 2400)
        self.assertFalse(complete)

    def test_identity_mismatch_and_noninteger_original_exit_are_errors(self):
        cbmc, manifest, bindings = sample()
        bindings["identity"]["stage"] = "another-stage"
        manifest["original_exits"]["solver"] = "10"
        report, complete = curator.curate(cbmc, manifest, bindings)
        self.assertFalse(complete)
        self.assertTrue(any("identity does not match" in e for e in report["errors"]))
        self.assertTrue(any("solver: expected integer" in e for e in report["errors"]))


if __name__ == "__main__":
    unittest.main()
