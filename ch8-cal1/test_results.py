"""Synthetic result projection tests; no Kani, Rust, CBMC, or CI invocations."""
import json
from pathlib import Path
import tempfile
import unittest
from copy import deepcopy
from unittest.mock import Mock

import results
import report
import run


SELECTOR_A = "slice::sort::shared::smallsort::verify::net::n08"
SELECTOR_B = "slice::sort::shared::smallsort::verify::net::n09"
FEATURES = sorted(results.EXPECTED_FEATURES)
FROZEN_REQUEST = results.spec.load()
MERGE_ROWS = FROZEN_REQUEST["source_bindings"]["merge_roster"]
COPY_BACK_ROWS = FROZEN_REQUEST["source_bindings"]["copy_back_roster"]
U64_N13_ROWS = FROZEN_REQUEST["source_bindings"]["u64_n13_roster"]
U64_N14_N17_ROWS = FROZEN_REQUEST["source_bindings"]["u64_n14_n17_roster"]
U64_N18_N19_ROWS = FROZEN_REQUEST["source_bindings"]["u64_n18_n19_roster"]
PROVIDER_ROWS = FROZEN_REQUEST["source_bindings"]["u64_n26_n32_providers_roster"]
CONSUMER_ROWS = FROZEN_REQUEST["source_bindings"]["u64_n26_n32_consumer_roster"]
PILOT_ROWS = FROZEN_REQUEST["source_bindings"]["pilot_roster"]
FIX1_ROWS = FROZEN_REQUEST["source_bindings"]["pilot_fix1_roster"]
CLOSE_ROWS = FROZEN_REQUEST["source_bindings"]["pilot_close_roster"]
WIDE_WITNESS_ROWS = FROZEN_REQUEST["source_bindings"]["wide_witness_roster"]
N10_WITNESS_ROWS = FROZEN_REQUEST["source_bindings"]["n10_wide_witness_roster"]
N12_WITNESS_ROWS = FROZEN_REQUEST["source_bindings"]["n12_wide_witness_roster"]
WIDE_N12_N14_ROWS = FROZEN_REQUEST["source_bindings"]["wide_n12_n14_roster"]
N12_N14_CHECK_ROWS = WIDE_N12_N14_ROWS[:4]
N14_WITNESS_ROWS = WIDE_N12_N14_ROWS[4:]
N32_ROWS = FROZEN_REQUEST["source_bindings"]["n32_pilot_roster"]
N32_PLAIN_ROWS = N32_ROWS[:3]
N32_CHECK_ROWS = N32_ROWS[3:]
CLOSURE_ROWS = FROZEN_REQUEST["roster"]
PROVIDER_REQUEST = FROZEN_REQUEST | {"roster": PROVIDER_ROWS}


def row(rid, selector, unwind=8):
    return {"id": rid, "selector": selector, "unwind": unwind, "check": None,
            "replace": [], "covers": ["cover-label"], "object_bits": 12}


def result_row(expected="VERIFIED"):
    if expected == "FAILED":
        return n17_control_row()
    return row("SYNTHETIC-INSERTION", SELECTOR_A) | {
        "expected_outcome": "VERIFIED", "expected_failure": None,
        "required_assertions": ["NUMERIC_ORDER", "BYTE_FRAME"], "repeatable_assertions": ["BYTE_FRAME"],
    }


def n17_control_row():
    """Legacy sole-failure fixture, intentionally independent of the frozen roster."""
    return row("SYNTHETIC-CONTROL", "slice::sort::shared::smallsort::verify::synthetic_control") | {
        "unwind": 36,
        "expected_outcome": "FAILED", "expected_failure": {
            "label": "SYNTHETIC_EXPECTED_FAILURE", "file": "core/src/slice/sort/shared/smallsort/verify/synthetic.rs",
            "line": 7, "column": 3, "function": "synthetic_control"},
        "required_assertions": ["SYNTHETIC_FRAME"], "repeatable_assertions": [],
        "covers": ["SYNTHETIC_CONTROL_REACHED"],
    }


def harness(selector, unwind=8, verdict="SUCCESS"):
    success = verdict == "SUCCESS"
    checks = {"total": 1, "success": int(success), "failure": [], "unreachable": [],
              "undetermined": [], "error": [], "unknown": [], "other": []}
    covers = {"total": 1, "satisfied": ["c1"], "unsatisfiable": [], "unreachable": [],
              "undetermined": [], "error": [], "unknown": [], "other": []}
    failed = [] if success else ["p1"]
    checks["failure"] = failed
    checks["success"] = int(success)
    return {"name": selector, "crate_name": "core", "file": "src/lib.rs", "line": 1,
            "contract": None, "is_automatically_generated": False, "has_loop_contracts": False,
            "is_bounded": False, "has_refcount_caveat": False,
            "attributes": {"kind": "Proof", "should_panic": False, "solver": None,
                           "unwind_value": unwind, "stubs": [], "verified_stubs": []},
            "outcome": {"kind": "COMPLETED", "verdict": verdict},
            "resolved_solver": "cadical", "resolved_unwind": unwind,
            "generated_concrete_test": False, "resources": {"verification_time_s": 1.5},
            "n_properties": 2, "n_failed": len(failed), "failure_kind": "NONE" if success else "OTHER",
            "failed_properties": ([] if success else [
                {"id": "p1", "description": "fail", "class": "assertion", "file": "src/lib.rs",
                 "line": "1", "trace_available": False, "status": "FAILURE"}]),
            "unsupported_constructs": [], "warnings": [], "warnings_truncated": 0,
            "checks": checks, "covers": covers}


def export_document(harnesses, *, state="COMPLETE", selectors=None):
    selectors = selectors or [h["name"] for h in harnesses]
    successful = sum(h["outcome"].get("verdict") == "SUCCESS" for h in harnesses)
    return {"schema_version": "0.1.0", "kani_commit": results.spec.TOOL[0], "kani_commit_dirty": False,
            "tools": {"kani": "0.68.0", "rustc": "1.99.0-nightly", "cbmc": "6.11.0"},
            "enabled_unstable_features": FEATURES,
            "harness_selection": {"requested_filters": selectors, "exact": True,
                                  "unmatched_filters": [], "matched_count": len(selectors)},
            "harness_timeout_s": None,
            "configuration": {"checks": {"memory_safety": True, "overflow": True, "unwinding": True,
                              "undefined_function": True, "assertion_reach_checks": True,
                              "ignore_global_asm": False, "extra_pointer_checks": False,
                              "assert_contracts": False, "prove_safety_only": False},
                              "cbmc_args": ["--object-bits", "12"], "coverage_enabled": False},
            "outcome": {"kind": "COMPLETED" if state == "COMPLETE" else "INTERRUPTED"},
            "run_state": state, "target": "x86_64-unknown-linux-gnu",
            "started_at": "2026-11-23T10:00:00Z", "wall_time_s": 5.0,
            "harnesses": harnesses,
            "summary": {"total": len(harnesses), "successful": successful,
                        "failed": len(harnesses) - successful, "checks_total": len(harnesses),
                        "checks_success": successful, "covers_total": len(harnesses),
                        "covers_satisfied": len(harnesses)}}


def regular(selector, verdict="SUCCESS", n=2):
    status = "SUCCESSFUL" if verdict == "SUCCESS" else "FAILED"
    lines = [f"Checking harness {selector}...", "RESULTS:"]
    for i in range(n):
        if i == 0:
            prop_id, desc, prop_status = "x.assertion.1", "assert ok", verdict
        else:
            prop_id, desc, prop_status = "x.cover.1", "cover-label", "SATISFIED"
        lines += [f"Check {i+1}: {prop_id}", f"\t - Status: {prop_status}",
                  f'\t - Description: "{desc}"', ""]
    lines += ["", "SUMMARY:", f" ** 0 of {n} failed", f" ** 1 of 1 cover properties satisfied",
              f"VERIFICATION:- {status}"]
    return ("\n".join(lines) + "\n").encode()


class ResultProjectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)
        self.child = {"stop_reason": "EXITED", "wall_seconds": 4.0, "peak_rss_kib": 1024,
                      "exit_code": 0, "signal": None, "reaped": True,
                      "sampler_valid": True, "max_verifier_children": 1,
                      "stdout_complete": True, "stderr_complete": True}

    def write(self, stdout, export, stderr=b""):
        (self.directory / "stdout.log").write_bytes(stdout)
        (self.directory / "stderr.log").write_bytes(stderr)
        (self.directory / "export.json").write_bytes(json.dumps(export).encode())

    def test_expected_result_accepts_positive_and_bound_control_failure(self):
        row_a = result_row()
        labels = row_a["required_assertions"]
        native = [{"id": f"p.assertion.{i}", "stock_export_id": f"p.assertion.{i}",
                   "class": "assertion", "status": "SUCCESS", "description": label}
                  for i, label in enumerate(labels, 1)]
        cover_ids = {}
        for i, label in enumerate(row_a["covers"], 1):
            prop_id = f"p.cover.{i}"
            native.append({"id": prop_id, "stock_export_id": prop_id, "class": "cover",
                           "status": "SATISFIED", "description": label})
            cover_ids[label] = prop_id
        stock = {"state": "COMPLETE", "failed_properties": [],
                 "property_ids": {row_a["id"]: {"covers.satisfied": list(cover_ids.values())}},
                 "totals": {row_a["id"]: {"checks_total": len(labels), "checks_success": len(labels)}}}
        result = results._expected_result(row_a, "VERIFIED", True, native, stock)
        self.assertEqual(result["status"], "MATCHED", result)

        control = result_row("FAILED")
        target = control["expected_failure"]
        failure = {"id": "h.assertion.4", "stock_export_id": "h.assertion.4", "class": "assertion",
                   "status": "FAILURE", "description": target["label"],
                   "location": target["file"] + f":{target['line']}" +
                               (f":{target['column']}" if target.get("column") else "")}
        failure["location"] += " in function " + target.get("function", "corrupt")
        native_control = [{"id": f"h.assertion.{i}", "stock_export_id": f"h.assertion.{i}",
                           "class": "assertion", "status": "SUCCESS", "description": label}
                          for i, label in enumerate(control["required_assertions"], 1)]
        native_control.append(failure)
        cover_ids = {}
        for i, label in enumerate(control["covers"], 1):
            prop_id = f"h.cover.{i}"
            native_control.append({"id": prop_id, "stock_export_id": prop_id, "class": "cover",
                                   "status": "SATISFIED", "description": label})
            cover_ids[label] = prop_id
        exported_failure = {"id": "h.assertion.4", "description": target["label"],
                            "class": "assertion", "file": target["file"],
                            "line": str(target["line"]), "status": "FAILURE"}
        stock_control = {"state": "COMPLETE", "failed_properties": [exported_failure],
                 "property_ids": {control["id"]: {"covers.satisfied": list(cover_ids.values()),
                                                           "checks.failure": ["h.assertion.4"]}},
                         "totals": {control["id"]: {"checks_total": len(control["required_assertions"]) + 1,
                                                     "checks_success": len(control["required_assertions"])}}}
        result = results._expected_result(control, "FAILED", True, native_control, stock_control)
        self.assertEqual(result["status"], "MATCHED", result)
        if target.get("column") and not target.get("function"):
            line_only = [dict(prop) for prop in native_control]
            line_only_failure = next(prop for prop in line_only if prop["status"] == "FAILURE")
            line_only_failure["location"] = target["file"] + f":{target['line']}"
            accepted_line_only = results._expected_result(control, "FAILED", True, line_only, stock_control)
            self.assertEqual(accepted_line_only["status"], "MATCHED", accepted_line_only)
            wrong_column = [dict(prop) for prop in native_control]
            wrong_column_failure = next(prop for prop in wrong_column if prop["status"] == "FAILURE")
            wrong_column_failure["location"] = target["file"] + f":{target['line']}:{target['column'] + 1}"
            mismatch = results._expected_result(control, "FAILED", True, wrong_column, stock_control)
            self.assertEqual(mismatch["status"], "MISMATCHED")
            self.assertIn("location", mismatch["reason"])

    def test_function_qualified_control_binds_exact_native_location_and_id(self):
        control = n17_control_row()
        target = control["expected_failure"]
        native = [{"id": f"p.assertion.{i}", "stock_export_id": f"p.assertion.{i}",
                   "class": "assertion", "status": "SUCCESS", "description": label}
                  for i, label in enumerate(control["required_assertions"], 1)]
        native.append({"id": "p.assertion.unknown", "stock_export_id": "p.assertion.unknown",
                       "class": "assertion", "status": "FAILURE", "description": target["label"],
                       "location": f"{target['file']}:{target['line']}:{target['column']} in function {target['function']}"})
        native.extend({"id": f"p.cover.{i}", "stock_export_id": f"p.cover.{i}",
                       "class": "cover", "status": "SATISFIED", "description": label}
                      for i, label in enumerate(control["covers"], 1))
        failure_id = "p.assertion.unknown"
        stock = {"state": "COMPLETE", "failed_properties": [
                    {"id": failure_id, "description": target["label"], "class": "assertion",
                     "file": target["file"], "line": str(target["line"]), "status": "FAILURE"}],
                 "property_ids": {control["id"]: {
                     "covers.satisfied": [p["stock_export_id"] for p in native if p["class"] == "cover"],
                     "checks.failure": [failure_id]}},
                 "totals": {control["id"]: {"checks_total": len(control["required_assertions"]) + 1,
                                              "checks_success": len(control["required_assertions"])}}}
        matched = results._expected_result(control, "FAILED", True, native, stock)
        self.assertEqual(matched["status"], "MATCHED", matched)

        for location in (
                f"{target['file']}:{target['line']}:{target['column']} in function wrong::<true>",
                f"{target['file']}:{target['line']}:{target['column'] + 1} in function {target['function']}",
                f"{target['file']}:{target['line']} in function {target['function']}"):
            mismatched_native = [dict(prop) for prop in native]
            next(prop for prop in mismatched_native if prop["status"] == "FAILURE")["location"] = location
            rejected = results._expected_result(control, "FAILED", True, mismatched_native, stock)
            self.assertEqual(rejected["status"], "MISMATCHED")
            self.assertIn("location/function", rejected["reason"])

        mismatched_ids = [dict(prop) for prop in native]
        next(prop for prop in mismatched_ids if prop["status"] == "FAILURE")["id"] = "different-native-id"
        rejected = results._expected_result(control, "FAILED", True, mismatched_ids, stock)
        self.assertEqual(rejected["status"], "MISMATCHED")
        self.assertIn("native IDs disagree", rejected["reason"])

    def test_expected_result_rejects_missing_inconsistent_partial_and_malformed(self):
        target = result_row()
        native = [{"id": f"p.assertion.{i}", "stock_export_id": f"p.assertion.{i}",
                   "class": "assertion", "status": "SUCCESS", "description": label}
                  for i, label in enumerate(target["required_assertions"], 1)]
        native += [{"id": f"p.cover.{i}", "stock_export_id": f"p.cover.{i}", "class": "cover",
                    "status": "SATISFIED", "description": label}
                   for i, label in enumerate(target["covers"], 1)]
        stock = {"state": "COMPLETE", "failed_properties": [],
                 "property_ids": {target["id"]: {"covers.satisfied": [p["stock_export_id"] for p in native if p["class"] == "cover"]}},
                 "totals": {target["id"]: {"checks_total": len(target["required_assertions"]),
                                            "checks_success": len(target["required_assertions"])}}}
        missing = results._expected_result(target, "VERIFIED", True, native[:-1], stock)
        self.assertEqual(missing["status"], "MISMATCHED")
        self.assertIn("required cover", missing["reason"])
        incomplete = results._expected_result(target, "VERIFIED", False, native, stock)
        self.assertEqual(incomplete["status"], "UNAVAILABLE")
        self.assertIn("complete terminal", incomplete["reason"])

        control = result_row("FAILED")
        broken = results._expected_result(control, "FAILED", True,
            [{"id": "n.assertion.1", "stock_export_id": "n.assertion.1", "class": "assertion",
              "status": "FAILURE", "description": control["expected_failure"]["label"],
              "location": f"wrong.rs:{control['expected_failure']['line']}:1 in function corrupt"}],
            {"state": "COMPLETE", "failed_properties": [{"id": "different", "description": control["expected_failure"]["label"],
             "class": "assertion", "file": control["expected_failure"]["file"],
             "line": str(control["expected_failure"]["line"]), "status": "FAILURE"}],
             "property_ids": {"checks.failure": ["different"]},
             "totals": {control["id"]: {"checks_total": 1, "checks_success": 0}}})
        self.assertEqual(broken["status"], "MISMATCHED")
        self.assertIn("IDs disagree", broken["reason"])
        self.assertIn("location", broken["reason"])

        malformed = result_row() | {"expected_outcome": "FAILED", "expected_failure": {"label": "x", "file": "x.rs"}}
        with self.assertRaisesRegex(ValueError, "malformed expected failure"):
            results._validate_rows([malformed])

    def test_repeatable_byte_frame_and_mandatory_anchor_compaction(self):
        byte_row = result_row()
        native = []
        ordinal = 0
        for label in byte_row["required_assertions"]:
            repeats = 2 if label in byte_row.get("repeatable_assertions", []) else 1
            for _ in range(repeats):
                ordinal += 1
                prop_id = f"byte.assertion.{ordinal}"
                native.append({"id": prop_id, "stock_export_id": prop_id, "class": "assertion",
                               "status": "SUCCESS", "description": label})
        cover_ids = []
        for index, label in enumerate(byte_row["covers"], 1):
            prop_id = f"byte.cover.{index}"
            native.append({"id": prop_id, "stock_export_id": prop_id, "class": "cover",
                           "status": "SATISFIED", "description": label})
            cover_ids.append(prop_id)
        stock = {"state": "COMPLETE", "failed_properties": [],
                 "property_ids": {byte_row["id"]: {"covers.satisfied": cover_ids}},
                 "totals": {byte_row["id"]: {"checks_total": ordinal, "checks_success": ordinal}}}
        matched = results._expected_result(byte_row, "VERIFIED", True, native, stock)
        self.assertEqual(matched["status"], "MATCHED", matched)
        failed_repeat = [dict(prop) for prop in native]
        next(prop for prop in failed_repeat if prop["class"] == "assertion")["status"] = "FAILURE"
        rejected = results._expected_result(byte_row, "VERIFIED", True, failed_repeat, stock)
        self.assertEqual(rejected["status"], "MISMATCHED")

        anchors = {"complete": True, "regular_properties": [{"id": "anchor", "location": None,
                    "status": "SUCCESS"}], "export_properties": []}
        oversized = {"schema": "rev2-slot-projection-v1", "mode": "singleton",
                     "outcome": "INCOMPLETE", "observed_outcome": "FAILED", "complete": False,
                     "native_checks": [{"description": "x"}],
                     "result_evidence": {"mandatory_anchors": anchors},
                     "native_metrics": {"large": "x" * results.MAX_PROJECTION_BYTES}}
        results._fit_projection(oversized)
        self.assertTrue(oversized["projection_truncated"])
        self.assertLessEqual(oversized["projection_bytes"], results.MAX_PROJECTION_BYTES)
        self.assertEqual(oversized["observed_outcome"], "FAILED")
        self.assertEqual(oversized["result_evidence"]["mandatory_anchors"], anchors)

    def test_report_profile_gates_match_and_limits(self):
        projected = {
            "required_covers": ["cover"], "outcome": "VERIFIED", "expected_outcome": "VERIFIED",
                     "expected_result": {"status": "MATCHED", "observed_outcome": "VERIFIED"},
                     "exit_code": 0, "projection_complete": True, "projection_status": "COMPLETE",
                     "projection": "slots/synthetic/projection.json",
                     "reaped": True, "sampler_valid": True, "mandatory_anchors_complete": True, "covers": {
                         "expected_labels_total": 1, "expected_reached_labels": ["cover"]},
                     "censored": False, "receipt_deadline_exceeded": False,
                     "receipt_write_completed_monotonic": 200, "receipt_deadline_monotonic": 201,
                     "receipt_write_deferred": False, "verification_seconds": 60,
                     "cold_wall_seconds": 100, "peak_rss_kib": 1024,
                     "stdout_delivery": "STOCK_PIPE", "frozen_stdout_delivery": "STOCK_PIPE"}
        accepted = report.profile(projected)
        self.assertTrue(accepted["matched_with_required_covers"])
        self.assertTrue(accepted["within_profile"])
        self.assertEqual(accepted["stdout_delivery"], "STOCK_PIPE")
        # A stock slot needs both its frozen role and its receipt delivery, and no relay record.
        for change in ({"stdout_delivery": None}, {"frozen_stdout_delivery": None},
                       {"stdout_delivery": "COMPLETE"}, {"stdout_relay": {"status": "COMPLETE"}}):
            with self.subTest(change=change):
                withheld = report.profile(projected | change)
                self.assertFalse(withheld["matched_with_required_covers"])
                self.assertFalse(withheld["within_profile"])
                self.assertEqual(withheld["stdout_delivery"], "NOT_STOCK_PIPE")
        projected["expected_result"] = {"status": "MISMATCHED", "observed_outcome": "VERIFIED"}
        rejected = report.profile(projected)
        self.assertFalse(rejected["matched_with_required_covers"])
        self.assertFalse(rejected["within_profile"])

    @staticmethod
    def _projection_fixture(target, *, failed_check_class=None, extra_assertion_failure=False):
        covers = target["covers"]
        failed = target["expected_outcome"] == "FAILED"
        assertions = list(target["required_assertions"])
        if failed:
            assertions.append(target["expected_failure"]["label"])
        props = []
        regular_lines = [f"Checking harness {target['selector']}...", "RESULTS:"]
        for i, label in enumerate(assertions, 1):
            status = "FAILURE" if failed and label == target["expected_failure"]["label"] else "SUCCESS"
            check_evidence = target.get("check_evidence") or {}
            anchor = (target.get("native_evidence", {}).get("coordinates", {}).get(label))
            if label in check_evidence.get("checked_assertions", []):
                function = check_evidence["target_instance"] + "::{closure#2}::{closure#0}"
            else:
                function = anchor["function"] if anchor else "synthetic_assertion"
            prop_id = f"{function}.assertion.{i}"
            location = (f"{anchor['file']}:{anchor['line']}:{anchor['column']} in function {function}" if anchor else
                        f"core/src/slice/sort/shared/smallsort/verify/synthetic.rs:{10+i}")
            regular_lines += [f"Check {len(props)+1}: {prop_id}", f"\t - Status: {status}",
                              f'\t - Description: "{label}"']
            if not (failed and label == target["expected_failure"]["label"]):
                regular_lines.append(f"\t - Location: {location}")
            stock = {"id": prop_id, "description": label, "class": "assertion",
                     "file": None, "line": None, "trace_available": failed and label == target["expected_failure"]["label"],
                     "status": status}
            if failed and label == target["expected_failure"]["label"]:
                failure_target = target["expected_failure"]
                loc = failure_target["file"] + f":{failure_target['line']}"
                if failure_target.get("column"):
                    loc += f":{failure_target['column']}"
                loc += " in function " + failure_target.get("function", "corrupt")
                regular_lines += [f"\t - Location: {loc}"]
                stock.update(file="library/" + failure_target["file"], line=str(failure_target["line"]))
            regular_lines.append("")
            props.append(stock)
        if target.get("native_evidence", {}).get("copy_back"):
            function = results.COPY_BACK_INSTANCE
            file, line, column = results.COPY_BACK_COORDINATE
            for suffix, description in results.COPY_BACK_PROPERTIES.items():
                prop_id = f"{function}.{suffix}"
                regular_lines += [f"Check {len(props)+1}: {prop_id}", "\t - Status: SUCCESS",
                                  f'\t - Description: "{description}"',
                                  f"\t - Location: {file}:{line}:{column} in function {function}", ""]
                props.append({"id": prop_id, "class": suffix.split(".")[0], "status": "SUCCESS"})
        if target["id"] in (results.U64_N26_N32_PLAIN_IDS | results.PILOT_PLAIN_IDS | results.CLOSE_SLOT_IDS
                            | results.N32_PLAIN_IDS | results.N32_CLOSURE_IDS):
            for anchor in target["native_evidence"]["required_properties"]:
                prop_id = anchor["id"]
                location = f"{anchor['file']}:{anchor['line']}:{anchor['column']} in function {anchor['function']}"
                regular_lines += [f"Check {len(props)+1}: {prop_id}", "\t - Status: SUCCESS",
                                  f'\t - Description: "{anchor["description"]}"',
                                  f"\t - Location: {location}", ""]
                props.append({"id": prop_id, "description": anchor["description"],
                              "class": anchor["class"], "file": anchor["file"],
                              "line": str(anchor["line"]), "status": "SUCCESS"})
        if target["id"] in results.spec.U64_N13_SLOT_IDS:
            # Generic swap property IDs are intentionally synthetic and opaque:
            # the production gate records their u64 function families without
            # freezing generated suffixes or multiplicities.
            for instance, file, line, column in (
                    ("ptr::copy::<u64>", "core/src/ptr/mod.rs", 682, 9),
                    ("ptr::copy_nonoverlapping::<u64>", "core/src/ptr/mod.rs", 587, 14)):
                prop_id = f"{instance}.safety_check.17"
                location = f"{file}:{line}:{column} in function {instance}"
                regular_lines += [f"Check {len(props)+1}: {prop_id}", "\t - Status: SUCCESS",
                                  '\t - Description: "synthetic generic pointer check"',
                                  f"\t - Location: {location}", ""]
                props.append({"id": prop_id, "description": "synthetic generic pointer check",
                              "class": "safety_check", "file": file, "line": str(line),
                              "status": "SUCCESS"})
        if target["id"] in results.INSERT_SLOT_IDS:
            instance = results.INSERT_COPY_INSTANCE
            functions = {"shift": "slice::sort::shared::smallsort::insert_tail",
                         "gap_fill": "slice::sort::shared::smallsort::CopyOnDrop<u64>::drop",
                         "ptr_wrapper": instance}
            copy_groups = [
                ("shift", "safety_check.97", "synthetic shift check"),
                ("gap_fill", "safety_check.98", "synthetic gap fill check"),
                *(("ptr_wrapper", suffix, description)
                  for suffix, description in results.COPY_BACK_PROPERTIES.items()),
            ]
            for role, suffix, description in copy_groups:
                file, line, column = results.spec.INSERT_COPY_COORDINATES[role]
                prop_id = f"{instance}.{suffix}"
                regular_lines += [f"Check {len(props)+1}: {prop_id}", "\t - Status: SUCCESS",
                                  f'\t - Description: "{description}"',
                                  f"\t - Location: {file}:{line}:{column} in function {functions[role]}", ""]
                props.append({"id": prop_id, "class": suffix.split(".")[0], "status": "SUCCESS"})
        if (target["id"] in results.U64_SLOT_IDS | results.PILOT_SLOT_IDS | results.FIX1_SLOT_IDS | results.CLOSE_SLOT_IDS
                or target["id"] in results.WIDE_N12_N14_CHECK_IDS | results.N32_SLOT_IDS | results.N32_CLOSURE_IDS):
            prop_id = "synthetic_u64_unwind.unwind.4"
            regular_lines += [f"Check {len(props)+1}: {prop_id}", "\t - Status: SUCCESS",
                              '\t - Description: "Unwinding assertion"',
                              "\t - Location: synthetic.rs:1 in function synthetic_u64_unwind", ""]
            props.append({"id": prop_id, "description": "Unwinding assertion", "class": "unwind",
                          "file": "synthetic.rs", "line": "1", "status": "SUCCESS"})
        check_evidence = target.get("check_evidence")
        check_symbol = target.get("check")
        if check_evidence:
            function = "core::" + check_evidence["target_instance"] + "::{closure#2}::{closure#0}"
            for kind, prefix in (("single_top_level_call", "Only a single top-level call"),
                                 ("no_recursive_call", "No recursive call")):
                prop_id = f"{function}.{kind}.1"
                description = f"{prefix} to function {check_symbol} when checking contract {check_symbol}"
                line = check_evidence["lines"][0]
                column = check_evidence.get("column", 1)
                location = f"{check_evidence['file']}:{line}:{column} in function {function}"
                regular_lines += [f"Check {len(props)+1}: {prop_id}", "\t - Status: SUCCESS",
                                  f'\t - Description: "{description}"', f"\t - Location: {location}", ""]
                props.append({"id": prop_id, "description": description, "class": kind,
                              "file": check_evidence["file"], "line": str(line),
                              "trace_available": False, "status": "SUCCESS"})
            for check_property in check_evidence["properties"]:
                prop_id = check_property["id"]
                description = check_property.get("description", "Synthetic required Check property")
                location = f"{check_property['file']}:{check_property['line']}"
                if check_property.get("column"):
                    location += f":{check_property['column']}"
                    location += " in function " + check_property.get("function", "synthetic_copy_contract")
                regular_lines += [f"Check {len(props)+1}: {prop_id}", "\t - Status: SUCCESS",
                                  f'\t - Description: "{description}"', f"\t - Location: {location}", ""]
                props.append({"id": prop_id, "description": description,
                              "class": check_property.get("class", "assertion"),
                              "file": check_property["file"], "line": str(check_property["line"]),
                              "trace_available": False, "status": "SUCCESS"})
            # Use the native builtin loop obligations from the FIX1 precedents.
            for helper, index, line in (("check_assignment", 1, 837), ("check_assignment", 2, 837),
                                        ("check_assignment", 3, 837), ("record_deallocated", 1, 740)):
                function = f"__CPROVER_contracts_write_set_{helper}"
                prop_id = f"{function}.unwind.{index}"
                location = f"<builtin-library-__CPROVER_contracts_library>:{line} in function {function}"
                regular_lines += [f"Check {len(props)+1}: {prop_id}", "\t - Status: SUCCESS",
                                  '\t - Description: "Unwinding assertion"', f"\t - Location: {location}", ""]
                props.append({"id": prop_id, "description": "Unwinding assertion", "class": "unwind",
                              "file": None, "line": None, "trace_available": False, "status": "SUCCESS"})
        if extra_assertion_failure:
            prop_id = "h.assertion.999"
            label = "UNEXPECTED_ASSERTION_FAILURE"
            regular_lines += [f"Check {len(props)+1}: {prop_id}", "\t - Status: FAILURE",
                              f'\t - Description: "{label}"', ""]
            props.append({"id": prop_id, "description": label, "class": "assertion",
                          "file": None, "line": None, "trace_available": True, "status": "FAILURE"})
        if failed_check_class:
            prop_id = f"h.{failed_check_class}.1"
            label = "unexpected native check failure"
            regular_lines += [f"Check {len(props)+1}: {prop_id}", "\t - Status: FAILURE",
                              f'\t - Description: "{label}"', ""]
            props.append({"id": prop_id, "description": label, "class": failed_check_class,
                          "file": None, "line": None, "trace_available": False, "status": "FAILURE"})
        for i, label in enumerate(covers, 1):
            anchor = target.get("native_evidence", {}).get("coordinates", {}).get(label)
            function = anchor["function"] if anchor else "synthetic_cover"
            prop_id = f"{function}.cover.{i}"
            location = (f"{anchor['file']}:{anchor['line']}:{anchor['column']} in function {function}" if anchor else
                        "core/src/slice/sort/shared/smallsort/verify/synthetic.rs:50")
            regular_lines += [f"Check {len(props)+1}: {prop_id}", "\t - Status: SATISFIED",
                              f'\t - Description: "{label}"',
                              f"\t - Location: {location}", ""]
            props.append({"id": prop_id, "description": label, "class": "cover",
                          "file": anchor["file"] if anchor else "core/src/slice/sort/shared/smallsort/verify/synthetic.rs",
                          "line": str(anchor["line"] if anchor else 50), "status": "SATISFIED"})
        failures = [p for p in props if p["status"] == "FAILURE"]
        check_total = sum(prop["class"] != "cover" for prop in props)
        check_success = check_total - len(failures)
        h = harness(target["selector"], unwind=36, verdict="FAILURE" if failed else "SUCCESS")
        if check_evidence:
            h["attributes"]["kind"] = {"ProofForContract": {"target_fn": check_symbol}}
            h["contract"] = {"contracted_function_name": check_symbol, "recursion_tracker": None}
        h.update(n_properties=len(props), n_failed=len(failures),
                 failure_kind="OTHER" if failed else "NONE", failed_properties=failures)
        h["checks"] = {"total": check_total, "success": check_success,
                       "failure": [p["id"] for p in failures], "unreachable": [], "undetermined": [],
                       "error": [], "unknown": [], "other": []}
        h["covers"] = {"total": len(covers), "satisfied": [p["id"] for p in props if p["class"] == "cover"],
                       "unsatisfiable": [], "unreachable": [], "undetermined": [], "error": [],
                       "unknown": [], "other": []}
        doc = export_document([h])
        doc["configuration"]["cbmc_args"] = ["--object-bits", "12"]
        doc["summary"].update(checks_total=check_total, checks_success=check_success,
                              covers_total=len(covers), covers_satisfied=len(covers))
        regular_lines += ["", "SUMMARY:", f" ** {len(failures)} of {check_total} failed",
                          f" ** {len(covers)} of {len(covers)} cover properties satisfied",
                          "VERIFICATION:- FAILED" if failed else "VERIFICATION:- SUCCESSFUL"]
        return ("\n".join(regular_lines) + "\n").encode(), doc

    def test_extra_native_failures_reject_legacy_control(self):
        control = n17_control_row()
        for check in ("pointer_dereference", "arithmetic_overflow", "unwind"):
            with self.subTest(check=check):
                self.write(*self._projection_fixture(control, failed_check_class=check))
                projected = results.project(self.directory, [control], self.child | {"exit_code": 1}, mode="singleton")
                self.assertEqual(projected["outcome"], "FAILED", projected)
                self.assertEqual(projected["expected_result"]["status"], "MISMATCHED")
                self.assertIn("sole failure", projected["expected_result"]["reason"])
        self.write(*self._projection_fixture(control, extra_assertion_failure=True))
        projected = results.project(self.directory, [control], self.child | {"exit_code": 1}, mode="singleton")
        self.assertEqual(projected["outcome"], "FAILED", projected)
        self.assertEqual(projected["observed_outcome"], "FAILED")
        self.assertEqual(projected["expected_result"]["status"], "MISMATCHED")
        self.assertIn("sole failure", projected["expected_result"]["reason"])

    def test_legacy_check_symbol_and_native_property_binding(self):
        root = row("SYNTHETIC-CHECK", SELECTOR_A, unwind=36) | {
            "check": "pair_step", "expected_outcome": "VERIFIED",
            "required_assertions": ["CURSORS"],
            "check_evidence": {
                "target_instance": "pair_step::<u8>", "file": "check.rs", "lines": [40],
                "checked_assertions": ["CURSORS"],
                "properties": [{"id": "memcpy.assigns.1", "file": "core/src/ptr/mod.rs", "line": 587}],
            },
        }
        self.write(*self._projection_fixture(root))
        observed = results.project(self.directory, [root], self.child, mode="singleton")
        self.assertEqual(observed["expected_result"]["status"], "MATCHED")
        stdout, doc = self._projection_fixture(root)
        h = doc["harnesses"][0]
        h["attributes"]["kind"]["ProofForContract"]["target_fn"] = "wrong_check"
        self.write(stdout, doc)
        wrong_check = results.project(self.directory, [root], self.child, mode="singleton")
        self.assertNotEqual(wrong_check["outcome"], "VERIFIED")

        stdout, doc = self._projection_fixture(root)
        doc["harnesses"][0]["contract"]["contracted_function_name"] = "foreign_contract_symbol"
        self.write(stdout, doc)
        unbound = results.project(self.directory, [root], self.child, mode="singleton")
        self.assertEqual(unbound["expected_result"]["status"], "MISMATCHED")
        self.assertIn("stock contract symbol", unbound["expected_result"]["reason"])

        stdout, doc = self._projection_fixture(root)
        anchor = root["check_evidence"]["properties"][0]
        location = f"{anchor['file']}:{anchor['line']}".encode()
        self.write(stdout.replace(location, b"wrong.rs:1"), doc)
        wrong_location = results.project(self.directory, [root], self.child, mode="singleton")
        self.assertEqual(wrong_location["expected_result"]["status"], "MISMATCHED")
        self.assertIn(anchor["id"], wrong_location["expected_result"]["reason"])

    def test_pilot_plain_and_check_roots_bind_exact_typed_copy_properties(self):
        pilot_rows = PILOT_ROWS
        self.assertEqual({row["id"] for row in pilot_rows}, set(results.PILOT_SLOT_IDS))
        for root in pilot_rows:
            with self.subTest(root=root["id"]):
                self.assertEqual(len(results._validate_rows([root])), 1)
                stdout, doc = self._projection_fixture(root)
                self.write(stdout, doc)
                matched = results.project(self.directory, [root], self.child, mode="singleton")
                self.assertEqual(matched["expected_result"]["status"], "MATCHED", matched)
                self.assertTrue(matched["result_evidence"]["mandatory_anchors"]["complete"])

                # Every required native copy property must keep its exact specialization and source.
                properties = (root.get("native_evidence") or {}).get("required_properties")
                if properties is None:
                    properties = root["check_evidence"]["properties"]
                copy_property = next(prop for prop in properties if prop["id"].startswith("ptr::copy_nonoverlapping"))
                wrong_id = copy_property["id"].rsplit(".", 1)[0] + ".99"
                bad_stdout = stdout.replace(copy_property["id"].encode(), wrong_id.encode(), 1)
                self.write(bad_stdout, doc)
                rejected = results.project(self.directory, [root], self.child, mode="singleton")
                self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])

                labels = [label for label in root["required_assertions"]
                          if label.endswith(("_FRAME", "_STABLE_EQUAL_KEYS", "_CURSORS"))]
                labels.extend(label for label in root["covers"] if label.endswith("_RETURNED"))
                for label in labels:
                    self.write(stdout.replace(label.encode(), b"LOST_NATIVE_LABEL"), doc)
                    rejected = results.project(self.directory, [root], self.child, mode="singleton")
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                    self.assertIn(label, rejected["expected_result"]["reason"])

                if root["check"] is None:
                    gate = root["native_evidence"]
                    bad_prop = dict(copy_property, function="ptr::copy_nonoverlapping::<wrong::Wide>")
                    bad_root = root | {"native_evidence": gate | {
                        "required_properties": [bad_prop if p["id"] == copy_property["id"] else p
                                                for p in properties]}}
                    with self.assertRaisesRegex(ValueError, "wrong typed-copy binding"):
                        results._validate_rows([bad_root])
                else:
                    gate = root["check_evidence"]
                    self.write(stdout.replace(b"memcpy.assigns.2", b"memcpy.assigns.99"), doc)
                    rejected = results.project(self.directory, [root], self.child, mode="singleton")
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                    self.assertIn("memcpy.assigns.2", rejected["expected_result"]["reason"])
                    bad_gate = gate | {"modifies": ["scratch.wrapping_add(k)", "scratch.wrapping_add(15 - k)"]}
                    with self.assertRaisesRegex(ValueError, "wrong target, source definition, or modifies scope"):
                        results._validate_rows([root | {"check_evidence": bad_gate}])
                key = "check_evidence" if root["check"] is not None else "native_evidence"
                bad_sites = list(root[key]["copy_sites"])
                bad_sites[0] = dict(bad_sites[0], line=bad_sites[0]["line"] + 1)
                source_gate = root[key] | {"copy_sites": bad_sites}
                with self.assertRaisesRegex(ValueError, "wrong local or actual typed-copy sites"):
                    results._validate_rows([root | {key: source_gate}])

    def test_fix1_directional_checks_bind_exact_targets_sites_and_scopes(self):
        self.assertEqual({root["id"] for root in FIX1_ROWS}, set(results.FIX1_SLOT_IDS))
        self.assertEqual(len(FIX1_ROWS), 2)
        self._check_split_merge_rows(FIX1_ROWS, results.spec.FIX1_MODIFIES)

    def test_wide_n12_n14_checks_bind_exact_targets_sites_and_scopes(self):
        self.assertEqual(results.spec.roster_digest(WIDE_N12_N14_ROWS), results.spec.WIDE_N12_N14_ROSTER_DIGEST)
        self.assertEqual(tuple(root["id"] for root in N12_N14_CHECK_ROWS), results.spec.WIDE_N12_N14_CHECK_SLOT_IDS)
        for length in (0, 2):
            self._check_split_merge_rows(N12_N14_CHECK_ROWS[length:length + 2], results.spec.WIDE_N12_N14_MODIFIES)
        # A Check of one length cannot carry the target, definition or binding of the other length.
        for root, other in zip(N12_N14_CHECK_ROWS, N12_N14_CHECK_ROWS[2:] + N12_N14_CHECK_ROWS[:2]):
            with self.subTest(root=root["id"], other=other["id"]):
                for field in ("target_instance", "definition"):
                    swapped = root["check_evidence"] | {field: other["check_evidence"][field]}
                    with self.assertRaisesRegex(ValueError, "wrong target, source definition, or direction scope"):
                        results._validate_rows([root | {"check_evidence": swapped}])
                with self.assertRaisesRegex(ValueError, "exact Proof role"):
                    results._validate_rows([root | {"check": other["check"]}])
                with self.assertRaisesRegex(ValueError, "wrong target, source definition, or direction scope"):
                    results._validate_rows([root | {"selector": other["selector"]}])
                with self.assertRaisesRegex(ValueError, "wrong target, source definition, or direction scope"):
                    results._validate_rows([root | {"check_evidence": root["check_evidence"] | {"column": 1}}])

    def test_n32_checks_bind_exact_targets_sites_scopes_and_copy_type(self):
        self.assertEqual(results.spec.roster_digest(N32_ROWS), results.spec.N32_PILOT_ROSTER_DIGEST)
        self.assertEqual(tuple(root["id"] for root in N32_CHECK_ROWS), results.spec.N32_CHECK_SLOT_IDS)
        for start in (0, 2):
            self._check_split_merge_rows(N32_CHECK_ROWS[start:start + 2], results.spec.N32_MODIFIES)
        for root in N32_CHECK_ROWS:
            kind = results.spec.N32_GEOMETRY[root["id"]][0]
            copy = "ptr::copy_nonoverlapping::<u64>" if kind == "u64" else f"ptr::copy_nonoverlapping::<{results.WIDE_TYPE}>"
            self.assertEqual({prop.get("function") for prop in root["check_evidence"]["properties"]} - {None}, {copy})
        # A Check of one type cannot carry the target, definition, selector or copy type of the other type.
        for root, other in zip(N32_CHECK_ROWS, N32_CHECK_ROWS[2:] + N32_CHECK_ROWS[:2]):
            with self.subTest(root=root["id"], other=other["id"]):
                for field in ("target_instance", "definition"):
                    swapped = root["check_evidence"] | {field: other["check_evidence"][field]}
                    with self.assertRaisesRegex(ValueError, "wrong target, source definition, or direction scope"):
                        results._validate_rows([root | {"check_evidence": swapped}])
                with self.assertRaisesRegex(ValueError, "exact Proof role"):
                    results._validate_rows([root | {"check": other["check"]}])
                with self.assertRaisesRegex(ValueError, "wrong target, source definition, or direction scope"):
                    results._validate_rows([root | {"selector": other["selector"]}])
                with self.assertRaisesRegex(ValueError, "scoped assigns and six typed-copy properties"):
                    results._validate_rows([root | {"check_evidence": root["check_evidence"] | {
                        "properties": other["check_evidence"]["properties"]}}])

    def test_n32_plain_supports_bind_selector_copy_type_sites_and_unwind(self):
        self.assertEqual(tuple(root["id"] for root in N32_PLAIN_ROWS), results.spec.N32_PLAIN_SLOT_IDS)
        self.assertEqual(results._validate_rows(N32_ROWS), [root["selector"] for root in N32_ROWS])
        for root in N32_PLAIN_ROWS:
            with self.subTest(root=root["id"]):
                stdout, doc = self._projection_fixture(root)
                self.write(stdout, doc)
                accepted = results.project(self.directory, [root], self.child, mode="singleton")
                self.assertEqual(accepted["expected_result"]["status"], "MATCHED", accepted)
                self.assertTrue(accepted["result_evidence"]["mandatory_anchors"]["complete"])
                copy_id = root["native_evidence"]["required_properties"][0]["id"]
                returned = next(label for label in root["covers"] if label.endswith("_RETURNED"))
                for label, replacement in ((copy_id, copy_id.rsplit(".", 1)[0] + ".99"),
                                           *((label, "LOST_POST") for label in root["required_assertions"]),
                                           (returned, "LOST_RETURN")):
                    self.write(stdout.replace(label.encode(), replacement.encode(), 1), doc)
                    rejected = results.project(self.directory, [root], self.child, mode="singleton")
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                    self.assertIn(label, rejected["expected_result"]["reason"])
                unwind = b"synthetic_u64_unwind.unwind.4\n\t - Status: SUCCESS"
                self.assertIn(unwind, stdout)
                self.write(stdout.replace(unwind, unwind.replace(b"SUCCESS", b"UNREACHABLE", 1)), doc)
                rejected = results.project(self.directory, [root], self.child, mode="singleton")
                self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                self.assertIn("every emitted unwind property", rejected["expected_result"]["reason"])
                native = root["native_evidence"]
                for change, message in (
                    ({"selector": root["selector"] + "_other"}, "exact plain Proof selector"),
                    ({"check": "actual_merge_up_u64_n32"}, "unexpected Check evidence specification"),
                    ({"expected_outcome": "FAILED", "expected_failure": {"label": "X", "file": "f", "line": 1,
                                                                         "class": "assertion"}},
                     "wrong expected outcome"),
                    ({"check_evidence": {"target_instance": "x"}}, "unexpected Check evidence specification"),
                    ({"native_evidence": native | {"copy_sites": native["copy_sites"][1:]}},
                     "wrong local or actual typed-copy sites"),
                ):
                    with self.subTest(change=sorted(change)), self.assertRaisesRegex(ValueError, message):
                        results._validate_rows([root | change])
        # A copy type, local site or role of another support is rejected.
        s8, fill_u64, fill_wide = N32_PLAIN_ROWS
        for root, other in ((fill_u64, fill_wide), (fill_wide, fill_u64), (s8, fill_wide)):
            with self.subTest(root=root["id"], other=other["id"]):
                wrong = root["native_evidence"] | {"required_properties": other["native_evidence"]["required_properties"]}
                if root is not s8:
                    with self.assertRaisesRegex(ValueError, "wrong typed-copy binding"):
                        results._validate_rows([root | {"native_evidence": wrong}])
                wrong = root["native_evidence"] | {"copy_sites": other["native_evidence"]["copy_sites"]}
                if root is s8:
                    with self.assertRaisesRegex(ValueError, "wrong local or actual typed-copy sites"):
                        results._validate_rows([root | {"native_evidence": wrong}])
        moved = deepcopy(fill_u64["native_evidence"])
        moved["copy_sites"][0]["column"] = 9
        with self.assertRaisesRegex(ValueError, "wrong local or actual typed-copy sites"):
            results._validate_rows([fill_u64 | {"native_evidence": moved}])

    def test_n32_closure_roots_bind_selector_sole_failure_copy_type_reached_sites_and_unwind(self):
        self.assertEqual(FROZEN_REQUEST["source_bindings"]["n32_closure_roster"], CLOSURE_ROWS)
        self.assertEqual(tuple(root["id"] for root in CLOSURE_ROWS), results.spec.N32_CLOSURE_SLOT_IDS)
        self.assertEqual(results._validate_rows(CLOSURE_ROWS), [root["selector"] for root in CLOSURE_ROWS])
        for root in CLOSURE_ROWS:
            failed = root["expected_outcome"] == "FAILED"
            child = self.child | {"exit_code": int(failed)}
            with self.subTest(root=root["id"]):
                stdout, doc = self._projection_fixture(root)
                self.write(stdout, doc)
                accepted = results.project(self.directory, [root], child, mode="singleton")
                self.assertEqual(accepted["expected_result"]["status"], "MATCHED", accepted)
                self.assertTrue(accepted["result_evidence"]["mandatory_anchors"]["complete"])
                # Lost typed-copy property, lost preliminary post, lost comparator or return cover.
                copy_id = root["native_evidence"]["required_properties"][0]["id"]
                for label, replacement in ((copy_id, copy_id.rsplit(".", 1)[0] + ".99"),
                                           *((label, "LOST_POST") for label in root["required_assertions"]),
                                           *((label, "LOST_COVER") for label in root["covers"])):
                    self.write(stdout.replace(f'"{label}"'.encode() if label != copy_id else label.encode(),
                                              f'"{replacement}"'.encode() if label != copy_id else replacement.encode(),
                                              1), doc)
                    rejected = results.project(self.directory, [root], child, mode="singleton")
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED", label)
                unwind = b"synthetic_u64_unwind.unwind.4\n\t - Status: SUCCESS"
                self.assertIn(unwind, stdout)
                self.write(stdout.replace(unwind, unwind.replace(b"SUCCESS", b"UNREACHABLE", 1)), doc)
                rejected = results.project(self.directory, [root], child, mode="singleton")
                self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                self.assertIn("every emitted unwind property", rejected["expected_result"]["reason"])
                # A second assertion failure, a failing safety or unwind check, or an UNDETERMINED obligation.
                for options in ({"extra_assertion_failure": True}, {"failed_check_class": "pointer_dereference"},
                                {"failed_check_class": "unwind"}):
                    self.write(*self._projection_fixture(root, **options))
                    rejected = results.project(self.directory, [root], child, mode="singleton")
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED", options)
                self.write(stdout.replace(unwind, unwind.replace(b"SUCCESS", b"UNDETERMINED", 1)), doc)
                rejected = results.project(self.directory, [root], child, mode="singleton")
                self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                native = root["native_evidence"]
                for change, message in (
                    ({"selector": root["selector"] + "_other"}, "exact plain Proof selector"),
                    ({"check": "actual_merge_up_u64_n32"}, "exact plain Proof selector|unexpected Check evidence"),
                    ({"stdout_delivery": "STDOUT_RELAY" if root["stdout_delivery"] == "STOCK_PIPE" else "STOCK_PIPE"},
                     "wrong frozen stdout delivery"),
                    ({"native_evidence": native | {"copy_sites": native["copy_sites"][1:]}},
                     "wrong actual typed-copy sites"),
                    ({"native_evidence": native | {"copy_back": True}}, "wrong actual typed-copy sites"),
                ):
                    with self.subTest(change=sorted(change)), self.assertRaisesRegex(ValueError, message):
                        results._validate_rows([root | change])
        s8, u64, wide = CLOSURE_ROWS
        # The S8 is VERIFIED; each control has exactly its own failure label and function.
        for root, other in ((s8, u64), (u64, wide), (wide, u64)):
            with self.subTest(root=root["id"], other=other["id"]):
                with self.assertRaisesRegex(ValueError, "wrong expected outcome or failure anchor"):
                    results._validate_rows([root | {"expected_outcome": other["expected_outcome"],
                                                    "expected_failure": other["expected_failure"]}])
        for root in (u64, wide):
            renamed = root["expected_failure"] | {"function": s8["selector"]}
            with self.assertRaisesRegex(ValueError, "wrong expected outcome or failure anchor"):
                results._validate_rows([root | {"expected_failure": renamed}])
        # A copy type or a reached-site list of the other route is rejected.
        for root, other in ((u64, wide), (wide, u64), (s8, wide)):
            with self.subTest(copy_type=root["id"]):
                wrong = root["native_evidence"] | {"required_properties": other["native_evidence"]["required_properties"]}
                with self.assertRaisesRegex(ValueError, "wrong typed-copy binding"):
                    results._validate_rows([root | {"native_evidence": wrong}])
        wrong = u64["native_evidence"] | {"copy_sites": s8["native_evidence"]["copy_sites"]}
        with self.assertRaisesRegex(ValueError, "wrong actual typed-copy sites"):
            results._validate_rows([u64 | {"native_evidence": wrong}])

    def test_n32_closure_controls_require_the_same_sole_failure_in_regular_and_stock(self):
        for root in CLOSURE_ROWS[1:]:
            with self.subTest(root=root["id"]):
                child = self.child | {"exit_code": 1}
                for field, value, reason in (
                    ("description", "ANOTHER_POST", "sole failure"),
                    ("line", "1", "stock failure location"),
                    ("id", "unrelated.assertion.1", "failure property IDs disagree"),
                ):
                    stdout, doc = self._projection_fixture(root)
                    h = doc["harnesses"][0]
                    failed = h["failed_properties"][0]
                    failed[field] = value
                    if field == "id":
                        h["checks"]["failure"] = [value]
                    self.write(stdout, doc)
                    rejected = results.project(self.directory, [root], child, mode="singleton")
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                    self.assertIn(reason, rejected["expected_result"]["reason"])
                # The pinned post of the other control is not this control's failure.
                stdout, doc = self._projection_fixture(root)
                other = CLOSURE_ROWS[1] if root is CLOSURE_ROWS[2] else CLOSURE_ROWS[2]
                label, other_label = root["expected_failure"]["label"], other["expected_failure"]["label"]
                self.write(stdout.replace(f'"{label}"'.encode(), f'"{other_label}"'.encode(), 1), doc)
                rejected = results.project(self.directory, [root], child, mode="singleton")
                self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                # A VERIFIED exit on a control is never a match.
                self.write(*self._projection_fixture(root | {"expected_outcome": "VERIFIED", "expected_failure": None}))
                rejected = results.project(self.directory, [root], self.child, mode="singleton")
                self.assertNotEqual(rejected["expected_result"]["status"], "MATCHED")

    def _check_split_merge_rows(self, rows, scopes):
        roots = {root["id"]: root for root in rows}
        for root in rows:
            with self.subTest(root=root["id"]):
                self.assertEqual(len(results._validate_rows([root])), 1)
                stdout, doc = self._projection_fixture(root)
                self.write(stdout, doc)
                accepted = results.project(self.directory, [root], self.child, mode="singleton")
                self.assertEqual(accepted["expected_result"]["status"], "MATCHED", accepted)
                self.assertTrue(accepted["result_evidence"]["mandatory_anchors"]["complete"])
                self.assertTrue(any(p.get("class") == "unwind" and p.get("status") == "SUCCESS"
                                    for p in accepted["native_checks"]))
                self.assertEqual(len(root["check_evidence"]["copy_sites"]), 1)
                self.assertEqual(root["check_evidence"]["modifies"], [scopes[root["id"]]])

                checked_label = root["check_evidence"]["checked_assertions"][0]
                self.write(stdout.replace(checked_label.encode(), b"LOST_CHECKED_LABEL", 1), doc)
                wrong_label = results.project(self.directory, [root], self.child, mode="singleton")
                self.assertEqual(wrong_label["expected_result"]["status"], "MISMATCHED")
                self.assertIn(checked_label, wrong_label["expected_result"]["reason"])

                unwind = b"synthetic_u64_unwind.unwind.4\n\t - Status: SUCCESS"
                self.assertIn(unwind, stdout)
                self.write(stdout.replace(unwind, unwind.replace(b"SUCCESS", b"UNREACHABLE"), 1), doc)
                failed_unwind = results.project(self.directory, [root], self.child, mode="singleton")
                self.assertEqual(failed_unwind["expected_result"]["status"], "MISMATCHED")
                self.assertIn("unwind evidence", failed_unwind["expected_result"]["reason"])

                wrong_target = root["check_evidence"] | {
                    "target_instance": root["check_evidence"]["target_instance"] + "_wrong"}
                with self.assertRaisesRegex(ValueError, "wrong target, source definition, or direction scope"):
                    results._validate_rows([root | {"check_evidence": wrong_target}])

                gate = root["check_evidence"]
                copy_property = next(prop for prop in gate["properties"]
                                     if prop["id"].startswith("ptr::copy_nonoverlapping"))
                for pid in (copy_property["id"], "memcpy.assigns.2"):
                    self.write(stdout.replace(pid.encode(), b"unused_property.1", 1), doc)
                    rejected = results.project(self.directory, [root], self.child, mode="singleton")
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                    self.assertIn(pid, rejected["expected_result"]["reason"])
                wrong_property = dict(copy_property, function="ptr::copy_nonoverlapping::<wrong::Wide>")
                wrong_properties = [wrong_property if prop is copy_property else prop for prop in gate["properties"]]
                with self.assertRaisesRegex(ValueError, "wrong typed-copy or assigns binding"):
                    results._validate_rows([root | {"check_evidence": gate | {"properties": wrong_properties}}])

                opposite = roots[next(rid for rid in roots if rid != root["id"])]
                wrong_scope = gate | {"modifies": opposite["check_evidence"]["modifies"]}
                with self.assertRaisesRegex(ValueError, "wrong target, source definition, or direction scope"):
                    results._validate_rows([root | {"check_evidence": wrong_scope}])

                wrong_site = gate | {"copy_sites": opposite["check_evidence"]["copy_sites"]}
                with self.assertRaisesRegex(ValueError, "wrong actual typed-copy site or direction"):
                    results._validate_rows([root | {"check_evidence": wrong_site}])

                wrong_checked = gate | {"checked_assertions": gate["checked_assertions"][:-1]}
                with self.assertRaisesRegex(ValueError, "four scoped wrapper assertions"):
                    results._validate_rows([root | {"check_evidence": wrong_checked}])

    def test_close_roots_require_typed_post_return_and_unwind_anchors(self):
        self.assertEqual(tuple(row["id"] for row in CLOSE_ROWS), results.spec.CLOSE_SLOT_IDS)
        self.assertEqual(tuple(row["id"] for row in WIDE_WITNESS_ROWS), (results.spec.WIDE_WITNESS_SLOT_ID,))
        self.assertEqual(tuple(row["id"] for row in N10_WITNESS_ROWS), (results.spec.N10_WITNESS_SLOT_ID,))
        self.assertEqual(tuple(row["id"] for row in N12_WITNESS_ROWS), (results.spec.N12_WITNESS_SLOT_ID,))
        self.assertEqual(tuple(row["id"] for row in N14_WITNESS_ROWS), (results.spec.N14_WITNESS_SLOT_ID,))
        self.assertEqual(WIDE_N12_N14_ROWS[4:], N14_WITNESS_ROWS)
        for root in CLOSE_ROWS + WIDE_WITNESS_ROWS + N10_WITNESS_ROWS + N12_WITNESS_ROWS + N14_WITNESS_ROWS:
            with self.subTest(root=root["id"]):
                child = self.child | {"exit_code": int(root["expected_outcome"] == "FAILED")}

                def project(stdout, doc):
                    self.write(stdout, doc)
                    return results.project(self.directory, [root], child, mode="singleton")

                stdout, doc = self._projection_fixture(root)
                accepted = project(stdout, doc)
                self.assertEqual(accepted["expected_result"]["status"], "MATCHED", accepted)
                self.assertTrue(accepted["result_evidence"]["mandatory_anchors"]["complete"])
                copy_id = root["native_evidence"]["required_properties"][0]["id"]
                returned = next(label for label in root["covers"] if "RETURN" in label)
                assertions = root["required_assertions"]
                if root["id"] not in results.spec.WITNESS_SLOT_IDS:
                    assertions = assertions[:1]
                other_copy_id = copy_id.rsplit(".", 1)[0] + ".99"
                for label, replacement in ((copy_id, other_copy_id),
                                           *((label, "LOST_POST") for label in assertions),
                                           (returned, "LOST_RETURN")):
                    rejected = project(stdout.replace(label.encode(), replacement.encode(), 1), doc)
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                    self.assertIn(label, rejected["expected_result"]["reason"])
                unwind = b"synthetic_u64_unwind.unwind.4\n\t - Status: SUCCESS"
                self.assertIn(unwind, stdout)
                rejected = project(stdout.replace(unwind, unwind.replace(b"SUCCESS", b"UNREACHABLE", 1)), doc)
                self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                self.assertIn("every emitted unwind property", rejected["expected_result"]["reason"])

    def test_close_controls_require_same_sole_failure_in_regular_and_stock(self):
        for root in CLOSE_ROWS[-2:] + WIDE_WITNESS_ROWS + N10_WITNESS_ROWS + N12_WITNESS_ROWS + N14_WITNESS_ROWS:
            with self.subTest(root=root["id"]):
                child = self.child | {"exit_code": 1}
                self.write(*self._projection_fixture(root, extra_assertion_failure=True))
                rejected = results.project(self.directory, [root], child, mode="singleton")
                self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                self.assertIn("sole failure", rejected["expected_result"]["reason"])

                for field, value, reason in (
                    ("description", "ANOTHER_POST", "sole failure"),
                    ("line", "1", "stock failure location"),
                    ("id", "unrelated.assertion.1", "failure property IDs disagree"),
                ):
                    stdout, doc = self._projection_fixture(root)
                    h = doc["harnesses"][0]
                    failed = h["failed_properties"][0]
                    failed[field] = value
                    if field == "id":
                        h["checks"]["failure"] = [value]
                    self.write(stdout, doc)
                    rejected = results.project(self.directory, [root], child, mode="singleton")
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                    self.assertIn(reason, rejected["expected_result"]["reason"])

    def test_literal_wide_witness_rejects_anchors_from_the_old_wide_root(self):
        root, = WIDE_WITNESS_ROWS
        old = next(row for row in CLOSE_ROWS if row["id"] == results.spec.CLOSE_SLOT_IDS[5])
        stdout, doc = self._projection_fixture(root)
        label = root["expected_failure"]["label"]
        anchor = root["native_evidence"]["coordinates"][label]
        old_anchor = old["native_evidence"]["coordinates"][label]
        location = f"{anchor['file']}:{anchor['line']}:{anchor['column']}"
        old_location = f"{old_anchor['file']}:{old_anchor['line']}:{old_anchor['column']}"
        self.assertIn(location.encode(), stdout)
        self.write(stdout.replace(location.encode(), old_location.encode(), 1), doc)
        rejected = results.project(self.directory, [root], self.child | {"exit_code": 1}, mode="singleton")
        self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
        self.assertIn(label, rejected["expected_result"]["reason"])

    def test_n10_wide_witness_rejects_the_n16_witness_geometry(self):
        root, = N10_WITNESS_ROWS
        old, = WIDE_WITNESS_ROWS
        child = self.child | {"exit_code": 1}
        self.write(*self._projection_fixture(root))
        accepted = results.project(self.directory, [root], child, mode="singleton")
        self.assertEqual(accepted["expected_result"]["status"], "MATCHED")
        self.write(*self._projection_fixture(old))
        rejected = results.project(self.directory, [root], child, mode="singleton")
        self.assertEqual((rejected["expected_result"]["status"], rejected["expected_result"]["observed_outcome"]),
                         ("UNAVAILABLE", "INCOMPLETE"))
        stdout, doc = self._projection_fixture(root)
        label = root["expected_failure"]["label"]
        anchor = root["native_evidence"]["coordinates"][label]
        old_anchor = old["native_evidence"]["coordinates"][old["expected_failure"]["label"]]
        location = f"{anchor['file']}:{anchor['line']}:{anchor['column']}"
        old_location = f"{old_anchor['file']}:{old_anchor['line']}:{old_anchor['column']}"
        for replaced in (stdout.replace(location.encode(), old_location.encode(), 1),
                         stdout.replace(label.encode(), old["expected_failure"]["label"].encode(), 1)):
            self.write(replaced, doc)
            rejected = results.project(self.directory, [root], child, mode="singleton")
            self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
        cross_half = "GEN_N10_WIDE_WITNESS_CROSS_HALF_TIE"
        self.assertIn(cross_half, root["covers"])
        self.write(stdout.replace(cross_half.encode(), b"LOST_TIE", 1), doc)
        rejected = results.project(self.directory, [root], child, mode="singleton")
        self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")

    def test_n12_wide_witness_rejects_the_n10_and_n16_witness_geometries(self):
        root, = N12_WITNESS_ROWS
        child = self.child | {"exit_code": 1}
        self.write(*self._projection_fixture(root))
        accepted = results.project(self.directory, [root], child, mode="singleton")
        self.assertEqual(accepted["expected_result"]["status"], "MATCHED")
        self.assertEqual(accepted["cover_summary"]["expected_reached_labels"], root["covers"])
        stdout, doc = self._projection_fixture(root)
        label = root["expected_failure"]["label"]
        anchor = root["native_evidence"]["coordinates"][label]
        location = f"{anchor['file']}:{anchor['line']}:{anchor['column']}"
        for old in (N10_WITNESS_ROWS[0], WIDE_WITNESS_ROWS[0]):
            with self.subTest(old=old["id"]):
                self.write(*self._projection_fixture(old))
                rejected = results.project(self.directory, [root], child, mode="singleton")
                self.assertEqual((rejected["expected_result"]["status"], rejected["expected_result"]["observed_outcome"]),
                                 ("UNAVAILABLE", "INCOMPLETE"))
                old_anchor = old["native_evidence"]["coordinates"][old["expected_failure"]["label"]]
                old_location = f"{old_anchor['file']}:{old_anchor['line']}:{old_anchor['column']}"
                for replaced in (stdout.replace(location.encode(), old_location.encode(), 1),
                                 stdout.replace(label.encode(), old["expected_failure"]["label"].encode(), 1)):
                    self.write(replaced, doc)
                    rejected = results.project(self.directory, [root], child, mode="singleton")
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
        for lost in ("GEN_N12_WIDE_WITNESS_CROSS_HALF_TIE", "AFTER_WIDE_N12_RETURN", "GEN_N12_WIDE_BEFORE_SWAP_PAIR"):
            self.write(stdout.replace(lost.encode(), b"LOST_LABEL", 1), doc)
            rejected = results.project(self.directory, [root], child, mode="singleton")
            self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")

    def test_historical_consumer_projections_require_exact_post_copy_and_covers(self):
        for root in FROZEN_REQUEST["source_bindings"]["consumer_roster"]:
            with self.subTest(root=root["id"]):
                failed = root["expected_outcome"] == "FAILED"
                child = self.child | {"exit_code": int(failed)}

                def project(stdout, doc, row=root):
                    self.write(stdout, doc)
                    return results.project(self.directory, [row], child, mode="singleton")

                stdout, doc = self._projection_fixture(root)
                accepted = project(stdout, doc)
                self.assertEqual(accepted["outcome"], root["expected_outcome"])
                self.assertEqual(accepted["expected_result"]["status"], "MATCHED")
                anchors = accepted["result_evidence"]["mandatory_anchors"]
                self.assertTrue(anchors["complete"])
                copy_ids = {p["id"] for p in anchors["regular_properties"]
                            if p["id"].startswith(results.COPY_BACK_INSTANCE + ".")}
                self.assertEqual(copy_ids, {f"{results.COPY_BACK_INSTANCE}.{suffix}"
                                            for suffix in results.COPY_BACK_PROPERTIES})
                invalid = root | {"native_evidence": root["native_evidence"] | {"copy_back": False}}
                self.assertIn("requires copy_back=true", project(stdout, doc, invalid)["reason"])

                post = root["expected_failure"]["label"] if failed else root["required_assertions"][-1]
                anchor = root["native_evidence"]["coordinates"][post]
                exact = f"{anchor['file']}:{anchor['line']}:{anchor['column']}".encode()
                self.assertIn(exact, stdout)
                for original, wrong in ((exact, exact[:-1] + b"9"),
                                        (min(copy_ids).encode(), min(copy_ids).rsplit(".", 1)[0].encode() + b".99"),
                                        (b"core/src/ptr/mod.rs:587:14", b"core/src/ptr/mod.rs:587:15")):
                    rejected = project(stdout.replace(original, wrong, 1), doc)
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                    self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])

                for label in root["covers"]:
                    if "AFTER_COPY_BACK" not in label and "ODD_" not in label:
                        continue
                    rejected = project(stdout.replace(label.encode(), b"LOST_COVER"), doc)
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                    self.assertIn(label, rejected["expected_result"]["reason"])
                if failed:
                    extra = project(*self._projection_fixture(root, extra_assertion_failure=True))
                    self.assertIn("sole failure", extra["expected_result"]["reason"])
                    mismatch = project(*self._projection_fixture(root, failed_check_class="unwind"))
                    self.assertIn("unwind property", mismatch["expected_result"]["reason"])

    def test_copy_back_projections_require_every_post_copy_property_and_return_cover(self):
        for root in COPY_BACK_ROWS:
            with self.subTest(root=root["id"]):
                child = self.child | {"exit_code": 0}

                def project(stdout, doc, row=root):
                    self.write(stdout, doc)
                    return results.project(self.directory, [row], child, mode="singleton")

                stdout, doc = self._projection_fixture(root)
                accepted = project(stdout, doc)
                self.assertEqual(accepted["outcome"], "VERIFIED")
                self.assertEqual(accepted["expected_result"]["status"], "MATCHED")
                anchors = accepted["result_evidence"]["mandatory_anchors"]
                self.assertTrue(anchors["complete"])
                copy_ids = {p["id"] for p in anchors["regular_properties"]
                            if p["id"].startswith(results.COPY_BACK_INSTANCE + ".")}
                self.assertEqual(copy_ids, {f"{results.COPY_BACK_INSTANCE}.{suffix}"
                                            for suffix in results.COPY_BACK_PROPERTIES})
                invalid = root | {"native_evidence": root["native_evidence"] | {"copy_back": False}}
                self.assertIn("requires copy_back=true", project(stdout, doc, invalid)["reason"])

                for label in (*root["required_assertions"], *root["covers"]):
                    anchor = root["native_evidence"]["coordinates"][label]
                    coordinate = f"{anchor['file']}:{anchor['line']}:{anchor['column']}"
                    function = anchor["function"]
                    for original, wrong in (
                        (label, "LOST_POST_OR_COVER"),
                        (coordinate, f"{coordinate.rsplit(':', 1)[0]}:{anchor['column'] + 1}"),
                        (f"in function {function}", f"in function {function}_other"),
                    ):
                        self.assertIn(original.encode(), stdout)
                        rejected = project(stdout.replace(original.encode(), wrong.encode(), 1), doc)
                        self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                        self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])

                for copy_id in sorted(copy_ids):
                    wrong_id = copy_id.rsplit(".", 1)[0] + ".99"
                    rejected = project(stdout.replace(copy_id.encode(), wrong_id.encode(), 1), doc)
                    self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                    self.assertIn(copy_id, rejected["expected_result"]["reason"])
                    self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])
                shifted = project(stdout.replace(b"core/src/ptr/mod.rs:587:14", b"core/src/ptr/mod.rs:587:15", 1), doc)
                self.assertFalse(shifted["result_evidence"]["mandatory_anchors"]["complete"])
                self.assertEqual(shifted["expected_result"]["status"], "MISMATCHED")

                properties = accepted["native_checks"]
                unwind = {"class": "unwind", "status": "SUCCESS"}
                errors, _ = results._native_source_evidence(root, [*properties, unwind])
                self.assertFalse(errors)
                errors, _ = results._native_source_evidence(root, [*properties, unwind | {"status": "UNREACHABLE"}])
                self.assertTrue(any("unwind property" in error for error in errors))

    def test_merge_check_projections_bind_all_eight_specializations(self):
        expected_ids = {
            *(f"N{n}-PAIR-FIXED" for n in range(26, 31)),
            "N27-ODD-CENTER", "N29-ODD-CENTER", "N31-ODD-CENTER",
        }
        self.assertEqual({target["id"] for target in MERGE_ROWS}, expected_ids)
        for target in MERGE_ROWS:
            with self.subTest(root=target["id"]):
                stdout, doc = self._projection_fixture(target)
                self.write(stdout, doc)
                child = self.child | {"exit_code": int(target["expected_outcome"] == "FAILED")}
                projected = results.project(self.directory, [target], child, mode="singleton")
                self.assertEqual(projected["outcome"], target["expected_outcome"], projected)
                self.assertEqual(projected["expected_result"]["status"], "MATCHED", projected["expected_result"])
                anchors = projected["result_evidence"]["mandatory_anchors"]
                self.assertTrue(anchors["complete"])
                unwind_records = [p for p in anchors["regular_properties"] if p["class"] == "unwind"]
                self.assertEqual(len(unwind_records), 4)
                self.assertTrue(all(p["status"] == "SUCCESS" for p in unwind_records))
                expected_copy_anchors = sum(
                    anchor["id"].startswith("ptr::copy_nonoverlapping::<u8>.")
                    for anchor in target.get("check_evidence", {}).get("properties", []))
                self.assertEqual(sum(p["id"].startswith("ptr::copy_nonoverlapping::<u8>.")
                                     for p in anchors["regular_properties"]),
                                 expected_copy_anchors if not child["exit_code"] else 0)
                post = target["required_assertions"][-1]
                anchor = target["native_evidence"]["coordinates"][post]
                exact = f"{anchor['file']}:{anchor['line']}:{anchor['column']}".encode()
                wrong = f"{anchor['file']}:{anchor['line']}:{anchor['column'] + 1}".encode()
                self.assertIn(exact, stdout)
                self.write(stdout.replace(exact, wrong, 1), doc)
                rejected = results.project(self.directory, [target], child, mode="singleton")
                self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
                self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])

                if target.get("check_evidence"):
                    stdout, doc = self._projection_fixture(target)
                    doc["harnesses"][0]["attributes"]["kind"]["ProofForContract"]["target_fn"] = "foreign_check"
                    self.write(stdout, doc)
                    rejected = results.project(self.directory, [target], self.child, mode="singleton")
                    self.assertNotEqual(rejected["expected_result"]["status"], "MATCHED")

                    stdout, doc = self._projection_fixture(target)
                    check_gate = target["check_evidence"]
                    exact_call = f"{check_gate['file']}:{check_gate['lines'][0]}:1".encode()
                    self.assertIn(exact_call, stdout)
                    wrong_call = f"{check_gate['file']}:{check_gate['lines'][0]}:2".encode()
                    self.write(stdout.replace(exact_call, wrong_call), doc)
                    rejected = results.project(self.directory, [target], self.child, mode="singleton")
                    self.assertNotEqual(rejected["expected_result"]["status"], "MATCHED")

                    stdout, doc = self._projection_fixture(target)
                    unwind_id = b"__CPROVER_contracts_write_set_check_assignment.unwind.1"
                    marker = unwind_id + b"\n\t - Status: SUCCESS"
                    self.assertIn(marker, stdout)
                    self.write(stdout.replace(marker, unwind_id + b"\n\t - Status: FAILURE", 1), doc)
                    rejected = results.project(self.directory, [target], self.child, mode="singleton")
                    self.assertNotEqual(rejected["expected_result"]["status"], "MATCHED")

                    stdout, doc = self._projection_fixture(target)
                    self.write(stdout.replace(b".unwind.", b".foreignunwind."), doc)
                    rejected = results.project(self.directory, [target], self.child, mode="singleton")
                    self.assertNotEqual(rejected["expected_result"]["status"], "MATCHED")

    def test_merge_checks_reject_copy_back_evidence(self):
        for root in MERGE_ROWS:
            with self.subTest(slot=root["id"]):
                self.write(*self._projection_fixture(root))
                invalid = root | {"native_evidence": root["native_evidence"] | {"copy_back": True}}
                projected = results.project(self.directory, [invalid], self.child, mode="singleton")
                self.assertEqual(projected["outcome"], "INCOMPLETE")
                self.assertFalse(projected["complete"])
                self.assertIn("requires copy_back=false", projected["reason"])

    def test_merge_checks_require_grouped_ptr_anchors_and_centers_require_sentinel(self):
        for target in MERGE_ROWS:
            with self.subTest(root=target["id"], mutation="positive"):
                stdout, doc = self._projection_fixture(target)
                self.write(stdout, doc)
                accepted = results.project(self.directory, [target], self.child, mode="singleton")
                self.assertEqual(accepted["expected_result"]["status"], "MATCHED",
                                 accepted["expected_result"])

            with self.subTest(root=target["id"], mutation="grouped ptr anchor"):
                stdout, doc = self._projection_fixture(target)
                grouped = next(anchor for anchor in target["check_evidence"]["properties"]
                               if anchor["id"].startswith("ptr::copy_nonoverlapping"))
                exact = f"{grouped['file']}:{grouped['line']}:{grouped['column']}".encode()
                wrong = f"{grouped['file']}:{grouped['line']}:{grouped['column'] + 1}".encode()
                self.assertIn(exact, stdout)
                self.write(stdout.replace(exact, wrong), doc)
                rejected = results.project(self.directory, [target], self.child, mode="singleton")
                self.assertNotEqual(rejected["expected_result"]["status"], "MATCHED")

            with self.subTest(root=target["id"], mutation="dropped grouped ptr anchor"):
                stdout, doc = self._projection_fixture(target)
                grouped = next(anchor for anchor in target["check_evidence"]["properties"]
                               if anchor["id"].startswith("ptr::copy_nonoverlapping"))
                self.assertIn(grouped["id"].encode(), stdout)
                self.write(stdout.replace(grouped["id"].encode(), b"foreign_copy_property", 1), doc)
                rejected = results.project(self.directory, [target], self.child, mode="singleton")
                self.assertNotEqual(rejected["expected_result"]["status"], "MATCHED")

        odd_rows = [target for target in MERGE_ROWS if target["id"].endswith("-ODD-CENTER")]
        self.assertEqual({target["id"] for target in odd_rows},
                         {"N27-ODD-CENTER", "N29-ODD-CENTER", "N31-ODD-CENTER"})
        for target in odd_rows:
            with self.subTest(root=target["id"], mutation="sentinel cover"):
                sentinel = next(label for label in target["covers"] if "SENTINEL" in label.upper())
                stdout, doc = self._projection_fixture(target)
                self.write(stdout.replace(sentinel.encode(), b"LOST_SENTINEL_COVER"), doc)
                rejected = results.project(self.directory, [target], self.child, mode="singleton")
                self.assertNotEqual(rejected["expected_result"]["status"], "MATCHED")

    def test_pair_check_rejects_shifted_copy_anchor(self):
        root = next(row for row in MERGE_ROWS if row["id"] == "N26-PAIR-FIXED")
        stdout, doc = self._projection_fixture(root)
        self.write(stdout, doc)
        accepted = results.project(self.directory, [root], self.child, mode="singleton")
        self.assertEqual(accepted["expected_result"]["status"], "MATCHED")

        location = b"core/src/ptr/mod.rs:587:14"
        self.assertIn(location, stdout)
        self.write(stdout.replace(location, b"core/src/ptr/mod.rs:588:14", 1), doc)
        rejected = results.project(self.directory, [root], self.child, mode="singleton")
        self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
        self.assertIn("ptr::copy_nonoverlapping::<u8>.precondition_instance.1",
                      rejected["expected_result"]["reason"])
        self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])

    def test_merge_roots_require_exact_roles_frames_and_covers(self):
        root = next(row for row in MERGE_ROWS if row["id"] == "N27-ODD-CENTER")
        for field in ("has_loop_contracts", "should_panic"):
            with self.subTest(field=field):
                stdout, doc = self._projection_fixture(root)
                h = doc["harnesses"][0]
                if field == "should_panic":
                    h["attributes"][field] = True
                else:
                    h[field] = True
                self.write(stdout, doc)
                projected = results.project(self.directory, [root], self.child, mode="singleton")
                self.assertFalse(projected["complete"])
                self.assertIn("REV2 proof root must run without loop contracts or should_panic",
                              projected["stock"]["reason"])

        for lost_cover in root["covers"]:
            if lost_cover.startswith("CAL1"):
                continue
            with self.subTest(missing_cover=lost_cover):
                stdout, doc = self._projection_fixture(root)
                lines = stdout.decode().replace(f'Description: "{lost_cover}"',
                                                f'Description: "{lost_cover}_LOST"')
                self.write(lines.encode(), doc)
                missing = results.project(self.directory, [root], self.child, mode="singleton")
                self.assertEqual(missing["expected_result"]["status"], "MISMATCHED")
                self.assertIn(lost_cover, missing["expected_result"]["reason"])

        stdout, doc = self._projection_fixture(root)
        sentinel = next(label for label in root["covers"] if "SENTINEL" in label.upper())
        self.write(stdout.replace(sentinel.encode(), b"LOST_SENTINEL"), doc)
        wrong_sentinel = results.project(self.directory, [root], self.child, mode="singleton")
        self.assertEqual(wrong_sentinel["expected_result"]["status"], "MISMATCHED")
        self.assertIn(sentinel, wrong_sentinel["expected_result"]["reason"])

    def test_pair_binding_rejects_foreign_specialization(self):
        root = next(row for row in MERGE_ROWS if row["id"] == "N26-PAIR-FIXED")
        label = "REV2_N26_PAIR_FIXED_UP_CURSORS"
        function = root["native_evidence"]["coordinates"][label]["function"].encode()
        self.assertIn(b"actual_pair_step_n26", function)
        stdout, doc = self._projection_fixture(root)
        self.write(stdout.replace(b"in function " + function,
                                b"in function " + function.replace(b"actual_pair_step_n26",
                                                                   b"actual_pair_step_n27")), doc)
        rejected = results.project(self.directory, [root], self.child, mode="singleton")
        self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
        self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])

    def test_pair_cursor_anchor_requires_its_nested_column(self):
        root = next(row for row in MERGE_ROWS if row["id"] == "N26-PAIR-FIXED")
        label = "REV2_N26_PAIR_FIXED_UP_CURSORS"
        anchor = root["native_evidence"]["coordinates"][label]
        line, column = anchor["line"], anchor["column"]
        self.assertEqual(column, 9)
        stdout, doc = self._projection_fixture(root)
        self.write(stdout, doc)
        accepted = results.project(self.directory, [root], self.child, mode="singleton")
        self.assertEqual(accepted["expected_result"]["status"], "MATCHED")

        self.write(stdout.replace(f"{anchor['file']}:{line}:{column}".encode(),
                                  f"{anchor['file']}:{line}:5".encode()), doc)
        rejected = results.project(self.directory, [root], self.child, mode="singleton")
        self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
        self.assertIn(label, rejected["expected_result"]["reason"])
        self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])

    def test_n26_n32_u64_rows_require_typed_copy_scoped_and_return_evidence(self):
        plain = next(row for row in PROVIDER_ROWS if row["check"] is None)
        stdout, doc = self._projection_fixture(plain)
        self.write(stdout, doc)
        accepted = results.project(self.directory, [plain], self.child, mode="singleton")
        self.assertEqual(accepted["expected_result"]["status"], "MATCHED", accepted["expected_result"])
        required = {p["id"] for p in plain["native_evidence"]["required_properties"]}
        observed = {p["id"] for p in accepted["result_evidence"]["mandatory_anchors"]["regular_properties"]}
        self.assertTrue(required <= observed)

        for prefix in ("ptr::copy::<u64>.", "ptr::copy_nonoverlapping::<u64>."):
            with self.subTest(missing=prefix):
                stdout, doc = self._projection_fixture(plain)
                missing = next(p["id"] for p in plain["native_evidence"]["required_properties"]
                               if p["id"].startswith(prefix))
                self.assertIn(missing.encode(), stdout)
                self.write(stdout.replace(missing.encode(), b"foreign_typed_copy_property", 1), doc)
                rejected = results.project(self.directory, [plain], self.child, mode="singleton")
                self.assertNotEqual(rejected["expected_result"]["status"], "MATCHED")
                self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])

        check = next(row for row in PROVIDER_ROWS if row["check"] is not None)
        stdout, doc = self._projection_fixture(check)
        self.assertIn(b"memcpy.assigns.1", stdout)
        self.write(stdout.replace(b"memcpy.assigns.1", b"foreign_scoped_assign", 1), doc)
        rejected = results.project(self.directory, [check], self.child, mode="singleton")
        self.assertNotEqual(rejected["expected_result"]["status"], "MATCHED")
        self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])
        stdout, doc = self._projection_fixture(check)
        returned = next(label for label in check["covers"] if label.endswith("_RETURNED"))
        self.assertIn(returned.encode(), stdout)
        self.write(stdout.replace(returned.encode(), b"LOST_RETURN_COVER", 1), doc)
        rejected = results.project(self.directory, [check], self.child, mode="singleton")
        self.assertEqual(rejected["expected_result"]["status"], "MISMATCHED")
        self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])

    def test_n26_n32_consumer_copyback_uses_u64_groups_without_u8_wrapper_groups(self):
        for root in (CONSUMER_ROWS[0], CONSUMER_ROWS[-1]):
            with self.subTest(slot=root["id"]):
                stdout, doc = self._projection_fixture(root)
                self.write(stdout, doc)
                accepted = results.project(self.directory, [root], self.child | {
                    "exit_code": int(root["expected_outcome"] == "FAILED")}, mode="singleton")
                self.assertEqual(accepted["expected_result"]["status"], "MATCHED",
                                 accepted["expected_result"])
                required = {p["id"] for p in root["native_evidence"]["required_properties"]}
                observed = {p["id"] for p in accepted["result_evidence"]["mandatory_anchors"]["regular_properties"]}
                self.assertTrue(required <= observed)
                self.assertFalse(any(p.startswith("ptr::copy_nonoverlapping::<u8>") for p in observed))

    def test_u64_odd_center_receipts_bind_the_transcribed_copy_site(self):
        centers = {"U64-N27-ODD-CENTER": (13, 1018), "U64-N29-ODD-CENTER": (14, 1104),
                   "U64-N31-ODD-CENTER": (15, 1190)}
        diagnostics = Mock()
        diagnostics.publication.return_value = [], {}
        slots = {slot[0]: slot for slot in run.expected_slots(PROVIDER_REQUEST)}
        for key, (midpoint, line) in centers.items():
            with self.subTest(slot=key):
                slot = slots[key]
                target, = slot[2]
                self.write(*self._projection_fixture(target))
                record = run.receipt(slot, "VERIFIED", "EXITED") | {"child": self.child, "last_phase": None}
                run.slot_projection(self.directory, self.directory, record, diagnostics)
                run.save_receipt(self.directory, record)
                receipt = results.spec.read(self.directory / "artifact" / "slots" / key / "receipt.json")
                self.assertEqual(receipt["expected_result"]["status"], "MATCHED")
                anchors = receipt["result_evidence"]["mandatory_anchors"]
                self.assertTrue(anchors["complete"])
                self.assertEqual(anchors["checked_write_set"]["copy_sites"], [{
                    "file": results.spec.MODULE_FILE, "line": line, "column": 9,
                    "token": f"ptr::copy_nonoverlapping(last_src, scratch.add({midpoint}), 1);",
                    "transcribes": {"file": results.spec.SMALLSORT_FILE, "line": 1034, "column": 13,
                                    "token": "ptr::copy_nonoverlapping(last_src, dst, 1);"},
                }])
                self.assertFalse(any(":1034:13" in (prop["location"] or "")
                                     for prop in anchors["regular_properties"]))

    def test_u64_n13_results_bind_typed_anchors_and_record_generic_swap_properties(self):
        self.assertEqual({target["id"] for target in U64_N13_ROWS}, {
            "U64-N13-SWAP", "U64-N13-S13-BITS", "U64-N13-S13-CORRUPT"})
        self.assertEqual(tuple(results.spec.U64_N13_SLOT_IDS), tuple(target["id"] for target in U64_N13_ROWS))
        for target in U64_N13_ROWS:
            with self.subTest(slot=target["id"]):
                with self.assertRaisesRegex(ValueError, "Check evidence"):
                    results._validate_rows([target | {"check": "unexpected_check",
                                                       "check_evidence": {}}])
                with self.assertRaisesRegex(ValueError, "plain Proof"):
                    results._validate_rows([target | {"replace": ["unexpected_replace"]}])
                failed = target["expected_outcome"] == "FAILED"
                stdout, doc = self._projection_fixture(target)
                child = self.child | {"exit_code": int(failed)}
                self.write(stdout, doc)
                accepted = results.project(self.directory, [target], child, mode="singleton")
                self.assertEqual(accepted["outcome"], target["expected_outcome"], accepted)
                self.assertEqual(accepted["expected_result"]["status"], "MATCHED",
                                 accepted["expected_result"])
                anchors = accepted["result_evidence"]["mandatory_anchors"]
                self.assertTrue(anchors["complete"])
                telemetry = [p for p in anchors["regular_properties"]
                             if p["id"].startswith(("ptr::copy::<u64>.",
                                                    "ptr::copy_nonoverlapping::<u64>."))]
                self.assertEqual(len(telemetry), 2)
                # The projected IDs stay visible, while opaque generated suffixes
                # are not part of the acceptance predicate.
                opaque = stdout.replace(b".safety_check.17", b".safety_check.987")
                self.write(opaque, doc)
                renamed = results.project(self.directory, [target], child, mode="singleton")
                self.assertEqual(renamed["expected_result"]["status"], "MATCHED",
                                 renamed["expected_result"])

                failed_unwind = stdout.replace(
                    b"synthetic_u64_unwind.unwind.4\n\t - Status: SUCCESS",
                    b"synthetic_u64_unwind.unwind.4\n\t - Status: FAILURE", 1)
                self.write(failed_unwind, doc)
                rejected_unwind = results.project(self.directory, [target], child, mode="singleton")
                self.assertNotEqual(rejected_unwind["expected_result"]["status"], "MATCHED")
                self.assertIn("unwind", rejected_unwind["expected_result"]["reason"])

                unreachable = stdout.replace(
                    b"ptr::copy::<u64>.safety_check.17\n\t - Status: SUCCESS",
                    b"ptr::copy::<u64>.safety_check.17\n\t - Status: UNREACHABLE", 1)
                self.write(unreachable, doc)
                rejected_status = results.project(self.directory, [target], child, mode="singleton")
                self.assertNotEqual(rejected_status["expected_result"]["status"], "MATCHED")

                first = target["native_evidence"]["coordinates"]
                label = target["covers"][0]
                anchor = first[label]
                wrong_class = stdout.replace(
                    f"{anchor['file']}:{anchor['line']}:{anchor['column']}".encode(),
                    f"{anchor['file']}:{anchor['line']}:{anchor['column'] + 1}".encode(), 1)
                self.write(wrong_class, doc)
                rejected_anchor = results.project(self.directory, [target], child, mode="singleton")
                self.assertEqual(rejected_anchor["expected_result"]["status"], "MISMATCHED")
                self.assertFalse(rejected_anchor["result_evidence"]["mandatory_anchors"]["complete"])
                wrong_role = target | {"native_evidence": target["native_evidence"] | {
                    "coordinates": target["native_evidence"]["coordinates"] | {
                        label: anchor | {"class": "assertion"}}}}
                with self.assertRaisesRegex(ValueError, "class disagrees with role"):
                    results._validate_rows([wrong_role])

                if failed:
                    extra = self._projection_fixture(target, extra_assertion_failure=True)
                    self.write(*extra)
                    rejected_extra = results.project(self.directory, [target], child, mode="singleton")
                    self.assertIn("sole failure", rejected_extra["expected_result"]["reason"])

    def test_u64_regular_stock_anchors_and_exit(self):
        for target in (*U64_N14_N17_ROWS, *PROVIDER_ROWS, *CONSUMER_ROWS):
            with self.subTest(slot=target["id"]):
                failed = target["expected_outcome"] == "FAILED"
                stdout, doc = self._projection_fixture(target)
                child = self.child | {"exit_code": int(failed)}
                self.write(stdout, doc)
                accepted = results.project(self.directory, [target], child, mode="singleton")
                self.assertEqual(accepted["expected_result"]["status"], "MATCHED", accepted["expected_result"])
                self.assertEqual(accepted["observed_outcome"], target["expected_outcome"])
                self.assertTrue(accepted["result_evidence"]["mandatory_anchors"]["complete"])
                for label, anchor in target["native_evidence"]["coordinates"].items():
                    location = f"{anchor['file']}:{anchor['line']}:{anchor['column']}".encode()
                    self.assertIn(location, stdout, label)
                    self.write(stdout.replace(location, location + b"9", 1), doc)
                    bad = results.project(self.directory, [target], child, mode="singleton")
                    self.assertEqual(bad["expected_result"]["status"], "MISMATCHED", label)
                    self.assertFalse(bad["result_evidence"]["mandatory_anchors"]["complete"])
                self.write(stdout.replace(b" - Status: SATISFIED", b" - Status: UNSATISFIABLE", 1), doc)
                lost_cover = results.project(self.directory, [target], child, mode="singleton")
                self.assertNotEqual(lost_cover["expected_result"]["status"], "MATCHED")
                self.write(stdout.replace(b"synthetic_u64_unwind.unwind.4\n\t - Status: SUCCESS",
                                          b"synthetic_u64_unwind.unwind.4\n\t - Status: FAILURE"), doc)
                unwind = results.project(self.directory, [target], child, mode="singleton")
                self.assertIn("unwind", unwind["expected_result"]["reason"])
                self.write(stdout, doc)
                wrong_exit = results.project(self.directory, [target], child | {"exit_code": int(not failed)},
                                             mode="singleton")
                self.assertNotEqual(wrong_exit["expected_result"]["status"], "MATCHED")
                if failed:
                    self.write(*self._projection_fixture(target, extra_assertion_failure=True))
                    extra_failure = results.project(self.directory, [target], child, mode="singleton")
                    self.assertIn("sole failure", extra_failure["expected_result"]["reason"])

    def test_insert_copy_ids_keep_caller_coordinates_separate_from_wrapper(self):
        rows = [U64_N14_N17_ROWS[0], *(row for row in PROVIDER_ROWS if row["id"] in results.INSERT_SLOT_IDS)]
        for root in rows:
            with self.subTest(slot=root["id"]):
                stdout, doc = self._projection_fixture(root)
                self.write(stdout, doc)
                projected = results.project(self.directory, [root], self.child, mode="singleton")
                evidence = projected["result_evidence"]["mandatory_anchors"]["insert_copy_safety"]
                instance = results.INSERT_COPY_INSTANCE
                self.assertEqual(evidence["shift"]["regular_ids"], [instance + ".safety_check.97"])
                self.assertEqual(evidence["gap_fill"]["regular_ids"], [instance + ".safety_check.98"])
                self.assertEqual(evidence["ptr_wrapper"]["regular_ids"],
                                 [f"{instance}.{suffix}" for suffix in results.COPY_BACK_PROPERTIES])
                self.assertFalse(evidence["unattributed_regular_ids"])

                self.write(stdout.replace(b"core/src/ptr/mod.rs:587:14",
                                          b"core/src/ptr/mod.rs:587:15", 1), doc)
                shifted = results.project(self.directory, [root], self.child, mode="singleton")
                self.assertIn("copy_nonoverlapping safety groups", shifted["expected_result"]["reason"])
                self.assertFalse(shifted["result_evidence"]["mandatory_anchors"]["complete"])

    def test_u64_check_requires_scoped_write_set_typed_copy_and_stock_target(self):
        for root in (*U64_N18_N19_ROWS, *PROVIDER_ROWS):
            gate = root.get("check_evidence")
            if not gate:
                continue
            stdout, doc = self._projection_fixture(root)
            for original, foreign in ((b"memcpy.assigns.1", b"memcpy.assigns.91"),
                                      (b"memcpy.assigns.2", b"memcpy.assigns.92"),
                                      (b"<builtin-library-memcpy>:46", b"<builtin-library-memcpy>:47"),
                                      (b"ptr::copy_nonoverlapping::<u64>", b"ptr::copy_nonoverlapping::<u8>"),
                                      (f"{gate['file']}:{gate['lines'][0]}:1".encode(),
                                       f"{gate['file']}:{gate['lines'][0] + 1}:1".encode())):
                with self.subTest(slot=root["id"], lost=original):
                    self.assertIn(original, stdout)
                    self.write(stdout.replace(original, foreign), doc)
                    result = results.project(self.directory, [root], self.child, mode="singleton")
                    self.assertEqual(result["expected_result"]["status"], "MISMATCHED")
                    self.assertFalse(result["result_evidence"]["mandatory_anchors"]["complete"])
            doc["harnesses"][0]["attributes"]["kind"]["ProofForContract"]["target_fn"] = "wrong_target"
            self.write(stdout, doc)
            bad = results.project(self.directory, [root], self.child, mode="singleton")
            self.assertNotEqual(bad["expected_result"]["status"], "MATCHED")
            self.assertFalse(bad["result_evidence"]["mandatory_anchors"]["complete"])

    def test_merge_check_target_is_bound_to_contract(self):
        root = next(row for row in MERGE_ROWS if row["id"] == "N26-PAIR-FIXED")
        stdout, doc = self._projection_fixture(root)
        doc["harnesses"][0]["attributes"]["kind"]["ProofForContract"]["target_fn"] = "wrong_target"
        self.write(stdout, doc)
        rejected = results.project(self.directory, [root], self.child, mode="singleton")
        self.assertNotEqual(rejected["expected_result"]["status"], "MATCHED")
        self.assertFalse(rejected["result_evidence"]["mandatory_anchors"]["complete"])

    def test_observed_outcome_survives_unconfirmed_profile_and_anchors_survive_cap(self):
        control = n17_control_row()
        stdout, doc = self._projection_fixture(control)
        doc["enabled_unstable_features"] = []
        self.write(stdout, doc)
        projected = results.project(self.directory, [control], self.child | {"exit_code": 1}, mode="singleton")
        self.assertEqual(projected["outcome"], "INCOMPLETE")
        self.assertEqual(projected["observed_outcome"], "FAILED")

    def test_singleton_projects_native_stock_cover_and_timings(self):
        row_a = row("NET-U8-N08", SELECTOR_A)
        self.write(regular(SELECTOR_A) + b"Starting Bounded Model Checking\nRuntime Symex: 0.4s\n"
                   b"Runtime Convert SSA: 0.2s\nRuntime Solver: 0.1s\nVerification Time: 1.0s\n",
                   export_document([harness(SELECTOR_A)]), b"Solving with CaDiCaL 3.0.0\n")
        result = results.project(self.directory, [row_a], self.child, mode="singleton")
        self.assertEqual(result["outcome"], "VERIFIED", result)
        self.assertTrue(result["complete"])
        self.assertEqual(result["native_terminal"], "VERIFICATION:- SUCCESSFUL")
        self.assertEqual([p["class"] for p in result["native_checks"]], ["assertion", "cover"])
        self.assertEqual(result["covers"][0]["label"], "cover-label")
        self.assertEqual(result["covers"][0]["satisfied_count"], 1)
        self.assertEqual(result["timings"]["verification_seconds"], 1.5)
        self.assertEqual(result["timings"]["symex_seconds"], .4)
        self.assertEqual(result["solver_version"], "CaDiCaL 3.0.0")
        self.assertLessEqual(result["projection_bytes"], results.MAX_PROJECTION_BYTES)

    def test_failure_uses_native_terminal_and_stock_failure(self):
        row_a = row("NET-U8-N08", SELECTOR_A)
        native = regular(SELECTOR_A, "FAILURE").replace(
            b'Description: "assert ok"\n', b'Description: "assert ok"\n\t - Location: src/lib.rs:1:2')
        native = native.replace(b"1:2\nCheck", b"1:2\n\nCheck")
        self.write(native, export_document([harness(SELECTOR_A, verdict="FAILURE")]), b"error: synthetic\n")
        result = results.project(self.directory, [row_a], self.child | {"exit_code": 1}, mode="singleton")
        self.assertEqual(result["outcome"], "FAILED")
        self.assertIn("synthetic", result["diagnostic_excerpt"][0])
        evidence = result["result_evidence"]
        failure = evidence["regular"]["witnesses"]["records"][0]
        self.assertEqual((failure["id"], failure["location"], failure["status"]),
                         ("x.assertion.1", "src/lib.rs:1:2", "FAILURE"))
        exported = evidence["export"]["failures"]["records"][0]
        self.assertEqual((exported["id"], exported["file"], exported["line"], exported["status"]),
                         ("p1", "src/lib.rs", "1", "FAILURE"))

    def test_partial_timeout_is_censored_and_retains_stock_terminal(self):
        row_a = row("NET-U8-N08", SELECTOR_A)
        partial = export_document([harness(SELECTOR_A)], state="PARTIAL")
        partial["harnesses"][0]["outcome"] = {"kind": "TIMEOUT"}
        self.write(b"Checking harness " + SELECTOR_A.encode() + b"...\n", partial)
        result = results.project(self.directory, [row_a], self.child | {
            "stop_reason": "TIMEOUT", "exit_code": -9, "signal": 9}, mode="singleton")
        self.assertEqual(result["outcome"], "TIMEOUT")
        self.assertTrue(result["censored"])
        self.assertFalse(result["complete"])
        self.assertEqual(result["stock"]["run_state"], "PARTIAL")

    def test_regular_timeout_retains_native_and_sampled_phase_witnesses(self):
        parsed = row("NET-U8-N08", SELECTOR_A)
        self.write(f"Checking harness {SELECTOR_A}...\nStarting Bounded Model Checking\n".encode(),
                   export_document([harness(SELECTOR_A)], state="PARTIAL"))
        child = self.child | {"stop_reason": "TIMEOUT", "exit_code": -9, "signal": 9,
                              "last_observed_phase": "cbmc", "last_phase_monotonic": 120.5}
        result = results.project(self.directory, [parsed], child, mode="singleton")
        self.assertEqual(result["outcome"], "TIMEOUT")
        self.assertEqual(result["last_phase_source"], "sampled_process_image")
        self.assertEqual(result["last_phase"], "cbmc")
        self.assertEqual(result["last_phase_monotonic"], 120.5)
        self.assertEqual(result["phase_observations"]["native_stdout"], {"phase": "symex", "timestamp": None})

    def test_cutoff_without_unambiguous_cbmc_command_keeps_unwind_unknown(self):
        target = row("NET-U8-N08", SELECTOR_A)
        selected = f"Checking harness {SELECTOR_A}...\n".encode()
        other = f"Checking harness {SELECTOR_B}...\n".encode()
        command = b"[Kani] Running: `cbmc --unwind 19 model.out --json-ui`\n"
        child = self.child | {"stop_reason": "RSS_LIMIT", "exit_code": -15}
        for stdout in (selected, command + selected, other + command, selected + command.rstrip(b"\n"),
                       selected + command + command, selected + command + other,
                       selected + command.replace(b"--unwind 19", b"--unwind 19 --unwind 20"),
                       selected + command.replace(b"--unwind 19", b'"model --unwind 19.out"')):
            with self.subTest(stdout=stdout):
                self.write(stdout, None)
                result = results.project(self.directory, [target], child, mode="singleton")
                self.assertEqual(result["resolved"], [])

    def test_cutoff_prefers_stock_unwind_and_binds_missing_unwind_in_sequential_batch(self):
        rows = [row("NET-U8-N08", SELECTOR_A), row("NET-U8-N09", SELECTOR_B)]
        stdout = (f"Checking harness {SELECTOR_A}...\n[Kani] Running: `cbmc --unwind 19 model-a.out`\n"
                  f"Checking harness {SELECTOR_B}...\n[Kani] Running: `cbmc --unwind 23 model-b.out`\n").encode()
        child = self.child | {"stop_reason": "TIMEOUT", "exit_code": -15}
        self.write(stdout, export_document([harness(SELECTOR_A)], state="PARTIAL",
                                           selectors=[SELECTOR_A, SELECTOR_B]))
        result = results.project(self.directory, rows, child, mode="batch-jobs1")
        self.assertEqual([(item["selector"], item["resolved_unwind"]) for item in result["resolved"]],
                         [(SELECTOR_A, 8), (SELECTOR_B, 23)])
        self.assertEqual(result["resolved"][1]["resolved_unwind_source"]["line"], 4)
        self.assertEqual(result["outcome"], "TIMEOUT")
        self.assertFalse(result["complete"])
        parallel = results.project(self.directory, rows, child, mode="batch-auto")
        self.assertEqual([item["selector"] for item in parallel["resolved"]], [SELECTOR_A])

    def test_terse_jobs1_batch_timeout_keeps_cbmc_timestamp(self):
        rows = [row("NET-U8-N08", SELECTOR_A), row("NET-U8-N09", SELECTOR_B)]
        self.write(f"Checking harness {SELECTOR_A}...\n".encode(),
                   export_document([harness(SELECTOR_A)], state="PARTIAL", selectors=[SELECTOR_A, SELECTOR_B]))
        child = self.child | {"stop_reason": "TIMEOUT", "exit_code": -9, "signal": 9,
                              "last_observed_phase": "cbmc", "last_phase_monotonic": 120.5}
        result = results.project(self.directory, rows, child, mode="batch-jobs1")
        self.assertEqual(result["outcome"], "TIMEOUT")
        self.assertEqual(result["last_phase"], "cbmc")
        self.assertEqual(result["last_phase_monotonic"], 120.5)
        self.assertEqual(result["phase_observations"]["native_stdout"]["phase"], "harness-selected")

    def test_batch_validates_ordered_roster_and_emits_stock_counts_ids_only(self):
        rows = [row("NET-U8-N08", SELECTOR_A), row("NET-U8-N09", SELECTOR_B)]
        doc = export_document([harness(SELECTOR_B), harness(SELECTOR_A)],
                              selectors=[SELECTOR_A, SELECTOR_B])
        self.write(b"multi-root output omitted from native property projection\n", doc)
        result = results.project(self.directory, rows, self.child, mode="batch")
        self.assertEqual(result["outcome"], "VERIFIED")
        self.assertTrue(result["complete"])
        self.assertEqual(result["native_checks"], [])
        self.assertEqual(result["stock"]["state"], "COMPLETE", result["stock"])
        self.assertEqual(result["stock"]["terminals"][0]["verdict"], "SUCCESS")
        self.assertIn("checks.success", result["stock"]["property_ids"]["NET-U8-N08"])
        self.assertEqual(result["timings"]["verification_seconds"], 3.0)
        self.assertEqual(result["cover_summary"]["stock_reached"], 2)

    def test_exact_selector_and_effective_unwind_mismatch_fail_closed(self):
        row_a = row("NET-U8-N08", SELECTOR_A, unwind=9)
        doc = export_document([harness(SELECTOR_A, unwind=8)])
        self.write(regular(SELECTOR_A), doc)
        result = results.project(self.directory, [row_a], self.child, mode="singleton")
        self.assertEqual(result["outcome"], "INCOMPLETE")
        self.assertIn("resolved unwind mismatch", result["stock"]["reason"])

    def test_stock_check_symbol_and_pin_are_bound(self):
        row_a = row("S13-N13", SELECTOR_A) | {"check": "sort13_optimal"}
        binding = harness(SELECTOR_A)
        binding["attributes"]["kind"] = {"ProofForContract": {"target_fn": "a::sort13_optimal"}}
        binding["contract"] = {"contracted_function_name": "native_check_symbol", "recursion_tracker": None}
        stock = export_document([binding])
        self.write(regular(SELECTOR_A), stock)
        self.assertEqual(results.project(self.directory, [row_a], self.child, mode="singleton")["outcome"], "VERIFIED")
        stock["kani_commit"] = "f" * 40
        binding["contract"] = None
        self.write(regular(SELECTOR_A), stock)
        projected = results.project(self.directory, [row_a], self.child, mode="singleton")
        self.assertEqual(projected["outcome"], "INCOMPLETE")
        self.assertIn("tool identity mismatch", projected["stock"]["reason"])
        self.assertIn("Check symbol missing", projected["stock"]["reason"])

    def test_admission_without_process_retains_distinct_status(self):
        projected = results.project(self.directory, [row("NET-U8-N08", SELECTOR_A)], self.child | {
            "status": "NOT_STARTED", "stop_reason": "ADMISSION_MEMORY_PRESSURE", "reaped": False,
        }, mode="singleton")
        self.assertEqual(projected["outcome"], "NOT_STARTED")
        self.assertFalse(projected["complete"])

    def test_stock_export_missing_or_wrong_type_has_incomplete_receipt(self):
        rows = [row("NET-U8-N08", SELECTOR_A)]
        for stock in (None, [], 33, "unparsed"):
            self.write(regular(SELECTOR_A), stock)
            projected = results.project(self.directory, rows, self.child, mode="singleton")
            self.assertEqual(projected["outcome"], "INCOMPLETE")
            self.assertEqual(projected["native_terminal"], "VERIFICATION:- SUCCESSFUL")

    def test_projection_has_hard_cap_and_marks_truncation(self):
        row_a = row("NET-U8-N08", SELECTOR_A)
        doc = export_document([harness(SELECTOR_A)])
        huge = "z" * 9000
        lines = [f"Checking harness {SELECTOR_A}...", "RESULTS:"]
        for i in range(1, 800):
            lines += [f"Check {i}: p.assertion.{i}", "\t - Status: SUCCESS",
                      f'\t - Description: "{huge}"', ""]
        lines += ["", "SUMMARY:", " ** 0 of 1 failed", "VERIFICATION:- SUCCESSFUL"]
        self.write(("\n".join(lines) + "\n").encode(), doc)
        result = results.project(self.directory, [row_a], self.child, mode="singleton")
        self.assertLessEqual(result["projection_bytes"], results.MAX_PROJECTION_BYTES)
        self.assertFalse(result["complete"])
        self.assertTrue(result.get("projection_truncated"))

    def test_cnf_markers_on_terminal_and_cutoff_keep_stream_coordinates(self):
        target = row("S13-N13-OB12", SELECTOR_A)
        prefix = (b"Starting Bounded Model Checking\nGenerated 93 VCC(s), 24 remaining after simplification\n"
                  b"converting SSA\n[2026-11-24T10:05:06Z] 120 variables, 300 clauses\n"
                  b"Covering goals\n11 variables, 34 clauses\n")
        for stop in ("EXITED", "RSS_LIMIT", "TIMEOUT", "LIVE_MEMORY_PRESSURE"):
            with self.subTest(stop=stop):
                ended = stop == "EXITED"
                suffix = regular(SELECTOR_A) if ended else b"100 variables, 21 claus"
                stock = export_document([harness(SELECTOR_A)], state="COMPLETE" if ended else "PARTIAL")
                self.write(prefix + suffix, stock, b"Solving with CaDiCaL 3.0.0\n")
                child = self.child | {"stop_reason": stop, "stdout_complete": ended, "stdout_truncated": not ended}
                projected = results.project(self.directory, [target], child, mode="singleton")
                self.assertEqual(projected["outcome"], "VERIFIED" if ended else stop)
                metrics = projected["native_metrics"]
                stdout, stderr = (metrics["streams"][name] for name in ("stdout", "stderr"))
                first = stdout["first_cnf"]
                self.assertIsNone(metrics["cross_stream_order"])
                self.assertEqual((first["variables"], first["clauses"], first["phase"]), (120, 300, "SAT"))
                self.assertEqual((first["line"], first["byte_start"], first["native_timestamp"]),
                                 (4, prefix.index(b"[2026"), "2026-11-24T10:05:06Z"))
                self.assertEqual(first, metrics["initial_solve_cnf"])
                self.assertEqual(len(stdout["subsequent_cnf"]), 1)
                self.assertEqual(stdout["subsequent_cnf"][0]["solve_context"], "COVER_OR_REACHABILITY")
                self.assertEqual(stdout["first_marker_by_kind"]["vcc"]["generated"], 93)
                self.assertEqual(stdout["last_terminal"] is not None, ended)
                self.assertEqual(stdout["incomplete_tail"] is None, ended)
                self.assertEqual(stdout["capture_truncated"], not ended)
                self.assertIsNone(stderr["first_cnf"])
                self.assertEqual(stderr["cnf_status"], "ABSENT_IN_COMPLETE_CAPTURE")

    def test_cnf_with_only_cover_or_incomplete_line_cannot_supply_initial_solve(self):
        target = row("MERGE-N32-MASK-OB12", SELECTOR_A)
        for stdout in (b"Starting Bounded Model Checking\nCovering goals\n14 variables, 22 clauses\n",
                       b"Starting Bounded Model Checking\nconverting SSA\n14 variables, 22 clauses"):
            self.write(stdout, None, b"terminal text\n")
            projected = results.project(self.directory, [target], self.child, mode="singleton")
            self.assertIsNone(projected["native_metrics"]["initial_solve_cnf"])
        stream = projected["native_metrics"]["streams"]["stdout"]
        self.assertIsNone(stream["first_cnf"])
        self.assertEqual(stream["cnf_status"], "UNOBSERVED_IN_PREFIX")
        self.assertTrue(stream["incomplete_tail"])

    def test_object_bits_11_validation_and_diagnostic_exit(self):
        target = row("S13-N13-OB11", SELECTOR_A) | {"object_bits": 11}
        stock = export_document([harness(SELECTOR_A)])
        self.write(regular(SELECTOR_A), stock)
        self.assertIn("CBMC argument configuration mismatch",
                      results.project(self.directory, [target], self.child, mode="singleton")["stock"]["reason"])
        stock["configuration"]["cbmc_args"] = ["--object-bits", "11"]
        self.write(regular(SELECTOR_A), stock)
        self.assertEqual(results.project(self.directory, [target], self.child, mode="singleton")["outcome"], "VERIFIED")
        self.write(b"", None, b"error: too many addressed objects\n")
        child = self.child | {"exit_code": 1}
        diagnostic = results.project(self.directory, [target], child, mode="singleton")
        self.assertEqual((diagnostic["outcome"], diagnostic["reason"]),
                         ("OBJECT_BITS_EXHAUSTED", "CBMC_TOO_MANY_ADDRESSED_OBJECTS"))
        cutoff = results.project(self.directory, [target], child | {"stop_reason": "RSS_LIMIT"}, mode="singleton")
        self.assertEqual(cutoff["outcome"], "RSS_LIMIT")


if __name__ == "__main__":
    unittest.main()
