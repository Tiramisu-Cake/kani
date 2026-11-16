"""Synthetic tests for runner validation; none invokes Kani or a verifier."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import threading
import sys
import tempfile
import unittest
from unittest import mock

import runner


def row(**updates):
    value = {"id": "synthetic", "selector": "slice::sort::root", "mode": "PFC",
             "variant": "production", "target": "slice::sort::body", "unwind": 4,
             "expected": "SUCCESS", "required_cover_count": 2,
             "required_cover_descriptions": ["C_merge_callback", "C_merge_return"], "timeout_seconds": 30}
    value.update(updates)
    return value


def export(*, selector="slice::sort::root", mode="pfc", schema="0.1.0", state="COMPLETE",
           verdict="SUCCESS", failures=None, named=None):
    target = "slice::sort::body"
    wrapper = "_RNvNtCs1kani4sort6modify"
    kind = {"ProofForContract": {"target_fn": target}} if mode == "pfc" else "Proof"
    failures = failures or []
    named = [{"trace_available": False, "status": "FAILURE", **prop} for prop in (named or [])]
    return {"schema_version": schema, "run_state": state, "outcome": {"kind": "COMPLETED"},
            "kani_commit": runner.TOOL_SHA,
            "kani_commit_dirty": False, "target": "x86_64-unknown-linux-gnu", "harness_timeout_s": 600.0,
            "tools": {"kani": "kani synthetic", "rustc": "rustc synthetic", "cbmc": "CBMC synthetic"},
            "configuration": {"checks": {"assert_contracts": False, "memory_safety": True,
                                            "overflow": True, "unwinding": True, "undefined_function": True,
                                            "assertion_reach_checks": True, "ignore_global_asm": False,
                                            "extra_pointer_checks": False, "prove_safety_only": False},
                              "coverage_enabled": False, "cbmc_args": ["--object-bits", "12"]},
            "enabled_unstable_features": sorted(set(runner.UNSTABLE) | {"export-json", "unstable-options"}),
            "harness_selection": {"requested_filters": [selector], "exact": True,
                                  "unmatched_filters": [], "matched_count": 1},
            "harnesses": [{"name": selector, "crate_name": "core", "is_automatically_generated": False,
                           "attributes": {"kind": kind},
                           "contract": ({"contracted_function_name": wrapper, "recursion_tracker": None}
                                        if mode == "pfc" else None),
                           "resolved_unwind": 4,
                           "outcome": {"kind": "COMPLETED", "verdict": verdict},
                           "n_properties": 6,
                           "n_failed": len(failures), "failed_properties": named,
                           "unsupported_constructs": [],
                           "checks": {"total": 4, "success": 4-len(failures), "failure": failures,
                                      "unreachable": [], "undetermined": [], "error": [], "unknown": [], "other": []},
                           "covers": {"total": 2, "satisfied": ["cover-A", "cover-B"],
                                      "unsatisfiable": [], "unreachable": [], "undetermined": [],
                                      "error": [], "unknown": [], "other": []}}]}


class RequestTests(unittest.TestCase):
    def request(self):
        return {"status": "READY", "std_sha": runner.STD_SHA, "std_tree": runner.STD_TREE,
                "tool_sha": runner.TOOL_SHA, "tool_tree": runner.TOOL_TREE,
                "rows": [row()], "changed_file_sha256": {}, "variants": {},
                "flags": {"cli": ["--no-assert-contracts", "--jobs=1", "--cbmc-args", "--object-bits", "12"],
                    "unstable_features": [*runner.UNSTABLE, "export-json"], "cfg": ["kani_smallsort_controls"],
                    "sorting_cfg": False, "assert_contracts": False, "uninit_checks": False,
                    "valid_value_checks": False, "jobs": 1, "attempt": 1, "max_root_seconds": runner.MAX_ROW_SECONDS},
            "budgets": {"phase_seconds": runner.PHASE_SECONDS, "setup_seconds": 1800, "reserve_seconds": 300,
                            "job_seconds": runner.JOB_SECONDS, "run_step_seconds": runner.RUN_STEP_SECONDS,
                            "group_seconds": 6600,
                            "rss_kib": runner.RSS_CAP_KIB,
                            "stdout_bytes": runner.STDOUT_CAP_BYTES, "stderr_bytes": runner.STDERR_CAP_BYTES,
                            "export_bytes": runner.EXPORT_CAP_BYTES, "artifact_bytes": runner.ARTIFACT_CAP_BYTES,
                            "row_seconds": runner.MAX_ROW_SECONDS}}

    def test_request_binding_and_guard(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "CI-REQUEST.json"
            request = self.request(); request["std_sha"] = "wrong"
            path.write_text(json.dumps(request))
            with self.assertRaisesRegex(runner.RunnerError, "std_sha"):
                runner.load_request(path)
            request = self.request(); request["rows"][0]["variant"] = "surprise"
            path.write_text(json.dumps(request))
            with self.assertRaisesRegex(runner.RunnerError, "variant"):
                runner.load_request(path)
        argv = runner.build_argv(Path("/std"), Path("/tool"), "x::root", 3, Path("/tmp/e.json"))
        self.assertIn("--no-assert-contracts", argv)
        self.assertLess(argv.index("-Z"), argv.index("--cbmc-args"))
        self.assertEqual(argv[-3:], ["--cbmc-args", "--object-bits", "12"])
        self.assertEqual(argv[argv.index("--export-json") + 1], "/tmp/e.json")
        self.assertEqual(argv[-4], "/std/library")

    def test_source_binding_and_dirty_or_file_drift(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); std = root / "std"; tool = root / "tool"
            std.mkdir(); tool.mkdir(); (std / "src").mkdir()
            source = std / "src/a.rs"; source.write_text("pinned")
            request = self.request(); request["changed_file_sha256"] = {"src/a.rs": runner.sha256(source)}
            expected = {str(std.resolve()): (runner.STD_SHA, runner.STD_TREE),
                        str(tool.resolve()): (runner.TOOL_SHA, runner.TOOL_TREE)}
            def fake_git(repo, *args):
                if args == ("rev-parse", "HEAD"): return expected[str(repo)][0]
                if args == ("rev-parse", "HEAD^{tree}"): return expected[str(repo)][1]
                if args == ("cat-file", "-t", runner.STD_SHA) or args == ("cat-file", "-t", runner.TOOL_SHA): return "commit"
                if args == ("status", "--porcelain=v1"): return ""
                raise AssertionError((repo, args))
            with mock.patch.object(runner, "git", side_effect=fake_git):
                runner.verify_source(std, tool, request)
                source.write_text("drift")
                with self.assertRaisesRegex(runner.RunnerError, "changed-file SHA drift"):
                    runner.verify_source(std, tool, request)

    def test_rejects_unpinned_rustflags(self):
        with mock.patch.dict(os.environ, {"RUSTFLAGS": "-C opt-level=3"}):
            with self.assertRaisesRegex(runner.RunnerError, "inherited RUSTFLAGS"):
                runner.ci_env()


class C02BindingTests(unittest.TestCase):
    def test_token_paths_preserve_identifier_boundaries(self):
        self.assertEqual(runner._target_tokens(" super :: super::bidirectional_merge "),
                         ("super", "super", "bidirectional_merge"))
        for value in [None, 17, {}, "", "bidi rectional_merge", "x:::y", "x::", "x-y", "x::<u8>"]:
            with self.subTest(value=value):
                self.assertIsNone(runner._target_tokens(value))

    def test_pinned_source_import_attribute_unwind_and_location(self):
        rel = "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs"
        source = ("use super::super::{bidirectional_merge, insert_tail, insertion_sort_shift_left};\n"
                  "#[kani::proof_for_contract(bidirectional_merge)]\n#[kani::unwind(17)]\n"
                  "fn c_merge_source_read_only() {}\n")
        selected = row(id="c_merge_source_read_only", target="slice::sort::shared::smallsort::bidirectional_merge",
                       source_target_syntax="bidirectional_merge", source_harness_file=rel,
                       source_harness_line=4, unwind=17)
        with tempfile.TemporaryDirectory() as d:
            std = Path(d); p = std / rel; p.parent.mkdir(parents=True); p.write_text(source)
            runner._verify_c02_source(std, {"rows": [selected]})
            for old, new in [("use super::super", "use other::super"),
                             ("proof_for_contract(bidirectional_merge)", "proof_for_contract(insert_tail)"),
                             ("unwind(17)", "unwind(8)"), ("fn c_merge_source_read_only", "fn other")]:
                p.write_text(source.replace(old, new))
                with self.subTest(old=old), self.assertRaises(runner.RunnerError):
                    runner._verify_c02_source(std, {"rows": [selected]})
            p.write_text(source)
            with self.assertRaises(runner.RunnerError):
                runner._verify_c02_source(std, {"rows": [{**selected, "source_harness_line": 99}]})

    def test_export_bare_path_uses_exact_source_spelling_and_location(self):
        selected = row(source_target_syntax="body", source_harness_file="library/test.rs", source_harness_line=7)
        payload = export(); h = payload["harnesses"][0]
        h.update(file="/checkout/library/test.rs", line=7)
        h["attributes"]["kind"]["ProofForContract"]["target_fn"] = " body "
        self.assertEqual(runner._parse_export_document(payload, selected)["outcome"], "EXPECTED")
        for target in [None, "other::body", "bo dy", "other", "body::<u8>"]:
            h["attributes"]["kind"]["ProofForContract"]["target_fn"] = target
            with self.subTest(target=target):
                self.assertEqual(runner._parse_export_document(payload, selected)["state"],
                                 "CONTRACT_TARGET_BINDING_MISMATCH")
        h["attributes"]["kind"]["ProofForContract"]["target_fn"] = "body"
        for field, value in [("file", "other/test.rs"), ("file", None), ("line", 8), ("line", True)]:
            good = h[field]; h[field] = value
            with self.subTest(field=field, value=value):
                self.assertEqual(runner._parse_export_document(payload, selected)["state"], "SOURCE_STAGE_TARGET_MISMATCH")
            h[field] = good
        self.assertEqual(runner._parse_export_document(payload, selected,
                         {selected["selector"]: "wrong::body"})["state"], "CONTRACT_TARGET_BINDING_MISMATCH")


class ExportTests(unittest.TestCase):
    def parse(self, value, selected_row=None, expected_source_targets=None):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "export.json"
            p.write_text(json.dumps(value))
            return runner.parse_export(p, selected_row or row(), expected_source_targets=expected_source_targets)

    def test_success_and_named_negative(self):
        binding = {row()["selector"]: "slice::sort::body"}
        accepted = self.parse(export(), expected_source_targets=binding)
        self.assertEqual(accepted["outcome"], "EXPECTED")
        self.assertFalse(accepted["is_automatically_generated"])
        self.assertEqual(accepted["expected_source_target"], "slice::sort::body")
        self.assertEqual(accepted["satisfied_cover_ids"], ["cover-A", "cover-B"])
        self.assertEqual(accepted["cover_description_to_id_binding"], "PENDING_INDEPENDENT_REVIEW_EXPORT_HAS_IDS_ONLY")
        self.assertEqual(accepted["reported_contracted_function_name"], "_RNvNtCs1kani4sort6modify")
        self.assertNotEqual(accepted["reported_contracted_function_name"], accepted["expected_source_target"])
        negative_row = row(expected="DETECTED", failure_match={"class": "assigns",
            "description_regex": r"^Check that .+ is assignable$",
            "locations": [{"file": "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs", "line": "23"},
                          {"file": "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs", "line": "25"}]})
        negative = export(verdict="FAILURE", failures=["property-7"], named=[
            {"id": "property-7", "description": "Check that write to source is assignable",
             "class": "assigns", "file": "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs", "line": "23"}])
        self.assertEqual(self.parse(negative, negative_row,
                                   {negative_row["selector"]: "slice::sort::body"})["outcome"], "EXPECTED")
        alias_row = row(expected="ALIAS_GAP")
        self.assertEqual(self.parse(export(), alias_row,
                                   {alias_row["selector"]: "slice::sort::body"})["outcome"], "ALIAS_GAP")
        mismatch = self.parse(export(), row(target="different::target"),
                              {row()["selector"]: "slice::sort::body"})
        self.assertEqual(mismatch["state"], "CONTRACT_TARGET_BINDING_MISMATCH")
        extra = export(verdict="FAILURE", failures=["property-7", "other"], named=[
            {"id": "property-7", "description": "Check that write to source is assignable",
             "class": "assigns", "file": "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs", "line": "23"},
            {"id": "other", "description": "wrong pointer assertion", "class": "assertion",
             "file": "verify/c_controls.rs", "line": "21"}])
        self.assertEqual(self.parse(extra, negative_row,
                                   {negative_row["selector"]: "slice::sort::body"})["outcome"], "UNKNOWN")
        second = {"id": "property-8", "description": "Check that restored source is assignable",
                  "class": "assigns", "file": "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs", "line": "25"}
        multi = export(verdict="FAILURE", failures=["property-7", "property-8"], named=[
            negative["harnesses"][0]["failed_properties"][0], second])
        self.assertEqual(self.parse(multi, negative_row,
                                   {negative_row["selector"]: "slice::sort::body"})["outcome"], "EXPECTED")
        wrong_location = export(verdict="FAILURE", failures=["property-7"], named=[
            {"id": "property-7", "description": "Check that write to source is assignable",
             "class": "assigns", "file": "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs", "line": "21"}])
        self.assertEqual(self.parse(wrong_location, negative_row,
                                   {negative_row["selector"]: "slice::sort::body"})["outcome"], "UNKNOWN")

    def test_coverage_inventory_reconciles_exactly(self):
        binding = {row()["selector"]: "slice::sort::body"}
        malformed = []
        value = export(); value["harnesses"][0]["covers"]["total"] = 1
        value["harnesses"][0]["n_properties"] = value["harnesses"][0]["checks"]["total"] + 1
        malformed.append((value, "COVERAGE_INCOMPLETE"))
        value = export(); value["harnesses"][0]["covers"]["satisfied"] = ["cover-A", "cover-A"]
        malformed.append((value, "COVERAGE_INCOMPLETE"))
        value = export(); value["harnesses"][0]["covers"]["satisfied"] = ["cover-A", 7]
        malformed.append((value, "COVERAGE_INCOMPLETE"))
        value = export(); value["harnesses"][0]["covers"]["total"] = True
        value["harnesses"][0]["n_properties"] = value["harnesses"][0]["checks"]["total"] + 1
        malformed.append((value, "INCOMPLETE_CHECK_INVENTORY"))
        for payload, state in malformed:
            with self.subTest(covers=payload["harnesses"][0]["covers"]):
                parsed = self.parse(payload, expected_source_targets=binding)
                self.assertEqual(parsed["state"], state)
                self.assertEqual(parsed["outcome"], "UNKNOWN")

    def test_wrong_root_mode_guard_and_export_drift(self):
        binding = {row()["selector"]: "slice::sort::body"}
        self.assertEqual(self.parse(export(selector="other::root"), expected_source_targets=binding)["state"], "WRONG_ROOT_OR_SELECTION")
        self.assertEqual(self.parse(export(mode="ordinary"), expected_source_targets=binding)["state"], "WRONG_MODE")
        self.assertEqual(self.parse(export(schema="0.2.0"), expected_source_targets=binding)["state"], "INCOMPLETE_OR_SCHEMA_DRIFT")
        self.assertEqual(self.parse(export(state="PARTIAL"), expected_source_targets=binding)["state"], "INCOMPLETE_OR_SCHEMA_DRIFT")
        bad = export(); bad["harnesses"][0]["checks"]["unreachable"] = ["x"]
        self.assertEqual(self.parse(bad, expected_source_targets=binding)["state"], "INCOMPLETE_CHECK_INVENTORY")
        bad = export(); bad["harnesses"][0]["resolved_unwind"] = 99
        self.assertEqual(self.parse(bad, expected_source_targets=binding)["state"], "WRONG_UNWIND")
        bad = export(); bad["harnesses"][0]["attributes"]["kind"]["ProofForContract"]["target_fn"] = "other"
        self.assertEqual(self.parse(bad, expected_source_targets=binding)["state"], "CONTRACT_TARGET_BINDING_MISMATCH")
        bad = export(); bad["harnesses"][0]["contract"]["contracted_function_name"] = ""
        self.assertEqual(self.parse(bad, expected_source_targets=binding)["state"], "CONTRACT_TARGET_BINDING_MISMATCH")
        bad = export(); del bad["harnesses"][0]["contract"]["contracted_function_name"]
        self.assertEqual(self.parse(bad, expected_source_targets=binding)["state"], "CONTRACT_TARGET_BINDING_MISMATCH")
        bad = export(); bad["configuration"]["checks"]["assert_contracts"] = True
        self.assertEqual(self.parse(bad, expected_source_targets=binding)["state"], "WRONG_CONFIGURATION")

    def test_export_counts_and_selection_are_strict_integers(self):
        binding = {row()["selector"]: "slice::sort::body"}
        count_fields = [
            ("harness", "n_properties"), ("harness", "n_failed"),
            ("checks", "total"), ("checks", "success"), ("covers", "total")]
        for group, field in count_fields:
            for value in (True, -1):
                payload = export()
                target = payload["harnesses"][0] if group == "harness" else payload["harnesses"][0][group]
                target[field] = value
                with self.subTest(group=group, field=field, value=value):
                    parsed = self.parse(payload, expected_source_targets=binding)
                    self.assertEqual(parsed["outcome"], "UNKNOWN")
                    self.assertEqual(parsed["state"], "INCOMPLETE_CHECK_INVENTORY")
        payload = export(); payload["harness_selection"]["matched_count"] = True
        self.assertEqual(self.parse(payload, expected_source_targets=binding)["state"], "WRONG_ROOT_OR_SELECTION")
        for value in (True, -1):
            payload = export(); payload["harnesses"][0]["resolved_unwind"] = value
            with self.subTest(resolved_unwind=value):
                self.assertEqual(self.parse(payload, expected_source_targets=binding)["state"], "WRONG_UNWIND")

    def test_invalid_export_shapes_and_size(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "e.json"
            self.assertEqual(runner.parse_export(p, row())["state"], "MISSING")
            p.write_bytes(b"")
            self.assertEqual(runner.parse_export(p, row())["state"], "EMPTY")
            p.write_bytes(b"{")
            self.assertEqual(runner.parse_export(p, row())["state"], "INVALID_OR_PARTIAL")
            p.write_text("null")
            self.assertEqual(runner.parse_export(p, row())["state"], "NULL")
            p.write_text("[]")
            self.assertEqual(runner.parse_export(p, row())["state"], "WRONG_TOP_LEVEL_TYPE")
            p.write_bytes(b" " * 100)
            self.assertEqual(runner.parse_export(p, row(), max_bytes=50)["state"], "OVERSIZE")

    def test_group_export_binds_each_mode_and_preserves_completed_partial_rows(self):
        first = row(id="pfc", selector="slice::sort::pfc")
        second = row(id="proof", selector="slice::sort::proof", mode="Original",
                     target="slice::sort::proof", unwind=4)
        payload = export(selector=first["selector"])
        proof_harness = export(selector=second["selector"], mode="ordinary")["harnesses"][0]
        payload["harnesses"].append(proof_harness)
        payload["harness_selection"]["requested_filters"] = [first["selector"], second["selector"]]
        payload["harness_selection"]["matched_count"] = 2
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "group.json"
            path.write_text(json.dumps(payload))
            parsed = runner.parse_group_export(path, [first, second],
                expected_source_targets={first["selector"]: "slice::sort::body"})
            self.assertEqual(parsed[first["selector"]]["outcome"], "EXPECTED")
            self.assertEqual(parsed[second["selector"]]["outcome"], "EXPECTED")
            payload["run_state"] = "PARTIAL"
            payload["harnesses"] = [payload["harnesses"][0]]
            path.write_text(json.dumps(payload))
            parsed = runner.parse_group_export(path, [first, second],
                expected_source_targets={first["selector"]: "slice::sort::body"})
            self.assertEqual(parsed[first["selector"]]["outcome"], "EXPECTED")
            self.assertEqual(parsed[second["selector"]]["state"], "MISSING_HARNESS_IN_PARTIAL_EXPORT")

    def test_group_export_rejects_bad_selection_and_duplicate_harness_names(self):
        first = row(id="one", selector="slice::sort::one")
        second = row(id="two", selector="slice::sort::two")
        payload = export(selector=first["selector"])
        payload["harness_selection"]["requested_filters"] = [first["selector"], second["selector"]]
        payload["harness_selection"]["matched_count"] = 2
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "group.json"
            path.write_text(json.dumps(payload))
            parsed = runner.parse_group_export(path, [first, second],
                expected_source_targets={first["selector"]: "slice::sort::body"})
            self.assertEqual(parsed[first["selector"]]["state"], "WRONG_ROOT_OR_SELECTION")
            payload["harnesses"].append(payload["harnesses"][0])
            path.write_text(json.dumps(payload))
            parsed = runner.parse_group_export(path, [first, second],
                expected_source_targets={first["selector"]: "slice::sort::body"})
            self.assertEqual(parsed[first["selector"]]["state"], "WRONG_ROOT_OR_SELECTION")

    def test_group_terminal_export_binds_target_and_timeout(self):
        selected = row(selector="slice::sort::group")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "group.json"
            for field, value, state in (("target", "aarch64-unknown-linux-gnu", "WRONG_TARGET_BINDING"),
                                        ("target", None, "WRONG_TARGET_BINDING"),
                                        ("harness_timeout_s", 1, "WRONG_HARNESS_TIMEOUT"),
                                        ("harness_timeout_s", None, "WRONG_HARNESS_TIMEOUT"),
                                        ("harness_timeout_s", True, "WRONG_HARNESS_TIMEOUT")):
                payload = export(selector=selected["selector"]); payload[field] = value
                path.write_text(json.dumps(payload))
                self.assertEqual(runner.parse_group_export(path, [selected])[selected["selector"]]["state"], state)

    def test_harness_timeout_is_unknown_with_details_preserved(self):
        payload = export()
        payload["harnesses"][0]["outcome"] = {"kind": "TIMEOUT"}
        parsed = self.parse(payload, expected_source_targets={row()["selector"]: "slice::sort::body"})
        self.assertEqual(parsed["state"], "HARNESS_TIMEOUT")
        self.assertEqual(parsed["outcome"], "UNKNOWN")
        self.assertEqual(parsed["harness_outcome"], {"kind": "TIMEOUT"})
        self.assertIn("checks", parsed)
        self.assertIn("covers", parsed)

    def test_frozen_manual_core_global_and_contract_bindings(self):
        binding = {row()["selector"]: "slice::sort::body"}
        for mode, selected_row in (("pfc", row()),
                                   ("ordinary", row(mode="Original", target="slice::sort::root"))):
            payload = export(mode=mode, selector=selected_row["selector"])
            payload["harnesses"][0]["is_automatically_generated"] = True
            with self.subTest(mode=mode):
                self.assertEqual(self.parse(payload, selected_row,
                    binding if mode == "pfc" else None)["state"], "WRONG_HARNESS_GENERATION")
        payload = export()
        payload["harnesses"][0]["crate_name"] = "alloc"
        self.assertEqual(self.parse(payload, expected_source_targets=binding)["state"], "WRONG_CRATE_BINDING")
        for field, value, state in (("target", "aarch64-unknown-linux-gnu", "WRONG_TARGET_BINDING"),
                                    ("target", None, "WRONG_TARGET_BINDING"),
                                    ("harness_timeout_s", 1, "WRONG_HARNESS_TIMEOUT"),
                                    ("harness_timeout_s", None, "WRONG_HARNESS_TIMEOUT"),
                                    ("harness_timeout_s", True, "WRONG_HARNESS_TIMEOUT")):
            payload = export(); payload[field] = value
            self.assertEqual(self.parse(payload, expected_source_targets=binding)["state"], state)
        payload = export(); del payload["configuration"]["checks"]["assertion_reach_checks"]
        self.assertEqual(self.parse(payload, expected_source_targets=binding)["state"], "WRONG_CONFIGURATION")
        payload = export(); payload["configuration"]["checks"]["extra_pointer_checks"] = True
        self.assertEqual(self.parse(payload, expected_source_targets=binding)["state"], "WRONG_CONFIGURATION")
        payload = export(); payload["configuration"]["coverage_enabled"] = True
        self.assertEqual(self.parse(payload, expected_source_targets=binding)["state"], "WRONG_CONFIGURATION")
        payload = export(); payload["enabled_unstable_features"].append("uninit-checks")
        self.assertEqual(self.parse(payload, expected_source_targets=binding)["state"], "WRONG_UNSTABLE_FEATURE_SET")

    def test_zero_check_vacuity_and_malformed_failure_records_are_unknown(self):
        binding = {row()["selector"]: "slice::sort::body"}
        payload = export()
        harness = payload["harnesses"][0]
        harness["checks"]["total"] = 0
        harness["checks"]["success"] = 0
        harness["n_properties"] = harness["covers"]["total"]
        self.assertEqual(self.parse(payload, expected_source_targets=binding)["state"],
                         "INCOMPLETE_CHECK_INVENTORY")
        payload = export(); payload["harnesses"][0]["failed_properties"] = [7]
        parsed = self.parse(payload, expected_source_targets=binding)
        self.assertNotEqual(parsed["outcome"], "EXPECTED")
        payload = export(); payload["harnesses"][0]["checks"]["failure"] = [7]
        self.assertEqual(self.parse(payload, expected_source_targets=binding)["state"], "WRONG_EXPORT_SHAPE")
        payload = export(); payload["harnesses"][0]["failed_properties"] = [
            {"id": "x", "description": "x", "class": "assertion", "file": None, "line": None,
             "trace_available": False, "status": "SUCCESS"}]
        payload["harnesses"][0]["checks"]["failure"] = ["x"]
        payload["harnesses"][0]["n_failed"] = 1
        payload["harnesses"][0]["checks"]["total"] = 5
        payload["harnesses"][0]["checks"]["success"] = 4
        payload["harnesses"][0]["n_properties"] = 7
        self.assertEqual(self.parse(payload, expected_source_targets=binding)["state"],
                         "INCONSISTENT_PROPERTY_COUNTS")

    def test_terminal_outcome_required_for_root_group_and_aggregate(self):
        selected = row()
        selector = selected["selector"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "export.json"
            for mode in ("missing", None, {}, [], "COMPLETED", {"kind": "NOT_RUN"},
                         {"kind": "COMPLETED", "extra": True}):
                payload = export()
                if mode == "missing":
                    payload.pop("outcome")
                else:
                    payload["outcome"] = mode
                path.write_text(json.dumps(payload))
                with self.subTest(outcome=mode):
                    self.assertEqual(runner.parse_export(path, selected)["outcome"], "UNKNOWN")
                    self.assertEqual(runner.parse_group_export(path, [selected])[selector]["outcome"], "UNKNOWN")
                    self.assertIsNone(runner._expected_group_exit(path, [selector]))
            path.write_text(json.dumps(export()))
            self.assertEqual(runner.parse_group_export(path, [selected])[selector]["outcome"], "EXPECTED")
            self.assertEqual(runner._expected_group_exit(path, [selector]), 0)


class ExecutionTests(unittest.TestCase):
    def test_synthetic_subprocess_success_and_signal(self):
        with tempfile.TemporaryDirectory() as d:
            ok = runner.execute([sys.executable, "-c", "print('synthetic ok')"], Path(d),
                                Path(d) / "ok", timeout=5)
            self.assertEqual(ok["original_exit_code"], 0)
            self.assertIn("synthetic ok", (Path(d) / "ok/stdout.log").read_text())
            killed = runner.execute([sys.executable, "-c", "import os,signal; os.kill(os.getpid(), signal.SIGTERM)"],
                                    Path(d), Path(d) / "signal", timeout=5)
            self.assertEqual(killed["signal"], 15)

    def test_synthetic_subprocess_timeout(self):
        with tempfile.TemporaryDirectory() as d:
            timed = runner.execute([sys.executable, "-c", "import time; time.sleep(5)"],
                                   Path(d), Path(d) / "timeout", timeout=1)
            self.assertTrue(timed["timed_out"])
            self.assertEqual(timed["termination_reason"], "timeout")

    def test_compile_boundary_persists_receipt_before_process_exit(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            marker = root / "export.json"
            selector = "slice::sort::root"
            payload = {"schema_version": "0.1.0", "kani_commit": runner.TOOL_SHA,
                "kani_commit_dirty": False, "run_state": "INCOMPLETE",
                "target": "x86_64-unknown-linux-gnu", "harness_timeout_s": 600.0,
                "harness_selection": {"requested_filters": [selector], "exact": True,
                    "unmatched_filters": [], "matched_count": 1}}
            command = "from pathlib import Path; import json,time,sys; " + \
                "print('compile-output-before-marker', flush=True); time.sleep(.15); " + \
                f"Path({str(marker)!r}).write_text({json.dumps(payload)!r}); " + \
                "time.sleep(.2); print('later verifier output', flush=True)"
            result = runner.execute([sys.executable, "-c", command], root, root / "run", timeout=3,
                compile_marker=marker, compile_selectors=[selector], compile_timeout=2)
            self.assertEqual(result["compile_receipt"]["status"], "COMPLETE")
            self.assertEqual(result["compile_receipt"]["boundary"], "PINNED_KANI_INCOMPLETE_EXPORT_MARKER")
            marker_digest = runner.sha256(marker)
            self.assertEqual(result["compile_receipt"]["export_marker_sha256"], marker_digest)
            snapshots = result["compile_receipt"]["output_snapshots"]
            compile_tail = Path(snapshots["stdout"]["tail_path"]).read_text()
            self.assertIn("compile-output-before-marker", compile_tail)
            self.assertNotIn("later verifier output", compile_tail)
            persisted = json.loads((root / "run/compile-receipt.json").read_text())
            self.assertEqual(persisted["status"], "COMPLETE")
            self.assertEqual(persisted["export_marker_sha256"], marker_digest)
            self.assertNotIn("later verifier output", Path(persisted["output_snapshots"]["stdout"]["tail_path"]).read_text())
            for field, value in (("target", "aarch64-unknown-linux-gnu"),
                                 ("target", None), ("harness_timeout_s", 1),
                                 ("harness_timeout_s", None), ("harness_timeout_s", True)):
                invalid = dict(payload); invalid[field] = value
                marker.write_text(json.dumps(invalid))
                self.assertFalse(runner._valid_compile_marker(marker, [selector]))
            marker.write_bytes(b"x" * 11)
            with mock.patch.object(runner, "EXPORT_CAP_BYTES", 10):
                self.assertFalse(runner._valid_compile_marker(marker, [selector]))

    def test_monitor_exception_kills_and_reaps_child_group(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            real_popen = runner.subprocess.Popen
            started = []
            def capture_popen(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                started.append(child)
                return child
            script = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); time.sleep(30)"
            with mock.patch.object(runner.subprocess, "Popen", side_effect=capture_popen), \
                 mock.patch.object(runner, "_group_rss_kib", side_effect=RuntimeError("synthetic sampler failure")):
                result = runner.execute([sys.executable, "-c", script], root, root / "run", timeout=60)
            self.assertEqual(len(started), 1)
            child = started[0]
            self.assertIsNotNone(child.poll(), "parent child process must be reaped")
            self.assertFalse(runner._group_has_live_members(child.pid), "no group descendants may remain")
            self.assertIn("synthetic sampler failure", result["monitor_error"])
            self.assertEqual(result["termination_reason"], "monitor_exception")
            self.assertEqual(result["original_exit_code"], child.returncode)
            self.assertIsNotNone(result["signal"])

    def test_stale_marker_refused_and_group_exit_mismatch_stays_partial(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "export.json"
            path.write_text(json.dumps(export()))
            with self.assertRaisesRegex(runner.RunnerError, "pre-existing group export"):
                runner._require_fresh_export(path)
            selector = row()["selector"]
            complete = runner._group_execution_status(
                {"original_exit_code": 1, "signal": None, "timed_out": False, "termination_reason": None},
                path, [selector])
            self.assertEqual(complete, (False, "EXIT_MISMATCH", 0))
            timed = runner._group_execution_status(
                {"original_exit_code": 0, "signal": None, "timed_out": True, "termination_reason": "timeout"},
                path, [selector])
            self.assertEqual(timed, (False, "PARTIAL", 0))

    def test_group_timeout_outcome_requires_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "export.json"
            payload = export()
            payload["harnesses"][0]["outcome"] = {"kind": "TIMEOUT"}
            path.write_text(json.dumps(payload))
            selector = row()["selector"]
            self.assertEqual(runner._expected_group_exit(path, [selector]), 1)
            complete = runner._group_execution_status(
                {"original_exit_code": 1, "signal": None, "timed_out": False, "termination_reason": None},
                path, [selector])
            self.assertEqual(complete, (True, "COMPLETE", 1))

    def test_expected_group_exit_rejects_oversized_export_before_read(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "export.json"
            path.write_bytes(b"x" * 11)
            with mock.patch.object(runner, "EXPORT_CAP_BYTES", 10):
                self.assertIsNone(runner._expected_group_exit(path, [row()["selector"]]))

    def test_offline_inventory_seeds_frozen_targets_without_kani_list(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); std = root / "std"; tool = root / "tool"; out = root / "out"
            std.mkdir(); tool.mkdir()
            request = {"rows": [row()], "base_std_sha": "c5ff36ff433692140605891f646043f991db05de"}
            with mock.patch.object(runner, "verify_source", return_value={"std_sha": runner.STD_SHA}), \
                 mock.patch.object(runner.subprocess, "run", side_effect=AssertionError("external command")):
                runner.seed_inventory(std, tool, out, request)
            inventory = json.loads((out / "inventory.json").read_text())
            self.assertEqual(inventory["inventory_source"], "FROZEN_CI_REQUEST_ROWS_NOT_KANI_LIST")
            self.assertEqual(inventory["expected_source_targets"], {row()["selector"]: row()["target"]})
            self.assertNotIn("contract_binding", inventory)
            self.assertNotIn("list_execution", inventory)

    def test_output_and_export_caps_kill_child(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "stdout"
            capped = runner.execute([sys.executable, "-c", "import sys; sys.stdout.write('x'*1000000); sys.stdout.flush(); import time; time.sleep(2)"],
                                    Path(d), out, timeout=5, stdout_cap=1024)
            self.assertEqual(capped["termination_reason"], "stdout_cap")
            self.assertLessEqual((out / "stdout.log").stat().st_size, 1024)
            export_path = Path(d) / "oversize-export.json"
            export_run = runner.execute([sys.executable, "-c",
                f"from pathlib import Path; import time; Path({str(export_path)!r}).write_bytes(b'x'*5000); time.sleep(2)"],
                Path(d), Path(d) / "export-cap", timeout=5, export_path=export_path, export_cap=1024)
            self.assertEqual(export_run["termination_reason"], "export_cap")

    def test_external_signal_kills_child_and_returns_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            timer = threading.Timer(0.25, lambda: os.kill(os.getpid(), runner.signal.SIGTERM))
            timer.start()
            try:
                result = runner.execute([sys.executable, "-c", "import time; time.sleep(4)"],
                                        Path(d), Path(d) / "external", timeout=8)
            finally:
                timer.cancel()
            self.assertEqual(result["interrupted_by_signal"], runner.signal.SIGTERM)
            self.assertEqual(result["termination_reason"], "external_signal")


class BatchTests(unittest.TestCase):
    def test_expected_negative_nonzero_exit_is_preserved(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); std = root / "std"; tool = root / "tool"; out = root / "out"
            std.mkdir(); tool.mkdir(); (tool / "scripts").mkdir(parents=True)
            row_obj = row(id="negative", expected="DETECTED", required_cover_count=0,
                failure_match={"class": "assigns",
                    "description_regex": r"^Check that .+ is assignable$",
                    "locations": [{"file": "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs", "line": "23"},
                                  {"file": "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs", "line": "25"}]})
            payload = export(verdict="FAILURE", failures=["property-1"], named=[
                {"id": "property-1", "description": "Check that write to source is assignable",
                 "class": "assigns", "file": "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs", "line": "23"}])
            script = tool / "scripts/kani"
            script.write_text("#!" + sys.executable + "\nimport json,sys\nfrom pathlib import Path\n"
                              "p=Path(sys.argv[sys.argv.index('--export-json')+1])\n"
                              "filters=[]\n"
                              "for i,arg in enumerate(sys.argv[:-1]):\n"
                              "  if arg=='--harness': filters.append(sys.argv[i+1])\n"
                              "marker={'schema_version':'0.1.0','run_state':'INCOMPLETE','kani_commit':" + repr(runner.TOOL_SHA) + ","
                              "'kani_commit_dirty':False,'target':'x86_64-unknown-linux-gnu','harness_timeout_s':600.0,"
                              "'harness_selection':{'requested_filters':filters,'exact':True,'unmatched_filters':[],'matched_count':len(filters)}}\n"
                              "p.write_text(json.dumps(marker)); import time; time.sleep(.15)\n"
                              f"p.write_text({json.dumps(payload)!r})\n"
                              "raise SystemExit(1)\n")
            script.chmod(script.stat().st_mode | stat.S_IXUSR)
            out.mkdir()
            groups = runner._group_rows([row_obj])
            (out / "inventory.json").write_text(json.dumps({"state": "INVENTORY_FROZEN_NOT_RUN",
                "inventory_source": "FROZEN_CI_REQUEST_ROWS_NOT_KANI_LIST",
                "phase_started_unix": __import__("time").time(),
                "request_sha256": runner.sha256(runner.REQUEST_PATH),
                "groups": [{"row_ids": [row_obj["id"]]}],
                "expected_source_targets": {row_obj["selector"]: "slice::sort::body"}}))
            request = {"rows": [row_obj], "changed_file_sha256": {}, "variants": {},
                       "base_std_sha": "c5ff36ff433692140605891f646043f991db05de"}
            fp = {"required_hashes_present": True, "binaries": {}, "reported_versions": {}}
            with mock.patch.object(runner, "verify_source", return_value={}), \
                 mock.patch.object(runner, "binary_fingerprints", return_value=fp), \
                 mock.patch.object(runner, "_group_rss_limit_kib", return_value=8 * 1024 * 1024):
                code = runner.run_rows(std, tool, out, request)
            receipt = json.loads((out / "negative/receipt.json").read_text())
            self.assertEqual(code, 0, json.dumps(receipt, sort_keys=True))
            self.assertEqual(receipt["outcome"], "EXPECTED")
            self.assertEqual(receipt["group_exit_code"], 1)
            self.assertIsNone(receipt["signal"])
            batch_receipt = json.loads((out / "receipt.json").read_text())
            self.assertEqual(batch_receipt["state"], "COMPLETE")
            self.assertTrue(batch_receipt["complete"])

    def test_grouping_separates_unwind_but_batches_same_flags(self):
        rows = [row(id=f"eight-{index}", selector=f"slice::sort::eight-{index}", unwind=8)
                for index in range(3)]
        rows.append(row(id="twelve", selector="slice::sort::twelve", unwind=12))
        groups = runner._group_rows(rows)
        self.assertEqual([[r["id"] for r in group] for group in groups],
                         [["eight-0", "eight-1", "eight-2"], ["twelve"]])
        argv = runner.build_argv(Path("/std"), Path("/tool"),
            [r["selector"] for r in groups[0]], 8, Path("/tmp/group.json"))
        self.assertEqual(argv.count("--harness"), 3)
        self.assertIn("600s", argv)
        self.assertEqual(argv[argv.index("--default-unwind") + 1], "8")

    def test_wrong_group_exit_keeps_row_observation_but_marks_batch_partial(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); std = root / "std"; tool = root / "tool"; out = root / "out"
            std.mkdir(); tool.mkdir(); out.mkdir()
            negative_row = row(id="negative", expected="DETECTED", required_cover_count=0,
                failure_match={"class": "assigns", "description_regex": r"^Check that .+ is assignable$",
                    "locations": [{"file": "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs", "line": "23"}]})
            payload = export(verdict="FAILURE", failures=["property-1"], named=[
                {"id": "property-1", "description": "Check that write to source is assignable",
                 "class": "assigns", "file": "library/core/src/slice/sort/shared/smallsort/verify/c_controls.rs", "line": "23"}])
            (out / "inventory.json").write_text(json.dumps({
                "state": "INVENTORY_FROZEN_NOT_RUN", "inventory_source": "FROZEN_CI_REQUEST_ROWS_NOT_KANI_LIST",
                "phase_started_unix": 1, "request_sha256": runner.sha256(runner.REQUEST_PATH),
                "expected_source_targets": {negative_row["selector"]: negative_row["target"]},
                "groups": [{"row_ids": ["negative"]}]}))
            request = {"rows": [negative_row], "changed_file_sha256": {}, "variants": {},
                       "base_std_sha": "c5ff36ff433692140605891f646043f991db05de"}
            fingerprints = {"required_hashes_present": True, "binaries": {}, "reported_versions": {}}
            def fake_execute(_argv, _cwd, _out, _timeout, **kwargs):
                kwargs["export_path"].write_text(json.dumps(payload))
                return {"original_exit_code": 0, "signal": None, "timed_out": False,
                        "termination_reason": None, "rss_peak_kib": 100, "rss_peak_gib": 0.001,
                        "stdout_truncated": False, "stderr_truncated": False}
            with mock.patch.object(runner, "verify_source", return_value={}), \
                 mock.patch.object(runner, "binary_fingerprints", return_value=fingerprints), \
                 mock.patch.object(runner, "_group_rss_limit_kib", return_value=8 * 1024 * 1024), \
                 mock.patch.object(runner, "execute", side_effect=fake_execute):
                code = runner.run_rows(std, tool, out, request)
            row_receipt = json.loads((out / "negative/receipt.json").read_text())
            batch_receipt = json.loads((out / "receipt.json").read_text())
            self.assertEqual(code, 1)
            self.assertEqual(row_receipt["outcome"], "EXPECTED")
            self.assertFalse(row_receipt["complete"])
            self.assertEqual(row_receipt["group_status"], "EXIT_MISMATCH")
            self.assertEqual(batch_receipt["state"], "PARTIAL")
            self.assertFalse(batch_receipt["complete"])


if __name__ == "__main__":
    unittest.main()
