#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Synthetic tests for complete, root-bound mixed inventory comparisons."""
import unittest
import io
from contextlib import redirect_stdout, redirect_stderr
import tempfile
import hashlib
import json
import copy
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from compare import Rejected, check_single, compare_pair, compare_root, compare_selection
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
            "n_failed": len(failures), "checks": checks, "covers": [],
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


class PortableObservationTests(unittest.TestCase):
    def fixture(self):
        data, text, selectors, cases, receipt = observation_fixture()
        source = "tests/json-handler/uninit-part1-composition/mixed.rs"
        # Exercise paths embedded in IDs and diagnostics, plus external JSON
        # failure files and regular source locations, through the real consumer.
        renamed = "root::{closure@" + source + ":27:17: 27:43}.read.1"
        diagnostic = ("cycle [call at " + source + ":81] -> {closure@" + source + ":67:1}")
        toolchain = ("rust-toolchain:nightly-2026-10-23-x86_64-unknown-linux-gnu/"
                     "library/core/src/ptr/mod.rs")

        def change(value):
            if isinstance(value, dict):
                return {key: change(item) for key, item in value.items()}
            if isinstance(value, list):
                return [change(item) for item in value]
            if isinstance(value, str):
                return value.replace("root.read.1", renamed).replace("cycle boundary", diagnostic)
            return value

        data = change(data)
        text = change(text)
        data["harnesses"][0]["failed_properties"][0]["file"] = toolchain
        text = text.replace(source + ":24:1 in function", toolchain + ":24:1 in function")
        return data, text, selectors, cases, receipt, source

    def test_consumer_relocation_keeps_exact_inventory_and_embedded_identities(self):
        data, text, selectors, cases, receipt, source = self.fixture()
        baseline = observation(data, text, selectors, cases, receipt)["roots"][0]
        expected = dict(baseline, binding="REGRESSION_BOUND", expected_verdict="FAILURE")
        for prefix, install, relative in (
                ("/root/kani", "/root/.rustup", "../../"),
                ("/home/runner/work/kani/kani/export", "/home/runner/.rustup", "../../../../"),
                ("/tmp/deep checkout/a/b", "/opt/custom-rustup", "../../../../../")):
            def relocate(value):
                if isinstance(value, dict):
                    return {key: relocate(item) for key, item in value.items()}
                if isinstance(value, list):
                    return [relocate(item) for item in value]
                if isinstance(value, str):
                    return value.replace(source, prefix + "/" + source).replace(
                        "rust-toolchain:", install + "/toolchains/").replace(
                        "/library/core/", "/lib/rustlib/src/rust/library/core/")
                return value

            moved = relocate(data)
            log = relocate(text).replace(install + "/", relative + ".rustup/")
            log = "warning: requested with `--force-warn unstable-features`\n" + log
            moved_receipt = dict(receipt, build_prefix=prefix)
            with self.subTest(prefix=prefix):
                actual = observation(moved, log, selectors, cases, moved_receipt)["roots"][0]
                self.assertEqual(actual, baseline)
                self.assertTrue(check_single(actual, expected))
                # Consistent changes to JSON and regular must still fail binding.
                for before, after in (("ptr/mod.rs", "mem/mod.rs"), (":27:17", ":27:18"),
                                      ("cycle [call", "other [call"), (":81]", ":82]"),
                                      ("2026-10-23", "2026-10-24")):
                    mutated = json.loads(json.dumps(moved).replace(before, after))
                    mutated_log = log.replace(before, after)
                    with self.subTest(mutation=after), self.assertRaises(Rejected):
                        observed = observation(mutated, mutated_log, selectors, cases, moved_receipt)
                        check_single(observed["roots"][0], expected)


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

    def shared_check(self, number=5, status="SUCCESS"):
        row = check(f"std::ptr::read::<u8>.safety_check.{number}", status)
        row["location"] = "library/core/src/ptr/mod.rs:1754:9 in function std::ptr::read::<u8>"
        return row

    def test_shared_superset_and_subset_are_diagnostic_but_rejected(self):
        extra = [self.shared_check(), self.shared_check(6, "UNREACHABLE")]
        mixed = copy.deepcopy(self.legal)
        mixed["checks"] += extra
        for before, after, direction in ((self.legal, mixed, "added"),
                                         (mixed, self.legal, "removed")):
            with self.subTest(direction=direction):
                with self.assertRaisesRegex(Rejected, "mixed-root inventory changed: legal"):
                    compare_pair(run(before), run(after), self.expected)
                diff = compare_root(before, after)
                self.assertFalse(diff["exact_match"])
                self.assertFalse(diff["accepted"])
                self.assertEqual(diff["differences"]["checks"][direction], extra)

    def test_shared_failure_multiset_drift_is_rejected(self):
        baseline = root("legal", [self.shared_check(1, "FAILURE")], "FAILURE")
        for mutation in ("extra", "missing", "id", "description", "location"):
            changed = copy.deepcopy(baseline)
            if mutation == "extra":
                changed = root("legal", baseline["checks"] + [self.shared_check(2, "FAILURE")],
                               "FAILURE")
            elif mutation == "missing":
                changed = root("legal", [])
            elif mutation == "location":
                changed["checks"][0]["location"] = "other.rs:99"
                changed["failed_properties"][0].update(file="other.rs", line="99")
            else:
                changed["checks"][0][mutation] += "changed"
                changed["failed_properties"][0][mutation] += "changed"
            with self.subTest(mutation=mutation), self.assertRaisesRegex(Rejected, "inventory changed"):
                compare_pair(run(baseline), run(changed), self.expected)

    def test_root_target_unknown_and_useful_check_drift_is_rejected(self):
        for function in ("legal", "pfc_contract", "repeated_relay", "unknown::<u8>"):
            changed = copy.deepcopy(self.legal)
            changed["checks"].append(check(function + ".safety_check.9"))
            changed["checks"][-1]["location"] = "fixture.rs:1 in function " + function
            with self.subTest(function=function), self.assertRaisesRegex(Rejected, "inventory changed"):
                compare_pair(run(self.legal), run(changed), self.expected)
        for prop_class in ("assertion", "reachability_check", "cover"):
            changed = copy.deepcopy(self.legal)
            extra = self.shared_check()
            extra["id"] = extra["id"].replace("safety_check", prop_class)
            changed["checks"].append(extra)
            self.assertFalse(compare_root(self.legal, changed)["accepted"])

    def test_shared_existing_identity_and_status_cannot_drift(self):
        baseline = root("legal", [self.shared_check()])
        for field, value in (("status", "UNREACHABLE"), ("description", "changed"),
                             ("location", "other.rs:1 in function std::ptr::read::<u8>")):
            changed = copy.deepcopy(baseline)
            changed["checks"][0][field] = value
            with self.subTest(field=field):
                self.assertFalse(compare_root(baseline, changed)["accepted"])

    def test_verdict_unsupported_and_reached_covers_stay_exact(self):
        changed = copy.deepcopy(self.legal)
        changed["verdict"] = "FAILURE"
        self.assertFalse(compare_root(self.legal, changed)["accepted"])
        baseline = copy.deepcopy(self.legal)
        baseline["checks"].append(self.shared_check())
        changed = copy.deepcopy(baseline)
        changed["unsupported_constructs"] = [dict(failed_metadata(changed["checks"][-1]),
                                                  status="SUCCESS")]
        self.assertFalse(compare_root(baseline, changed)["accepted"])
        baseline["covers"] = [check("useful.cover.1", "SATISFIED")]
        for covers in ([], [check("useful.cover.1", "UNSATISFIABLE")],
                       [check("other.cover.1", "SATISFIED")]):
            changed = copy.deepcopy(baseline)
            changed["covers"] = covers
            self.assertFalse(compare_root(baseline, changed)["accepted"])

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

    def test_reached_cover_is_retained_with_exact_identity_and_location(self):
        data, regular, selectors, cases, receipt = observation_fixture()
        harness = data["harnesses"][0]
        harness["covers"].update(total=1, satisfied=["root.cover.1"])
        harness["n_properties"] += 1
        data["summary"].update(covers_total=1, covers_satisfied=1)
        regular = regular.replace("\nSUMMARY:", 'Check 5: root.cover.1\n'
                                  '\t - Status: SATISFIED\n'
                                  '\t - Description: "useful path reached"\n'
                                  '\t - Location: fixture.rs:1 in function root\n\nSUMMARY:')
        result = observation(data, regular, selectors, cases, receipt)
        self.assertEqual(result["roots"][0]["covers"], [
            {"id": "root.cover.1", "status": "SATISFIED", "description": "useful path reached",
             "location": "fixture.rs:1 in function root"}])
        harness["covers"]["satisfied"] = ["wrong.cover.1"]
        with self.assertRaisesRegex(Rejected, "cover inventory mismatch"):
            observation(data, regular, selectors, cases, receipt)

    def test_pfc_target_accepts_bare_and_qualified_names_but_rejects_other_targets(self):
        for target in ("pfc_contract", "mixed::pfc_contract", "other_contract",
                       "not_pfc_contract", "mixed::not_pfc_contract"):
            with self.subTest(target=target):
                data, regular, selectors, cases, receipt = observation_fixture()
                case = cases[selectors[0]]
                case.update(mode="PFC", target="pfc_contract")
                data["harnesses"][0]["attributes"]["kind"] = {
                    "ProofForContract": {"target_fn": target}}
                if target in ("pfc_contract", "mixed::pfc_contract"):
                    observation(data, regular, selectors, cases, receipt)
                else:
                    with self.assertRaisesRegex(Rejected, "wrong PFC target.*actual="):
                        observation(data, regular, selectors, cases, receipt)

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
        self.assertEqual(receipt["expected_exit"], 0)
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


class CaptureDiagnosticTests(unittest.TestCase):
    def invoke(self, fail_run=None, compare_error=False, corrupt_receipt=False,
               collect_unbound=True, report_error=False, interrupt=False, shared_extra=False,
               failure_drift=False, bound_manifest=False, stale_binding=False):
        args = SimpleNamespace(kani="must-not-run", keep_output=True,
                               collect_unbound=collect_unbound)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            output, errors = io.StringIO(), io.StringIO()
            manifest = json.loads((mixed_runner.HERE / "roots.json").read_text())
            if bound_manifest:
                for case in manifest["roots"]:
                    baseline = root(case["name"], [check(case["name"], "FAILURE" if
                                    case["expected_verdict"] == "FAILURE" else "SUCCESS")],
                                    case["expected_verdict"])
                    case.update(binding="REGRESSION_BOUND", expected_inventory=baseline["checks"],
                                expected_failure_kind=baseline["failure_kind"],
                                expected_failures=baseline["failed_properties"],
                                expected_unsupported_inventory=baseline["unsupported_constructs"])
                    if stale_binding:
                        case["expected_inventory"] = [check("stale.golden.binding")]
            else:
                # Exercise the pending guard independently of committed bindings.
                manifest["roots"][0]["binding"] = "BINDING_PENDING"
            (base / "roots.json").write_text(json.dumps(manifest))

            def execute(_kani, _manifest, selectors, cases, _parent, run_id):
                if run_id == fail_run:
                    directory = base / run_id
                    directory.mkdir()
                    if corrupt_receipt:
                        (directory / "receipt.json").write_text('{"broken":')
                    (directory / "regular.out").write_text("VERIFICATION:- SUCCESSFUL\n")
                    if interrupt:
                        raise KeyboardInterrupt()
                    raise Rejected("wrong PFC target: pfc_legal")
                roots = [root(name, [check(name, "FAILURE" if
                         cases[name]["expected_verdict"] == "FAILURE" else "SUCCESS")],
                         cases[name]["expected_verdict"]) for name in selectors]
                if compare_error and run_id == "all_A_then_B":
                    roots[0]["checks"][0]["location"] = "changed.rs:1"
                if shared_extra and run_id == "all_A_then_B":
                    row = check("std::ptr::read::<u8>.safety_check.5")
                    row["location"] = "ptr/mod.rs:1754:9 in function std::ptr::read::<u8>"
                    roots[0]["checks"].append(row)
                if failure_drift and run_id == "all_A_then_B":
                    roots[0] = root(roots[0]["expected_root"], [check("unexpected", "FAILURE")],
                                    "FAILURE")
                return run(*roots), {"run_id": run_id}

            original_write = Path.write_text

            def write_text(path, *args, **kwargs):
                if report_error and path == base / "capture.json":
                    raise OSError("report disk failure")
                return original_write(path, *args, **kwargs)

            with mock.patch.object(mixed_runner.tempfile, "mkdtemp", return_value=str(base)), \
                    mock.patch.object(mixed_runner, "HERE", base), \
                    mock.patch.object(mixed_runner, "execute", side_effect=execute) as invoked, \
                    mock.patch.object(mixed_runner.subprocess, "run") as process, \
                    mock.patch.object(Path, "write_text", write_text), \
                    redirect_stdout(output), redirect_stderr(errors):
                code = mixed_runner.capture(args)
            process.assert_not_called()
            report = json.loads((base / "capture.json").read_text()) if (
                base / "capture.json").exists() else None
            return code, report, output.getvalue(), errors.getvalue(), invoked.call_count

    def test_isolated_and_combined_failures_report_step_and_reason_after_logs(self):
        for run_id in ("isolated-pfc_legal", "all_A_then_B"):
            with self.subTest(run_id=run_id):
                code, report, output, errors, _ = self.invoke(fail_run=run_id)
                self.assertEqual(code, 1)
                self.assertEqual(report["status"], "FAIL")
                self.assertEqual(report["step"], run_id + ": execute/observe")
                self.assertIn("VERIFICATION:- SUCCESSFUL", output)
                self.assertIn(run_id + ": execute/observe: Rejected: wrong PFC target",
                              errors.splitlines()[-1])

    def test_inventory_comparison_failure_records_diff_and_completes_all_runs(self):
        code, report, _, errors, count = self.invoke(compare_error=True)
        self.assertEqual(code, 2)
        self.assertEqual(count, 11)
        self.assertEqual(report["status"], "UNBOUND_CAPTURE")
        self.assertEqual(report["mixed_root_oracle"], "MISMATCH")
        mismatches = [item for item in report["mixed_root_comparisons"] if not item["accepted"]]
        self.assertEqual(len(mismatches), 1)
        self.assertEqual(mismatches[0]["order"], "all_A_then_B")
        self.assertEqual(mismatches[0]["root"], "immutable_legal")
        self.assertEqual(mismatches[0]["differences"]["checks"]["added"][0]["location"],
                         "changed.rs:1")
        self.assertEqual(len(report["combined_inventory_observations"]), 4)
        self.assertEqual(errors, "")

    def test_shared_superset_capture_records_mismatch_and_completes_all_runs(self):
        code, report, _, errors, count = self.invoke(shared_extra=True)
        self.assertEqual(code, 2)
        self.assertEqual(count, 11)
        self.assertEqual(report["mixed_root_oracle"], "MISMATCH")
        self.assertFalse(report["mixed_root_comparisons"][0]["accepted"])
        self.assertEqual(report["mixed_root_comparisons"][0]["differences"]["checks"]["added"][0],
                         {"id": "std::ptr::read::<u8>.safety_check.5",
                          "status": "SUCCESS", "description": "std::ptr::read::<u8>.safety_check.5",
                          "location": "ptr/mod.rs:1754:9 in function std::ptr::read::<u8>"})
        self.assertEqual(errors, "")

    def test_failure_drift_capture_retains_failure_metadata_and_runs_all_orders(self):
        code, report, _, errors, count = self.invoke(failure_drift=True)
        self.assertEqual((code, count), (2, 11))
        self.assertEqual(report["mixed_root_oracle"], "MISMATCH")
        diff = report["mixed_root_comparisons"][0]
        self.assertFalse(diff["accepted"])
        self.assertEqual(diff["differences"]["verdict"],
                         {"isolated": "SUCCESS", "combined": "FAILURE"})
        self.assertEqual(diff["differences"]["failed_properties"]["added"][0],
                         failed_metadata(check("unexpected", "FAILURE")))
        self.assertEqual(errors, "")

    def test_bound_regression_uses_oracle_and_explicit_capture_never_claims_pass(self):
        for shared, failure, collect, expected_code in ((False, False, False, 0),
                                                      (True, False, False, 1),
                                                      (False, True, False, 1),
                                                      (False, False, True, 2)):
            with self.subTest(shared=shared, failure=failure, collect=collect):
                code, report, _, _, count = self.invoke(
                    shared_extra=shared, failure_drift=failure, collect_unbound=collect,
                    bound_manifest=True)
                self.assertEqual(code, expected_code)
                if code != 1:
                    self.assertEqual(count, 11)
                    self.assertEqual(report["status"], "UNBOUND_CAPTURE" if collect else "PASS")

    def test_explicit_capture_skips_stale_golden_bindings(self):
        code, report, _, errors, count = self.invoke(
            collect_unbound=True, bound_manifest=True, stale_binding=True)
        self.assertEqual((code, count), (2, 11))
        self.assertEqual(report["status"], "UNBOUND_CAPTURE")
        self.assertEqual(report["binding_status"], "NOT_CHECKED_CAPTURE")
        self.assertEqual(report["mixed_root_oracle"], "EXACT_MATCH")
        self.assertEqual(errors, "")

    def test_corrupt_receipt_does_not_mask_original_failure(self):
        code, report, _, errors, _ = self.invoke(fail_run="isolated-pfc_legal",
                                                corrupt_receipt=True)
        self.assertEqual(code, 1)
        self.assertIn("read_error", report["runs"][0])
        self.assertIn("wrong PFC target", errors.splitlines()[-1])

    def test_report_write_failure_does_not_mask_original_failure(self):
        code, report, _, errors, _ = self.invoke(fail_run="isolated-pfc_legal",
                                                report_error=True)
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertIn("Could not save failure report: report disk failure", errors)
        self.assertIn("wrong PFC target", errors.splitlines()[-1])

    def test_preflight_binding_pending_reports_reason_without_executing(self):
        code, report, _, errors, count = self.invoke(collect_unbound=False)
        self.assertEqual(code, 1)
        self.assertIsNone(report)
        self.assertEqual(count, 0)
        self.assertIn("Composition stopped at preflight: Rejected: BINDING_PENDING", errors)

    def test_keyboard_interrupt_reports_active_step(self):
        code, report, _, errors, _ = self.invoke(fail_run="all_A_then_B", interrupt=True)
        self.assertEqual(code, 130)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("all_A_then_B: execute/observe: KeyboardInterrupt", errors)

    def test_complete_unbound_capture_still_exits_two_without_pass_credit(self):
        code, report, _, errors, count = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(count, 11)
        self.assertEqual(report["status"], "UNBOUND_CAPTURE")
        self.assertEqual(report["binding_status"], "NOT_CHECKED_CAPTURE")
        self.assertEqual(report["order_credit"], "NOT_ESTABLISHED")
        self.assertEqual(errors, "")


def subprocess_timeout():
    import subprocess
    return subprocess.TimeoutExpired("fake-kani", 180)


if __name__ == "__main__":
    unittest.main()
