#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Synthetic collector checks only. These never run Kani or establish a Rust result."""
import contextlib
import copy
import io
import json
import signal
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from observe import observe
from run import collect, invoke

ROOTS = json.loads(Path(__file__).with_name("roots.json").read_text())["roots"]


def export_for(root, verdict="SUCCESS"):
    mode, target = root["intended_mode"], root["target"]
    kind = {"ProofForContract": {"target_fn": target}} if mode.endswith("Check") else "Proof"
    failures = [] if verdict == "SUCCESS" else [dict(id="payload.assertion.1", status="FAILURE",
                description="synthetic payload check", **{"class": "assertion"})]
    return dict(schema_version="0.1.0", run_state="COMPLETE", outcome={"kind": "COMPLETED"},
                harness_selection=dict(exact=True, matched_count=1, unmatched_filters=[],
                                       requested_filters=[root["harness"]]),
                enabled_unstable_features=["uninit-checks", "function-contracts", "stubbing",
                                           "export-json", "unstable-options"],
                configuration=dict(cbmc_args=["--object-bits", "12"], checks=dict(
                    memory_safety=True, overflow=True, unwinding=True, undefined_function=True,
                    assertion_reach_checks=True, assert_contracts=True, prove_safety_only=False)),
                harnesses=[dict(name=root["harness"], outcome=dict(kind="COMPLETED", verdict=verdict),
                    attributes=dict(kind=kind, should_panic=False, stubs=[], unwind_value=8,
                                    verified_stubs=[target] if mode == "Replace" else []),
                    contract=dict(recursion_tracker="recursive::REENTRY" if mode == "RecursiveCheck"
                                  else None) if mode.endswith("Check") else None,
                    resolved_unwind=8, failed_properties=failures, unsupported_constructs=[],
                    n_failed=len(failures), n_properties=3,
                    checks=dict(total=1, success=int(not failures), failure=[p["id"] for p in failures],
                                unreachable=[], undetermined=[], error=[], unknown=[], other=[]),
                    covers=dict(total=2, satisfied=["new.cover.1", "uninit.cover.2"],
                                unsatisfiable=[], unreachable=[], undetermined=[], error=[],
                                unknown=[], other=[]))],
                summary=dict(total=1, successful=int(not failures), failed=int(bool(failures)),
                             checks_total=1, checks_success=int(not failures), covers_total=2,
                             covers_satisfied=2))


class ObserverTests(unittest.TestCase):
    def test_all_modes_preserve_success_without_qualification(self):
        for root in ROOTS:
            with self.subTest(root=root["harness"]):
                result = observe(export_for(root), root, 0)
                self.assertFalse(result["mode_qualification"])
                self.assertEqual(result["binding_status"], "BINDING_PENDING")

    def test_boundary_failure_is_collected_without_a_golden(self):
        root = ROOTS[0]
        result = observe(export_for(root, "FAILURE"), root, 1)
        self.assertEqual(len(result["failures"]), 1)
        self.assertIsNone(result["companion_pass"])

    def test_companion_failure_is_not_a_pass(self):
        root = ROOTS[1]
        self.assertFalse(observe(export_for(root, "FAILURE"), root, 1)["companion_pass"])

    def test_reject_partial_crash_timeout_and_oom(self):
        root = ROOTS[0]
        for state in ("PARTIAL", "INCOMPLETE", "NO_HARNESSES_SELECTED"):
            data = export_for(root)
            data["run_state"] = state
            with self.assertRaises(ValueError):
                observe(data, root, 0)
        for kind in ("TIMEOUT", "CRASHED", "OUT_OF_MEMORY"):
            data = export_for(root)
            data["harnesses"][0]["outcome"] = {"kind": kind}
            with self.assertRaises(ValueError):
                observe(data, root, 1)

    def test_reject_selection_root_exit_and_inventory_drift(self):
        root = ROOTS[0]
        for change in (
            lambda d: d["harness_selection"].update(exact=False),
            lambda d: d["harness_selection"].update(matched_count=0),
            lambda d: d["harnesses"].append(copy.deepcopy(d["harnesses"][0])),
            lambda d: d["harnesses"][0].update(name="other"),
            lambda d: d["harnesses"][0].update(n_failed=1),
            lambda d: d["harnesses"][0]["checks"].update(unknown=["unknown.1"]),
            lambda d: d["summary"].update(successful=0),
        ):
            data = export_for(root)
            change(data)
            with self.assertRaises(ValueError):
                observe(data, root, 0)
        with self.assertRaises(ValueError):
            observe(export_for(root), root, 1)

    def test_reject_stub_target_and_recursion_tracker_loss(self):
        data = export_for(ROOTS[0])
        data["harnesses"][0]["attributes"]["verified_stubs"] = ["wrong_target"]
        with self.assertRaises(ValueError):
            observe(data, ROOTS[0], 0)
        for root in (ROOTS[2], ROOTS[3]):
            data = export_for(root)
            tracker = data["harnesses"][0]["contract"]["recursion_tracker"]
            data["harnesses"][0]["contract"]["recursion_tracker"] = None if tracker else "wrong"
            with self.assertRaises(ValueError):
                observe(data, root, 0)

    def test_unsupported_frame_and_unreached_paths_are_explicit_gaps(self):
        root = ROOTS[0]
        data = export_for(root, "FAILURE")
        harness = data["harnesses"][0]
        harness["failed_properties"][0]["description"] = "*p is assignable"
        harness["unsupported_constructs"] = [harness["failed_properties"][0]]
        harness["covers"]["unreachable"] = [harness["covers"]["satisfied"].pop()]
        data["summary"]["covers_satisfied"] = 1
        result = observe(data, root, 1)
        self.assertEqual(len(result["gaps"]), 3)
        self.assertFalse(result["mode_qualification"])

    def test_reject_weakened_checks_profile_and_bounds(self):
        root = ROOTS[0]
        for change in (
            lambda d: d["configuration"]["checks"].update(assert_contracts=False),
            lambda d: d["configuration"].update(cbmc_args=["--object-bits", "16"]),
            lambda d: d["harnesses"][0].update(resolved_unwind=1),
            lambda d: d.update(enabled_unstable_features=["export-json"]),
        ):
            data = export_for(root)
            change(data)
            with self.assertRaises(ValueError):
                observe(data, root, 0)

    def test_successful_unsupported_property_is_not_a_failure_gap(self):
        root = ROOTS[1]
        data = export_for(root)
        data["harnesses"][0]["unsupported_constructs"] = [{"status": "SUCCESS"}]
        self.assertTrue(observe(data, root, 0)["companion_pass"])


class CollectorTests(unittest.TestCase):
    def run_collector(self, destination, fake):
        with patch("run.invoke", side_effect=fake) as invocation, contextlib.redirect_stdout(io.StringIO()):
            result = collect("NEVER_EXECUTED_KANI", destination)
        return result, invocation.call_count

    def test_fresh_runs_commands_and_all_outcomes_are_saved(self):
        def fake(command, work, log, timeout):
            root = next(r for r in ROOTS if r["harness"] == command[command.index("--harness") + 1])
            self.assertEqual(command[-3:], ["--cbmc-args", "--object-bits", "12"])
            self.assertLess(command.index("unstable-options"), command.index("--cbmc-args"))
            self.assertEqual(timeout, 180)
            verdict = "SUCCESS" if root["companion"] else "FAILURE"
            path = Path(command[command.index("--export-json") + 1])
            path.write_text(json.dumps(export_for(root, verdict)))
            return 0 if root["companion"] else 1
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "results"
            result, calls = self.run_collector(destination, fake)
            self.assertEqual((result, calls), (0, 6))
            report = json.loads((destination / "observations.json").read_text())
            self.assertEqual(len(report["roots"]), 6)
            self.assertFalse(report["mode_qualification"])
            self.assertEqual(len(list(destination.glob("*/export.json"))), 6)

    def test_build_missing_export_and_timeout_stop_downstream(self):
        for failure in (None, subprocess.TimeoutExpired("synthetic", 180)):
            def fake(command, work, log, timeout):
                if failure:
                    raise failure
                return 1  # No export: e.g. a compiler error.
            with tempfile.TemporaryDirectory() as temporary:
                destination = Path(temporary) / "results"
                result, calls = self.run_collector(destination, fake)
                self.assertEqual((result, calls), (1, 1))
                report = json.loads((destination / "observations.json").read_text())
                self.assertTrue(all(r["execution_status"] == "NOT_RUN" for r in report["roots"][1:]))

    def test_stale_output_rejected_before_invocation(self):
        with tempfile.TemporaryDirectory() as temporary, patch("run.invoke") as invocation:
            with self.assertRaises(FileExistsError):
                collect("NEVER_EXECUTED_KANI", Path(temporary))
            invocation.assert_not_called()

    def test_outer_timeout_kills_and_reaps_the_process_group(self):
        with patch("run.subprocess.Popen") as launch, patch("run.os.killpg") as kill:
            process = launch.return_value.__enter__.return_value
            process.pid = 12345
            process.wait.side_effect = [subprocess.TimeoutExpired("synthetic", 180), -9]
            with self.assertRaises(subprocess.TimeoutExpired):
                invoke(["NEVER_EXECUTED_KANI"], Path("."), io.BytesIO(), 180)
            kill.assert_called_once_with(12345, signal.SIGKILL)
            self.assertTrue(launch.call_args.kwargs["start_new_session"])
            self.assertEqual(process.wait.call_count, 2)


if __name__ == "__main__":
    unittest.main()
