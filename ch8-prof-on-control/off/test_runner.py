# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
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
             "variant": "production", "cfg": [], "unwind": 4, "expected": "SUCCESS",
             "failure_description": "expected semantic failure", "required_cover_count": 2,
             "timeout_seconds": 30}
    value.update(updates)
    return value


def export(*, selector="slice::sort::root", mode="pfc", schema="0.1.0", state="COMPLETE",
           verdict="SUCCESS", failures=None, named=None):
    target = "slice::sort::body"
    wrapper = "_RNvNtCs1kani4sort6modify"
    kind = {"ProofForContract": {"target_fn": target}} if mode == "pfc" else "Proof"
    failures = failures or []
    named = named or []
    return {"schema_version": schema, "run_state": state, "kani_commit": runner.TOOL_SHA,
            "kani_commit_dirty": False, "target": runner.TARGET, "harness_timeout_s": 600,
            "tools": {"kani": "kani synthetic", "rustc": "rustc synthetic", "cbmc": "CBMC synthetic"},
            "configuration": {"checks": {"assert_contracts": False, "memory_safety": True,
                                            "overflow": True, "unwinding": True, "undefined_function": True,
                                            "assertion_reach_checks": True, "prove_safety_only": False,
                                            "ignore_global_asm": False, "extra_pointer_checks": False},
                              "cbmc_args": ["--object-bits", "12"], "coverage_enabled": False},
            "enabled_unstable_features": sorted(set(runner.UNSTABLE) | {"export-json"}),
            "harness_selection": {"requested_filters": [selector], "exact": True,
                                  "unmatched_filters": [], "matched_count": 1},
            "harnesses": [{"name": selector, "attributes": {"kind": kind},
                           "is_automatically_generated": False,
                           "contract": {"requires": [], "ensures": [], "contracted_function_name": wrapper},
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
                "budgets": {"phase_seconds": runner.PHASE_SECONDS, "rss_kib": runner.RSS_CAP_KIB,
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
        argv = runner.build_argv(Path("/std"), Path("/tool"), "x::root", 3, Path("/tmp/e.json"))
        self.assertIn("--no-assert-contracts", argv)
        self.assertNotIn("--default-unwind", argv)
        self.assertEqual(argv[-3:], ["--cbmc-args", "--object-bits", "12"])
        self.assertEqual(argv[argv.index("--export-json") + 1], "/tmp/e.json")
        self.assertEqual(argv[argv.index("--harness-timeout") + 1], "600s")
        self.assertEqual(argv[argv.index("--target-dir") + 1], "/tmp/target")
        self.assertIn("/std/library", argv)

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


class ExportTests(unittest.TestCase):
    def parse(self, value, selected_row=None, contract_binding=None):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "export.json"
            p.write_text(json.dumps(value))
            return runner.parse_export(p, selected_row or row(), contract_binding=contract_binding)

    def test_success_and_named_negative(self):
        binding = {row()["selector"]: "slice::sort::body"}
        accepted = self.parse(export(), contract_binding=binding)
        self.assertEqual(accepted["outcome"], "EXPECTED")
        self.assertEqual(accepted["export_target_fn"], "slice::sort::body")
        self.assertEqual(accepted["reported_contracted_function_name"], "_RNvNtCs1kani4sort6modify")
        self.assertNotEqual(accepted["reported_contracted_function_name"], accepted["export_target_fn"])
        negative_row = row(expected="DETECTED", failure_description="S1 semantic check")
        negative = export(verdict="FAILURE", failures=["property-7"], named=[
            {"id": "property-7", "description": "S1 semantic check failed"}])
        self.assertEqual(self.parse(negative, negative_row,
                                   {negative_row["selector"]: "slice::sort::body"})["outcome"], "EXPECTED")
        extra = export(verdict="FAILURE", failures=["property-7", "other"], named=[
            {"id": "property-7", "description": "S1 semantic check failed"}])
        self.assertEqual(self.parse(extra, negative_row,
                                   {negative_row["selector"]: "slice::sort::body"})["outcome"], "UNKNOWN")

    def test_wrong_root_mode_guard_and_export_drift(self):
        binding = {row()["selector"]: "slice::sort::body"}
        self.assertEqual(self.parse(export(selector="other::root"), contract_binding=binding)["state"], "WRONG_ROOT_OR_SELECTION")
        self.assertEqual(self.parse(export(mode="ordinary"), contract_binding=binding)["state"], "WRONG_MODE")
        self.assertEqual(self.parse(export(schema="0.2.0"), contract_binding=binding)["state"], "INCOMPLETE_OR_SCHEMA_DRIFT")
        self.assertEqual(self.parse(export(state="PARTIAL"), contract_binding=binding)["state"], "INCOMPLETE_OR_SCHEMA_DRIFT")
        bad = export(); bad["harnesses"][0]["checks"]["unreachable"] = ["x"]
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "INCOMPLETE_CHECK_INVENTORY")
        bad = export(); bad["harnesses"][0]["resolved_unwind"] = 99
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "WRONG_UNWIND")
        bad = export(); bad["harnesses"][0]["attributes"]["kind"]["ProofForContract"]["target_fn"] = "other"
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "CONTRACT_TARGET_BINDING_MISMATCH")
        bad = export(); bad["harnesses"][0]["contract"]["contracted_function_name"] = ""
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "CONTRACT_TARGET_BINDING_MISMATCH")
        bad = export(); del bad["harnesses"][0]["contract"]["contracted_function_name"]
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "CONTRACT_TARGET_BINDING_MISMATCH")
        bad = export(); bad["configuration"]["checks"]["assert_contracts"] = True
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "WRONG_CONFIGURATION")

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


if __name__ == "__main__":
    unittest.main()
