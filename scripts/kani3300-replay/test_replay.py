#!/usr/bin/env python3
"""Synthetic receipt/parser tests; these never invoke Kani or a build."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import replay
from replay import execute, load_request, parse_export, persist_then_postprocess, root_exit_code


class ExportTests(unittest.TestCase):
    def check_state(self, content, expected):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "export.json"
            if content is not None:
                p.write_bytes(content)
            got = parse_export(p, "expected::root")
            self.assertEqual(got["state"], expected)
            self.assertEqual(got["outcome"], "UNKNOWN")

    def test_parsed_success_claim_is_unvalidated_and_still_unknown(self):
        self.check_state(b'{"result":"SUCCESS","harness":"expected::root"}', "UNVALIDATED_JSON_OBJECT")

    def test_missing(self):
        self.check_state(None, "MISSING")

    def test_partial(self):
        self.check_state(b'{"harness":', "INVALID_OR_PARTIAL")

    def test_null(self):
        self.check_state(b'null', "NULL")

    def test_wrong_type(self):
        self.check_state(b'[]', "WRONG_TOP_LEVEL_TYPE")

    def test_wrong_source(self):
        self.check_state(b'{"selector":"other::root"}', "WRONG_SOURCE_OR_SELECTOR")

    def test_sort4_review_requires_success_and_all_covers(self):
        selector = "slice::sort::shared::smallsort::verify::helper_contracts::sort4_safety_u64"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "export.json"
            path.write_text(json.dumps({"harness": selector, "result": "SUCCESS"}))
            result = parse_export(path, selector)
            review = " ".join(result["review_required"])
            self.assertIn("zero failures", review)
            self.assertIn("all 3 covers reached, including return", review)
            self.assertNotIn("Unsupported", review)
            self.assertEqual(result["outcome"], "UNKNOWN")


    def test_malformed_success_exit_is_nonzero(self):
        for state in ("EMPTY", "INVALID_OR_PARTIAL", "NULL", "WRONG_TOP_LEVEL_TYPE",
                      "WRONG_SOURCE_OR_SELECTOR", "MISSING"):
            with self.subTest(state=state):
                receipt = {"original_exit_code": 0, "timed_out": False, "runner_error": None,
                           "export": {"state": state}, "postprocessing_state": "COMPLETE",
                           "rss": {"status": "OBSERVED_WAIT4_LINUX_RU_MAXRSS", "max_bytes": 1}}
                self.assertNotEqual(root_exit_code(receipt), 0)

    def test_original_child_failure_code_is_preserved(self):
        receipt = {"original_exit_code": 7, "timed_out": False, "runner_error": None,
                   "export": {"state": "INVALID_OR_PARTIAL"}, "postprocessing_state": "COMPLETE",
                   "rss": {"status": "OBSERVED_WAIT4_LINUX_RU_MAXRSS", "max_bytes": 1}}
        self.assertEqual(root_exit_code(receipt), 7)

    def test_unvalidated_object_with_zero_child_exit_remains_unknown(self):
        receipt = {"original_exit_code": 0, "timed_out": False, "runner_error": None,
                   "export": {"state": "UNVALIDATED_JSON_OBJECT"}, "postprocessing_state": "COMPLETE",
                   "rss": {"status": "OBSERVED_WAIT4_LINUX_RU_MAXRSS", "max_bytes": 1}}
        self.assertEqual(root_exit_code(receipt), 0)

    def test_unknown_rss_makes_receipt_nonzero(self):
        receipt = {"original_exit_code": 0, "timed_out": False, "runner_error": None,
                   "export": {"state": "UNVALIDATED_JSON_OBJECT"}, "postprocessing_state": "COMPLETE",
                   "rss": {"status": "UNKNOWN", "max_bytes": None}}
        self.assertEqual(root_exit_code(receipt), 1)


class RequestTests(unittest.TestCase):
    def test_actual_request_is_exact_six_row_preparation(self):
        req = load_request()
        self.assertEqual({r["id"] for r in req["roots"]},
                         {'sort4-closure-on', 'swap-if-less-closure-on', 'raw-negative-on', 'raw-legal-on', 'merge-profile-closure-on', 'merge-raw-closure-on'})
        self.assertTrue(all(r["status"] == "NOT_RUN" for r in req["roots"]))
        self.assertEqual(req["run_budget"]["max_invocations"], 6)
        self.assertEqual(req["run_budget"]["retry_policy"], "NONE")

    def load_modified(self, modify):
        req = json.loads(replay.REQUEST.read_text())
        modify(req)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "request.json"
            path.write_text(json.dumps(req))
            with mock.patch.object(replay, "REQUEST", path), mock.patch.object(
                    replay, "REQUEST_SHA", hashlib.sha256(path.read_bytes()).hexdigest()):
                return load_request()

    def test_rejects_extra_or_wrong_root(self):
        def mutate(req): req["roots"][0]["id"] = "unknown-row"
        with self.assertRaisesRegex(ValueError, "row allowlist"):
            self.load_modified(mutate)

    def test_rejects_retry_or_parallel_cap_expansion(self):
        for key, value in (("retry_policy", "ONE_RETRY"), ("max_parallel", 2), ("max_invocations", 4)):
            def mutate(req, key=key, value=value): req["run_budget"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "bounded preparation caps"):
                self.load_modified(mutate)

    def test_rejects_modified_request_hash(self):
        with mock.patch.object(replay, "REQUEST_SHA", "0" * 64):
            with self.assertRaisesRegex(ValueError, "request SHA-256"):
                load_request()

        def wrong_patch_metadata(req): req["test_patch_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "request test patch hash"):
            self.load_modified(wrong_patch_metadata)

        def wrong_file_hash(req): req["patched_file_sha256"][next(iter(req["patched_file_sha256"]))] = "0" * 64
        with self.assertRaisesRegex(ValueError, "request patched file hashes"):
            self.load_modified(wrong_file_hash)


class ExecutionTests(unittest.TestCase):
    def run_synthetic(self, code, timeout=1.0):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            import sys
            receipt = execute([sys.executable, "-c", code], Path.cwd(), {}, out, timeout)
            receipt["outcome"] = "UNKNOWN"
            receipt["runtime_proof_status"] = "NOT_RUN_UNTIL_REVIEWED"
            return receipt

    def test_success_exit_not_proof_credit(self):
        r = self.run_synthetic("print('synthetic success')")
        self.assertEqual(r["original_exit_code"], 0)
        self.assertFalse(r["timed_out"])
        self.assertEqual(r["rss_status"], "OBSERVED_WAIT4_LINUX_RU_MAXRSS")
        self.assertIsInstance(r["rss_max_bytes"], int)
        self.assertEqual(r["outcome"], "UNKNOWN")

    def test_failure_exit_preserved_not_arbitrary_negative_credit(self):
        r = self.run_synthetic("raise SystemExit(7)")
        self.assertEqual(r["original_exit_code"], 7)
        self.assertEqual(r["outcome"], "UNKNOWN")

    def test_timeout_recorded(self):
        r = self.run_synthetic("import time; time.sleep(10)", timeout=0.05)
        self.assertTrue(r["timed_out"])
        self.assertIsNotNone(r["original_exit_code"])
        self.assertEqual(r["outcome"], "UNKNOWN")

    def test_signal_preserved(self):
        r = self.run_synthetic("import os,signal; os.kill(os.getpid(), signal.SIGTERM)")
        self.assertEqual(r["signal"], 15)
        self.assertLess(r["original_exit_code"], 0)
        self.assertGreaterEqual(r["rss_max_bytes"], 0)


    def test_runner_exec_error_is_recorded_and_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            receipt = execute([str(out / "no-such-executable")], Path.cwd(), {}, out, 1.0)
            self.assertIsNone(receipt["original_exit_code"])
            self.assertTrue(receipt["runner_error"].startswith("runner_exec_or_wait_error:"))
            self.assertEqual(receipt["stdout_bytes"], 0)
            self.assertEqual(receipt["stderr_bytes"], 0)
            envelope = {**receipt, "export": {"state": "MISSING"},
                        "postprocessing_state": "INCOMPLETE"}
            self.assertNotEqual(root_exit_code(envelope), 0)

    def test_postprocessing_error_keeps_atomic_partial_execution_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "receipt.json"
            receipt = {"original_exit_code": 0, "timed_out": False, "signal": None,
                       "argv": ["synthetic"], "source_identity": {"sha": "bound"},
                       "outcome": "UNKNOWN", "postprocessing_state": "INCOMPLETE"}
            stage = {"name": "runtime-inventory"}

            def fail_postprocessing():
                before = json.loads(path.read_text())
                self.assertEqual(before["postprocessing_state"], "INCOMPLETE")
                self.assertEqual(before["original_exit_code"], 0)
                self.assertEqual(before["outcome"], "UNKNOWN")
                raise OSError("synthetic inventory failure")

            result = persist_then_postprocess(path, receipt, stage, fail_postprocessing)
            saved = json.loads(path.read_text())
            self.assertEqual(saved["original_exit_code"], 0)
            self.assertEqual(saved["argv"], ["synthetic"])
            self.assertEqual(saved["source_identity"], {"sha": "bound"})
            self.assertEqual(saved["outcome"], "UNKNOWN")
            self.assertEqual(saved["postprocessing_state"], "INCOMPLETE")
            self.assertEqual(saved["postprocessing_error"]["stage"], "runtime-inventory")
            self.assertEqual(result, saved)


class C2BindingTests(unittest.TestCase):
    def test_request_and_observer_have_frozen_sel1_c2_identity(self):
        req = load_request()
        self.assertEqual(replay.SEL1_C2_SHA, "14bc57fdb99960240c4944845a3d985c8af4dcf7")
        self.assertEqual(replay.SEL1_C2_TREE, "1efb6e4dfa69d346df8e23741d11839b1932403d")
        self.assertEqual(req["tool_export_sha"], replay.SEL1_C2_SHA)
        self.assertEqual(req["tool_export_tree"], replay.SEL1_C2_TREE)
        self.assertEqual(replay.SOURCE_BINDING.name, "sel1-c2-source-binding.json")
        self.assertEqual(req["proposal"]["runner"], "ubuntu-24.04")

    def test_exact_rows_targets_flags_and_unwinds(self):
        rows = load_request()["roots"]
        self.assertEqual([r["source_unwind"] for r in rows], [34, 34, 16, 8, 16, 16])
        self.assertEqual([r["expected_mode"] for r in rows],
                         ["Check(bidirectional_merge)", "Check(merge_profile_closure_u8)", "Check(sort4_stable)", "Check(swap_if_less)", "Original(sort4_stable)", "Original(sort4_stable)"])
        self.assertEqual([r["expected_result"] for r in rows], ["SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS", "SUCCESS", "FAILURE"])
        for row in rows:
            self.assertEqual(row["argv"][0], "<EXACT_SEL1_C2_KANI_BINARY>")
            self.assertEqual(row["argv"][row["argv"].index("--harness") + 1], row["selector"])
            self.assertTrue(row["uninit"])
            self.assertIn("uninit-checks", row["argv"])
            self.assertIn("--no-assert-contracts", row["argv"])
            self.assertEqual(row["environment"]["RUSTFLAGS"], "--cfg kani_smallsort_controls")

    def test_source_binding_consistency_without_executing_tools(self):
        binding = json.loads(replay.SOURCE_BINDING.read_text())
        self.assertEqual(binding["export_sha"], replay.SEL1_C2_SHA)
        self.assertEqual(binding["export_tree"], replay.SEL1_C2_TREE)
        self.assertEqual(set(binding["subtrees"]),
                         {"kani-compiler", "kani-driver", "library", "tests", "tools", "scripts", "docs"})
        self.assertIn("scripts/setup/ubuntu-24.04", binding["files"])
        self.assertIn("scripts/setup/ubuntu/install_deps.sh", binding["files"])

    def test_verify_source_rejects_wrong_binding_head_tree_and_dirty(self):
        binding = json.loads(replay.SOURCE_BINDING.read_text())
        for case in ("binding", "head", "tree", "dirty"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as td:
                altered = json.loads(json.dumps(binding))
                altered["state"] = "SEL1_C2_FROZEN"
                if case == "binding":
                    altered["export_sha"] = "1658f4cadfa83139e41180ce3865e23f79d889aa"
                p = Path(td) / "binding.json"
                p.write_text(json.dumps(altered))

                def fake_git(repo, *args):
                    if args == ("cat-file", "-t", replay.SEL1_C2_SHA): return "commit"
                    if args == ("rev-parse", replay.SEL1_C2_SHA + "^{tree}"):
                        return "wrong" if case == "tree" else replay.SEL1_C2_TREE
                    if args == ("rev-parse", "HEAD"):
                        return "wrong" if case == "head" else replay.SEL1_C2_SHA
                    if args == ("status", "--porcelain"): return " M source" if case == "dirty" else ""
                    self.fail("unexpected git invocation")

                with mock.patch.object(replay, "SOURCE_BINDING", p), mock.patch.object(replay, "git", side_effect=fake_git):
                    with self.assertRaises(ValueError): replay.verify_source(Path(td))

    def test_not_run_and_post_run_source_failure_cannot_pass(self):
        base = {"original_exit_code": 0, "timed_out": False, "runner_error": None,
                "export": {"state": "UNVALIDATED_JSON_OBJECT"}, "postprocessing_state": "COMPLETE",
                "rss": {"status": "OBSERVED_WAIT4_LINUX_RU_MAXRSS", "max_bytes": 1}}
        self.assertNotEqual(root_exit_code({**base, "original_exit_code": None, "runtime_proof_status": "NOT_RUN"}), 0)
        failed = {**base, "post_run_validation": {"sel1_c2_source_valid": {"valid": False}}}
        self.assertNotEqual(root_exit_code(failed), 0)
        self.assertEqual(root_exit_code({**failed, "original_exit_code": 7}), 7)

    def test_workflow_is_serial_six_rows_with_preflight_and_run4_recipe(self):
        workflow = replay.HERE.parent.parent / ".github/workflows/kani3300-replay.yml"
        if not workflow.exists(): self.skipTest("workflow checked in full export validation")
        text = workflow.read_text()
        for required in ("uninit-ci/sel1-c2-replay-*", "runs-on: ubuntu-24.04", "max-parallel: 1",
                         "timeout-minutes: 60", "uses: ./export/.github/actions/setup", "kani_dir: export",
                         "--destination", "https://github.com/Tiramisu-Cake/verify-rust-std.git"):
            self.assertIn(required, text)
        self.assertLess(text.index("Python-only wrapper preflight"), text.index("Setup pinned Kani dependencies"))
        self.assertIn("  push:", text)
        self.assertNotIn("workflow_dispatch", text)

    def test_run_root_substitutes_exact_c2_binary_and_preserves_exit(self):
        import subprocess
        req = load_request()
        original_hash = replay.sha256
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            binary = base / "kani"
            binary.write_text("mock only; must never execute")
            binary.chmod(0o755)
            status = b"".join(b" M " + p.encode() + b"\0" for p in replay.PATCHED_FILE_HASHES)
            std = base / "std"
            for rel in replay.PATCHED_FILE_HASHES:
                path = std / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("mock source bytes")

            def fake_hash(path):
                if path.is_relative_to(std): return replay.PATCHED_FILE_HASHES[path.relative_to(std).as_posix()]
                return original_hash(path)

            cases = [(row, None) for row in req["roots"]] + [
                (req["roots"][0], field) for field in ("HEAD", "HEAD^{tree}", "HEAD:library")]
            for case_index, (row, drift) in enumerate(cases):
                head_calls = 0

                def fake_git(repo, *args):
                    nonlocal head_calls
                    if args == ("rev-parse", "HEAD"):
                        head_calls += 1
                    post_run = head_calls > 1
                    if post_run and args == ("rev-parse", drift):
                        return "0" * 40
                    return {("rev-parse", "HEAD"): replay.STD_SHA,
                            ("rev-parse", "HEAD^{tree}"): replay.STD_COMMIT_TREE,
                            ("rev-parse", "HEAD:library"): replay.STD_TREE}[args]

                with self.subTest(row=row["id"], post_run_std_drift=drift):
                    out = base / (row["id"] + ("-drift-" + str(case_index) if drift else ""))
                    execution = {"original_exit_code": 7, "timed_out": False, "runner_error": None,
                                 "signal": None, "rss_max_bytes": 100,
                                 "rss_status": "OBSERVED_WAIT4_LINUX_RU_MAXRSS"}
                    with mock.patch.object(replay, "verify_source", return_value={"sel1_c2_sha": replay.SEL1_C2_SHA}), \
                         mock.patch.object(replay, "git", side_effect=fake_git), \
                         mock.patch.object(replay.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=status)), \
                         mock.patch.object(replay, "sha256", side_effect=fake_hash), \
                         mock.patch.object(replay, "runtime_inventory", return_value={"mock_only": True}), \
                         mock.patch.object(replay, "execute", return_value=execution) as execute_mock:
                        receipt = replay.run_root(base, std, row["id"], binary, out)
                    expected = [str(binary) if x == "<EXACT_SEL1_C2_KANI_BINARY>" else x.replace("<OUTPUT_ROOT>", str(base)) for x in row["argv"]]
                    self.assertEqual(execute_mock.call_args.args[0], expected)
                    self.assertEqual(execute_mock.call_args.args[1], std)
                    self.assertEqual(receipt["argv"], expected)
                    self.assertEqual(receipt["sel1_c2_sha"], replay.SEL1_C2_SHA)
                    self.assertEqual(receipt["original_exit_code"], 7)
                    self.assertEqual(receipt["outcome"], "UNKNOWN")
                    self.assertEqual(root_exit_code(receipt), 7)
                    self.assertEqual(receipt["post_run_validation"]["std_test_only_overlay_valid"], drift is None)
                    self.assertEqual(json.loads((out / "receipt.json").read_text()), receipt)


class PreparationGuardTests(unittest.TestCase):
    def test_unbound_source_is_rejected_before_git_or_execution(self):
        binding = json.loads(replay.SOURCE_BINDING.read_text())
        binding["state"] = "PENDING_FREEZE"
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "binding.json"
            path.write_text(json.dumps(binding))
            with mock.patch.object(replay, "SOURCE_BINDING", path), mock.patch.object(replay, "git") as git_mock:
                with self.assertRaisesRegex(ValueError, "PENDING_FREEZE"):
                    replay.verify_source(Path("/must/not/run"))
                git_mock.assert_not_called()

    def test_duplicate_selector_rejected_even_with_valid_request_checksum(self):
        req = json.loads(replay.REQUEST.read_text())
        req["roots"][1]["selector"] = req["roots"][0]["selector"]
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "request.json"
            p.write_text(json.dumps(req))
            with mock.patch.object(replay, "REQUEST", p), mock.patch.object(
                    replay, "REQUEST_SHA", hashlib.sha256(p.read_bytes()).hexdigest()):
                with self.assertRaisesRegex(ValueError, "duplicate exact selector"):
                    replay.load_request()


if __name__ == "__main__":
    unittest.main()
