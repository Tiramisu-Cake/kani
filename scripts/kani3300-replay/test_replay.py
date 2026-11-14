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

    def test_explicit_not_run_is_invalid_for_zero_exit(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "export.json"
            p.write_text('{"status":"NOT_RUN"}')
            export = parse_export(p, "expected::root")
        self.assertEqual(export["state"], "EXPLICIT_NOT_RUN")
        receipt = {"original_exit_code": 0, "timed_out": False, "runner_error": None,
                   "export": export, "postprocessing_state": "COMPLETE",
                   "rss": {"status": "OBSERVED_WAIT4_LINUX_RU_MAXRSS", "max_bytes": 1}}
        self.assertNotEqual(root_exit_code(receipt), 0)


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
                         {"sort4-closure-on", "swap-if-less-closure-on", "raw-legal-on",
                          "raw-negative-on", "merge-raw-closure-on", "merge-profile-closure-on"})
        self.assertTrue(all(r["status"] == "NOT_RUN" for r in req["roots"]))
        self.assertTrue(all(r["state"] == "NOT_RUN" for r in req["roots"]))
        self.assertEqual(req["run_budget"]["max_invocations"], 6)
        self.assertEqual(req["run_budget"]["aggregate_job_envelope_seconds"], 21600)
        self.assertEqual(req["run_budget"]["retry_policy"], "NONE")
        self.assertEqual(req["tool_export_sha"], replay.TOOL_SHA)
        self.assertEqual(req["test_overlay_commit"], replay.STD_OVERLAY_SHA)

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
        def mutate(req): req["roots"][0]["id"] = "raw-negative-on-extra"
        with self.assertRaisesRegex(ValueError, "row allowlist"):
            self.load_modified(mutate)

    def test_rejects_retry_or_parallel_cap_expansion(self):
        for key, value in (("retry_policy", "ONE_RETRY"), ("max_parallel", 2), ("max_invocations", 7)):
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

    def test_rejects_source_stage_target_and_selector_argv_mismatches(self):
        for field, value, message in (
                ("expected_mode", "Original(sort4_stable)", "source-stage-target"),
                ("source_unwind", 17, "source-stage-target"),
                ("selector", "slice::wrong::harness", "source-stage-target")):
            def mutate(req, field=field, value=value): req["roots"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, message):
                self.load_modified(mutate)

        def mutate_argv(req): req["roots"][0]["argv"].remove("--exact")
        with self.assertRaisesRegex(ValueError, "exact argv/environment"):
            self.load_modified(mutate_argv)

    def test_rejects_weakened_sort4_oracle_and_changed_flags(self):
        def weaken_oracle(req): req["roots"][0]["expected_failed_checks"] = 1
        with self.assertRaisesRegex(ValueError, "source-stage-target"):
            self.load_modified(weaken_oracle)

        def weaken_flags(req): req["flags"]["experimental_valid_value"] = True
        with self.assertRaisesRegex(ValueError, "checker flags"):
            self.load_modified(weaken_flags)

    def test_rejects_std_overlay_binding_mismatch(self):
        def mutate(req): req["test_only_library_tree"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "std overlay identity"):
            self.load_modified(mutate)

    def test_request_binds_exact_five_patched_files(self):
        req = load_request()
        self.assertEqual(len(req["patched_file_sha256"]), 5)
        self.assertEqual(set(req["patched_file_sha256"]), set(replay.PATCHED_FILE_HASHES))


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

    def test_post_run_source_validation_failure_rejects_zero_but_preserves_positive_exit(self):
        base = {"timed_out": False, "runner_error": None,
                "export": {"state": "UNVALIDATED_JSON_OBJECT"},
                "postprocessing_state": "COMPLETE",
                "rss": {"status": "OBSERVED_WAIT4_LINUX_RU_MAXRSS", "max_bytes": 1},
                "post_run_validation": {"tool_source_valid": {"valid": False},
                                        "std_test_only_overlay_valid": True}}
        self.assertNotEqual(root_exit_code({**base, "original_exit_code": 0}), 0)
        self.assertEqual(root_exit_code({**base, "original_exit_code": 7}), 7)


class OverlayWorkflowTests(unittest.TestCase):
    def test_workflow_keeps_six_serial_rows_and_exact_prepare_invocation(self):
        workflow = (replay.HERE.parents[1] / ".github/workflows/kani3300-replay.yml").read_text()
        req = load_request()
        self.assertIn("branches: ['ci/kani3300-sel1-replay-w15']", workflow)
        self.assertIn("max-parallel: 1", workflow)
        self.assertLess(workflow.index("python3 -m unittest -v test_replay.py"),
                        workflow.index("Read exact export revision"))
        self.assertLess(workflow.index("python3 -m unittest -v test_replay.py"),
                        workflow.index("Build this exact SEL1 checkout"))
        self.assertEqual(workflow.count("          - "), 6)
        for row in req["roots"]:
            self.assertIn(f"          - {row['id']}", workflow)
        self.assertEqual(req["run_budget"]["retry_policy"], "NONE")
        self.assertIn("--repo https://github.com/Tiramisu-Cake/verify-rust-std.git", workflow)
        self.assertIn("--destination \"$RUNNER_TEMP/kani3300-std\"", workflow)
        self.assertIn('"submodule", "update", "--init", "--depth", "1"',
                      (replay.HERE / "replay.py").read_text())
        self.assertNotIn("retry", workflow.lower())

    def test_prepare_std_preserves_pinned_clone_checkout_patch_and_submodules(self):
        req = load_request()
        paths = sorted(replay.PATCHED_FILE_HASHES)
        with tempfile.TemporaryDirectory() as td:
            destination = Path(td) / "std"
            calls = []
            status = b"".join(b" M " + p.encode() + b"\0" for p in paths)

            def fake_run(argv, **kwargs):
                calls.append(argv)
                if "status" in argv:
                    return mock.Mock(stdout=status)
                return mock.Mock(stdout=b"")

            def fake_git(repo, *args):
                if args == ("rev-parse", "HEAD^{tree}"):
                    return replay.STD_COMMIT_TREE
                if args == ("rev-parse", "HEAD:library"):
                    return replay.STD_TREE
                return ""

            def fake_sha(path):
                path = Path(path)
                if path == replay.PATCH:
                    return replay.PATCH_SHA
                return replay.PATCHED_FILE_HASHES[path.relative_to(destination).as_posix()]

            with mock.patch.object(replay.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(replay, "git", side_effect=fake_git), \
                    mock.patch.object(replay, "sha256", side_effect=fake_sha):
                result = replay.prepare_std("https://example.invalid/std.git", destination)

        self.assertEqual(result["status"], "PREPARED_NOT_RUN")
        self.assertEqual(result["changed_paths"], paths)
        self.assertIn(["git", "clone", "--no-hardlinks", "https://example.invalid/std.git",
                       str(destination)], calls)
        self.assertIn(["git", "-C", str(destination), "submodule", "update", "--init",
                       "--depth", "1"], calls)
        self.assertIn(["git", "-C", str(destination), "apply", "--check", str(replay.PATCH)], calls)

    def test_run_root_substitutes_only_output_binary_and_preserves_receipt_exit(self):
        req = load_request()
        root = "raw-negative-on"
        row = next(r for r in req["roots"] if r["id"] == root)
        patched_paths = sorted(replay.PATCHED_FILE_HASHES)
        status = b"".join(b" M " + p.encode() + b"\0" for p in patched_paths)
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo, std, out = base / "repo", base / "std", base / "out" / root
            repo.mkdir(); std.mkdir()
            binary = base / "kani"
            binary.write_text("synthetic executable")
            binary.chmod(0o755)
            captured = {}

            def fake_execute(argv, cwd, env, out_dir, timeout=replay.ROOT_CAP_SECONDS):
                captured.update(argv=argv, cwd=cwd, env=env, out=out_dir, timeout=timeout)
                (out_dir / "export.json").write_text('{"status":"NOT_RUN"}')
                return {"started_unix": 1, "original_exit_code": 7, "timed_out": False,
                        "runner_error": None, "signal": None, "rss_max_bytes": 100,
                        "rss_status": "OBSERVED_WAIT4_LINUX_RU_MAXRSS", "elapsed_seconds": 1,
                        "stdout_sha256": "0" * 64, "stdout_bytes": 0,
                        "stderr_sha256": "0" * 64, "stderr_bytes": 0}

            def fake_sha(path):
                path = Path(path)
                if path == replay.REQUEST:
                    return replay.REQUEST_SHA
                if path == replay.PATCH:
                    return replay.PATCH_SHA
                return replay.PATCHED_FILE_HASHES[path.relative_to(std).as_posix()]

            with mock.patch.object(replay, "verify_source", return_value={"proof_status": "NOT_RUN"}), \
                    mock.patch.object(replay, "git", side_effect=[replay.STD_SHA, replay.STD_TREE]), \
                    mock.patch.object(replay.subprocess, "run", return_value=mock.Mock(stdout=status)), \
                    mock.patch.object(replay, "sha256", side_effect=fake_sha), \
                    mock.patch.object(replay, "execute", side_effect=fake_execute), \
                    mock.patch.object(replay, "runtime_inventory", return_value={"synthetic": True}):
                receipt = replay.run_root(repo, std, root, binary, out)

        expected_argv = [str(binary) if x == "<EXACT_SEL1_KANI_BINARY>" else
                         x.replace("<OUTPUT_ROOT>", str(out.parent)) for x in row["argv"]]
        self.assertEqual(captured["argv"], expected_argv)
        self.assertEqual(captured["cwd"], std)
        self.assertEqual(receipt["original_exit_code"], 7)
        self.assertEqual(receipt["export"]["state"], "EXPLICIT_NOT_RUN")
        self.assertEqual(receipt["runtime_proof_status"], "NOT_RUN_UNTIL_REVIEWED")
        self.assertEqual(root_exit_code(receipt), 7)


if __name__ == "__main__":
    unittest.main()
