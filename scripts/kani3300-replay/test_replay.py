#!/usr/bin/env python3
"""Synthetic receipt/parser tests; these never invoke Kani or a build."""

import json
from pathlib import Path
import tempfile
import unittest

from replay import execute, parse_export, persist_then_postprocess, root_exit_code


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

    def test_malformed_success_exit_is_nonzero(self):
        for state in ("EMPTY", "INVALID_OR_PARTIAL", "NULL", "WRONG_TOP_LEVEL_TYPE",
                      "WRONG_SOURCE_OR_SELECTOR", "MISSING"):
            with self.subTest(state=state):
                receipt = {"original_exit_code": 0, "timed_out": False, "runner_error": None,
                           "export": {"state": state}, "postprocessing_state": "COMPLETE"}
                self.assertNotEqual(root_exit_code(receipt), 0)

    def test_original_child_failure_code_is_preserved(self):
        receipt = {"original_exit_code": 7, "timed_out": False, "runner_error": None,
                   "export": {"state": "INVALID_OR_PARTIAL"}, "postprocessing_state": "COMPLETE"}
        self.assertEqual(root_exit_code(receipt), 7)

    def test_unvalidated_object_with_zero_child_exit_remains_unknown(self):
        receipt = {"original_exit_code": 0, "timed_out": False, "runner_error": None,
                   "export": {"state": "UNVALIDATED_JSON_OBJECT"}, "postprocessing_state": "COMPLETE"}
        self.assertEqual(root_exit_code(receipt), 0)


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


if __name__ == "__main__":
    unittest.main()
