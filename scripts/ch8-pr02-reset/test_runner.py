#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Synthetic runner-result error paths; does not invoke Kani or simulate proof."""
import tempfile
import unittest
from pathlib import Path

from run_arm_b import evaluate_case


CASE = {"name": "reassemble_ptr_fragments_in_static",
        "source_file": "issue-4854-autoharness.rs", "automatic": True}
CONTEXT = {"stage": "B", "source_sha": "src", "expected_source_sha": "src",
           "source_tree": "tree", "expected_source_tree": "tree",
           "target": "x86_64-unknown-linux-gnu",
           "expected_target": "x86_64-unknown-linux-gnu"}


def valid_export():
    return {
        "outcome": {"kind": "COMPLETED"}, "run_state": "COMPLETE",
        "target": "x86_64-unknown-linux-gnu",
        "harness_selection": {"matched_count": 1},
        "harnesses": [{"name": CASE["name"], "file": CASE["source_file"],
                       "is_automatically_generated": True,
                       "outcome": {"kind": "COMPLETED", "verdict": "SUCCESS"}}],
        "summary": {"total": 1, "successful": 1, "failed": 0},
    }


class RunnerResultTests(unittest.TestCase):
    def evaluate(self, exit_code=0, payload=None, context=None):
        with tempfile.TemporaryDirectory(prefix="ch8-runner-test-") as tmp:
            export = Path(tmp) / "result.json"
            if payload is not None:
                import json
                export.write_text(json.dumps(payload))
            return evaluate_case(exit_code,
                "VERIFICATION:- SUCCESSFUL\nComplete - 1 successfully verified functions, 0 failures, 1 total.\n",
                export, CASE, context or CONTEXT)

    def test_completed_success(self):
        self.assertTrue(self.evaluate(payload=valid_export())[0])

    def test_nonzero_and_timeout_fail_closed(self):
        self.assertFalse(self.evaluate(exit_code=1, payload=valid_export())[0])
        self.assertFalse(self.evaluate(exit_code=None, payload=valid_export())[0])

    def test_missing_null_and_malformed_export_fail_closed(self):
        self.assertFalse(self.evaluate()[0])
        self.assertFalse(self.evaluate(payload=None)[0])
        with tempfile.TemporaryDirectory(prefix="ch8-runner-null-") as tmp:
            export = Path(tmp) / "result.json"
            export.write_text("null")
            ok, reason, _ = evaluate_case(0, "", export, CASE, CONTEXT)
            self.assertFalse(ok)
            self.assertIn("export root", reason)
            export.write_text("{")
            ok, reason, _ = evaluate_case(0, "", export, CASE, CONTEXT)
            self.assertFalse(ok)
            self.assertIn("invalid export", reason)

    def test_partial_not_run_and_wrong_field_types_fail_closed(self):
        for mutate in (
            lambda d: d.update(run_state="PARTIAL"),
            lambda d: d.update(outcome={"kind": "NOT_RUN"}),
            lambda d: d.update(harnesses="one"),
            lambda d: d.update(summary=None),
        ):
            payload = valid_export()
            mutate(payload)
            self.assertFalse(self.evaluate(payload=payload)[0])

    def test_source_stage_target_name_file_and_kind_mismatches_fail_closed(self):
        for key, value in (("source_sha", "wrong"), ("source_tree", "wrong"),
                           ("stage", "A"), ("target", "aarch64-unknown-linux-gnu")):
            context = dict(CONTEXT)
            context[key] = value
            self.assertFalse(self.evaluate(payload=valid_export(), context=context)[0])
        for key, value in (("name", "wrong"), ("file", "other.rs"),
                           ("is_automatically_generated", False),
                           ("outcome", {"kind": "COMPLETED", "verdict": "FAILURE"})):
            payload = valid_export()
            payload["harnesses"][0][key] = value
            self.assertFalse(self.evaluate(payload=payload)[0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
