#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Synthetic tests for lifecycle source binding, failure receipts, and matrix aggregation."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lifecycle


def git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout.decode().strip()


def init_repo(path):
    path.mkdir()
    git(path, "init", "-q")
    git(path, "config", "user.name", "Synthetic")
    git(path, "config", "user.email", "synthetic@example.invalid")
    (path / "tracked.txt").write_text("bound source\n")
    git(path, "add", "tracked.txt")
    git(path, "commit", "-qm", "source")
    return path


def binding_for(root):
    data = (root / "tracked.txt").read_bytes()
    return {"export_sha": git(root, "rev-parse", "HEAD"),
            "export_tree": git(root, "rev-parse", "HEAD^{tree}"),
            "files": {"tracked.txt": hashlib.sha256(data).hexdigest()},
            "subtrees": {}, "submodule_pins": {}, "symlinks": {}}


def complete_receipt(row, run="run-123", overlay="overlay-abc"):
    binding = json.loads((HERE / "binding.json").read_text())
    stages = {}
    ids = []
    for stage in binding["stages"]:
        sid = stage["id"]
        ids.append(sid)
        counts = [{"line": 1, "counts": {"passed": 1, "failed": 0, "ignored": 0, "filtered": 0}}] if stage["counts_required"] else []
        stages[sid] = {"status": "EXIT_ZERO", "exit": 0, "counts_required": stage["counts_required"],
                       "command": stage["command"], "mode": stage["mode"], "source_line": stage["line"], "counts": counts}
    return {"schema": "kani3300-gatea-observer-v1", "status": "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW",
            "script_exit": 0, "termination": None,
            "event_stream": {"complete": True, "truncated": False, "sha256": "a" * 64, "bytes": 1},
            "stages": stages, "stage_order_seen": ids, "problems": [],
            "matrix_os": row, "run_id": run, "run_attempt": "1", "overlay_sha": overlay,
            "export_sha": binding["export_sha"], "export_tree": binding["export_tree"],
            "runtime_inventory": {"status": "COLLECTED", "required_missing": [],
                                  "tools": {name: {"sha256": "b" * 64, "version": ["synthetic version"]}
                                            for name in ("kani-compiler", "kani-driver", "cbmc", "goto-instrument", "kissat", "cvc5", "z3", "rustc")}},
            "lifecycle": {"source_identity_ok": True,
                          "statuses": {"setup": "success", "preflight": "success", "observer": "success", "regression": "success"}}}


class LifecycleTests(unittest.TestCase):
    def test_wrong_sha_tree_and_file_hash_are_explicit(self):
        with tempfile.TemporaryDirectory() as td:
            root = init_repo(Path(td) / "export")
            binding = binding_for(root)
            binding["export_sha"] = "0" * 40
            binding["export_tree"] = "1" * 40
            binding["files"]["tracked.txt"] = "2" * 64
            result = lifecycle._check_source(root, binding, "pre-setup")
            self.assertFalse(result["ok"])
            self.assertEqual(len(result["mismatches"]), 3)

    def test_untracked_and_worktree_changes_are_not_clean(self):
        with tempfile.TemporaryDirectory() as td:
            root = init_repo(Path(td) / "export")
            binding = binding_for(root)
            (root / "tracked.txt").write_text("changed\n")
            (root / "new.txt").write_text("untracked\n")
            result = lifecycle._check_source(root, binding, "post-setup")
            self.assertFalse(result["clean"])
            self.assertEqual(len(result["status"]), 2)

    def test_unbound_tracked_edit_is_not_clean(self):
        with tempfile.TemporaryDirectory() as td:
            root = init_repo(Path(td) / "export")
            (root / "other.txt").write_text("stable\n")
            git(root, "add", "other.txt")
            git(root, "commit", "-qm", "add unbound source file")
            binding = binding_for(root)
            (root / "other.txt").write_text("edited\n")
            result = lifecycle._check_source(root, binding, "post-setup")
            self.assertFalse(result["ok"])
            self.assertIn("source worktree/index is not clean (includes untracked files)", result["mismatches"])

    def test_setup_only_failure_creates_fallback_incomplete_receipt(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            binding_path = root / "binding.json"
            binding_path.write_text(json.dumps({"export_sha": "x", "export_tree": "y", "files": {}, "subtrees": {}, "submodule_pins": {}}))
            output = root / "artifacts" / "ubuntu-24.04"
            lifecycle.main(["init", "--binding", str(binding_path), "--output", str(output),
                            "--platform", "ubuntu-24.04", "--run-id", "r", "--run-attempt", "1", "--started-epoch", "1"])
            status = lifecycle.main(["finalize", "--binding", str(binding_path), "--output", str(output),
                                     "--setup-status", "failure", "--preflight-status", "skipped",
                                     "--observer-status", "skipped", "--regression-status", "skipped"])
            receipt = json.loads((output / "receipt.json").read_text())
            self.assertEqual(status, 1)
            self.assertEqual(receipt["status"], "NOT_RUN")
            self.assertIn("lifecycle", receipt)
            self.assertEqual(receipt["lifecycle"]["statuses"]["setup"], "failure")

    def test_budget_applies_job_deadline_and_reserve(self):
        with tempfile.TemporaryDirectory() as td:
            output = Path(td)
            (output / "lifecycle.json").write_text(json.dumps({"job_started_epoch": 1000}))
            # 360 minutes minus 100 seconds elapsed and 600 seconds reserve.
            code = lifecycle.main(["budget", "--output", str(output), "--now-epoch", "1100"])
            self.assertEqual(code, 0)
            state = json.loads((output / "lifecycle.json").read_text())
            self.assertEqual(state["budget"]["allowed_seconds"], 20400)

    def test_missing_matrix_row_is_failed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "one").mkdir()
            (root / "one" / "receipt.json").write_text(json.dumps(complete_receipt("ubuntu-24.04")))
            (root / "two").mkdir()
            (root / "two" / "receipt.json").write_text(json.dumps(complete_receipt("ubuntu-24.04-arm")))
            out = root / "summary.json"
            code = lifecycle.main(["aggregate", "--receipts-dir", str(root), "--output", str(out), "--overlay-sha", "overlay-abc", "--matrix-result", "success"])
            result = json.loads(out.read_text())
            self.assertEqual(code, 1)
            self.assertEqual(result["rows"]["macos-15"]["status"], "MISSING")

    def test_failed_row_not_masked_by_two_complete_rows(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for row in lifecycle.EXPECTED_ROWS:
                folder = root / row
                folder.mkdir()
                receipt = complete_receipt(row)
                if row == "macos-15":
                    receipt["status"] = "INCOMPLETE_OR_FAILED"
                    receipt["script_exit"] = 1
                (folder / "receipt.json").write_text(json.dumps(receipt))
            out = root / "summary.json"
            code = lifecycle.main(["aggregate", "--receipts-dir", str(root), "--output", str(out), "--overlay-sha", "overlay-abc", "--matrix-result", "success"])
            result = json.loads(out.read_text())
            self.assertEqual(code, 1)
            self.assertFalse(result["rows"]["macos-15"]["ok"])
            self.assertEqual(sum(1 for v in result["rows"].values() if v["ok"]), 2)

    def test_status_string_without_complete_stage_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for row in lifecycle.EXPECTED_ROWS:
                folder = root / row
                folder.mkdir()
                receipt = complete_receipt(row)
                receipt["stages"] = {}
                receipt["stage_order_seen"] = []
                (folder / "receipt.json").write_text(json.dumps(receipt))
            out = root / "summary.json"
            code = lifecycle.main(["aggregate", "--receipts-dir", str(root), "--output", str(out),
                                   "--overlay-sha", "overlay-abc", "--matrix-result", "success"])
            self.assertEqual(code, 1)

    def test_nonzero_filtered_count_is_not_aggregate_success(self):
        receipt = complete_receipt("ubuntu-24.04")
        sid = next(stage["id"] for stage in json.loads((HERE / "binding.json").read_text())["stages"]
                   if stage["counts_required"])
        receipt["stages"][sid]["counts"][0]["counts"]["filtered"] = 1
        self.assertFalse(lifecycle._row_complete(receipt, json.loads((HERE / "binding.json").read_text())["stages"]))

    def test_null_receipt_produces_failed_summary_instead_of_crashing(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for row in lifecycle.EXPECTED_ROWS:
                folder = root / row
                folder.mkdir()
                content = "null" if row == "macos-15" else json.dumps(complete_receipt(row))
                (folder / "receipt.json").write_text(content)
            out = root / "summary.json"
            code = lifecycle.main(["aggregate", "--receipts-dir", str(root), "--output", str(out),
                                   "--overlay-sha", "overlay-abc", "--matrix-result", "success"])
            result = json.loads(out.read_text())
            self.assertEqual(code, 1)
            self.assertEqual(result["rows"]["macos-15"]["status"], "INVALID_RECEIPT")

    def test_combined_metadata_cap_is_explicit(self):
        receipt = {"problems": ["x" * (lifecycle.METADATA_CAP_BYTES + 1)]}
        state = {"source_checks": []}
        self.assertFalse(lifecycle._enforce_metadata_cap(receipt, state))

    @unittest.skipUnless(os.name == "posix", "process-group semantics are POSIX-only")
    def test_bounded_process_kills_descendant_after_leader_exits(self):
        with tempfile.TemporaryDirectory() as td:
            launched = Path(td) / "launched"
            marker = Path(td) / "survived"
            child = ("from pathlib import Path; import time; "
                     "Path(%r).write_text('yes'); time.sleep(0.9); Path(%r).write_text('alive')") % (str(launched), str(marker))
            parent = "import subprocess,sys; subprocess.Popen([sys.executable, '-c', sys.argv[1]])"
            _, _, _, truncated = lifecycle._bounded_process([sys.executable, "-c", parent, child], timeout=0.4)
            self.assertTrue(truncated)
            self.assertTrue(launched.exists(), "descendant should have started before deadline")
            time.sleep(0.65)
            self.assertFalse(marker.exists(), "descendant survived after process group cleanup")


if __name__ == "__main__":
    unittest.main()
