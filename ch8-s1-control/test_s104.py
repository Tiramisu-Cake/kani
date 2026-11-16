"""S1-04 regressions for request groups, exact negatives, and source overlays."""
from __future__ import annotations

import difflib
import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import negative_oracle
import runner


class S104RunnerTests(unittest.TestCase):
    def test_porcelain_z_keeps_a_path_with_spaces_and_restores_on_bad_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "source"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            rel = "library/core/file with spaces.rs"
            source = repo / rel
            source.parent.mkdir(parents=True)
            source.write_text("before\n")
            subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
            subprocess.run(["git", "-C", str(repo), "-c", "user.name=Synthetic",
                            "-c", "user.email=synthetic@invalid", "commit", "-qm", "fixture"], check=True)
            patch = root / "overlay.patch"
            patch.write_text("".join(difflib.unified_diff(["before\n"], ["after\n"],
                                                           fromfile="a/" + rel, tofile="b/" + rel)))
            digest = hashlib.sha256(b"after\n").hexdigest()
            with mock.patch.object(runner, "_variant_info", return_value=(patch, "fixture", {rel: digest})):
                applied, _ = runner._run_variant(repo, "activation-default", {})
            self.assertEqual(applied, patch)
            self.assertEqual(source.read_text(), "after\n")
            subprocess.run(["git", "-C", str(repo), "apply", "--reverse", str(patch)], check=True)
            with mock.patch.object(runner, "_variant_info", return_value=(patch, "fixture", {rel: "wrong"})):
                with self.assertRaisesRegex(runner.RunnerError, "changed-file SHA mismatch"):
                    runner._run_variant(repo, "activation-default", {})
            self.assertEqual(source.read_text(), "before\n")
            self.assertEqual(subprocess.check_output(["git", "-C", str(repo), "status",
                                                     "--porcelain=v1"]), b"")

    def test_negative_oracle_requires_exact_id_file_line_class(self):
        oracle = {"selector": "crate::root", "property_id": "assertion.4",
                  "file": "library/core.rs", "export_file": "/kani/export/library/core.rs",
                  "line": 27, "class": "assertion"}
        harness = {"name": "crate::root", "outcome": {"kind": "COMPLETED", "verdict": "FAILURE"},
                   "n_failed": 1, "n_properties": 3,
                   "checks": {"failure": ["assertion.4"], "total": 2, "success": 1,
                              "unreachable": [], "undetermined": [], "error": [], "unknown": [], "other": []},
                   "covers": {"total": 1, "satisfied": ["cover.1"], "unsatisfiable": [],
                              "unreachable": [], "undetermined": [], "error": [], "unknown": [], "other": []},
                   "unsupported_constructs": [],
                   "failed_properties": [{"id": "assertion.4", "file": "/kani/export/library/core.rs",
                                          "line": "27", "class": "assertion", "status": "FAILURE"}]}
        self.assertTrue(negative_oracle.matches(harness, oracle))
        for key, value in (("id", "description-only"), ("line", "28"),
                           ("file", "/kani/export/elsewhere.rs"), ("class", "cover")):
            altered = {**harness, "failed_properties": [dict(harness["failed_properties"][0])]}
            altered["failed_properties"][0][key] = value
            self.assertFalse(negative_oracle.matches(altered, oracle), key)
        self.assertFalse(negative_oracle.matches(harness, None))

    def test_fixed_n_union_stays_pending_without_named_message_binding(self):
        ids = [f"case_n{i}" for i in range(4)]
        messages = ["COVER_N0", "COVER_N1", "COVER_N2", "COVER_N3"]
        success = ["MODEL", "POST"]
        union = {"id": "fixed_n", "member_row_ids": ids,
                 "required_cover_messages": messages, "required_success_messages": success}
        rows = [{"id": rid, "mode": "PFC", "expected": "SUCCESS", "required_covers": messages}
                for rid in ids]
        observations = {rid: {"status": "OBSERVED", "outcome": "EXPECTED",
                              "export": {"state": "VALIDATED_OBSERVATION",
                                         "satisfied_cover_ids": messages},
                              "success_message_binding": "PENDING_NO_NAMED_SUCCESS_CHECK_BINDING"}
                       for rid in ids}
        pending = runner.aggregate_replacement_union(union, rows, observations)
        self.assertEqual(pending["state"], "PENDING_NAMED_MESSAGE_BINDING")
        self.assertFalse(pending["eligible_for_review"])
        self.assertEqual(pending["proof_credit"], "NONE")
        observations[ids[-1]]["outcome"] = "UNKNOWN"
        incomplete = runner.aggregate_replacement_union(union, rows, observations)
        self.assertEqual(incomplete["state"], "INCOMPLETE_CASES")
        self.assertFalse(incomplete["eligible_for_review"])


if __name__ == "__main__":
    unittest.main()
