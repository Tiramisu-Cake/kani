# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Synthetic fail-closed tests for the D0 property/GOTO inventory builder."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).with_name("inventory.py")
spec = importlib.util.spec_from_file_location("d0_inventory", SCRIPT)
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.case_root = self.root / "case-A"
        self.private = self.case_root / "cbmc-private"
        self.private.mkdir(parents=True)
        self.goto_input = self.case_root / "model" / "model.out"
        self.goto_input.parent.mkdir()
        self.goto_input.write_bytes(b"synthetic-goto")
        self.raw = self.private / "capture.json"
        self.meta = self.private / "capture.meta.json"
        self.location = {"file": "main.rs", "line": "1", "function": "harness",
                         "propertyId": "p.check.1", "propertyClass": "assertion"}
        self._write_solver("SUCCESS", "SUCCESS")
        self._write_metadata()
        self._write_roots()
        self.cbmc = self._fake_tool("cbmc-tool", [{"properties": [{
            "name": "p.check.1", "description": "assertion", "class": "assertion",
            "sourceLocation": self.location}]}])
        self.goto = self._fake_tool("goto-instrument", [{"functions": [{
            "name": "harness", "instructions": [{"locationNumber": "42",
                "instruction": "ASSERT x", "labels": ["claim_label"], "targets": ["43"],
                "sourceLocation": self.location}]}]}])

    def tearDown(self):
        self.temp.cleanup()

    def _write_roots(self):
        self.goto_hash = hashlib.sha256(self.goto_input.read_bytes()).hexdigest()
        metadata_file = self.case_root / "metadata.json"
        metadata_file.write_text("synthetic actual harness metadata", encoding="utf-8")
        rows = [{"pretty_name": "harness", "mangled_name": "_ZN7harness",
                 "solver_input": str(self.goto_input), "solver_input_sha256": self.goto_hash,
                 "metadata_file": str(metadata_file),
                 "metadata_sha256": hashlib.sha256(metadata_file.read_bytes()).hexdigest()}]
        (self.case_root / "roots.json").write_text(json.dumps(rows), encoding="utf-8")

    def _write_solver(self, status, property_status):
        doc = [{"result": [{"property": "p.check.1", "status": property_status,
                            "description": "assertion", "sourceLocation": self.location,
                            "trace": []}]}, {"cProverStatus": status}]
        self.raw.write_text(json.dumps(doc), encoding="utf-8")

    def _write_metadata(self, **updates):
        digest = hashlib.sha256(self.raw.read_bytes()).hexdigest()
        doc = {"schema_version": inventory.CAPTURE_SCHEMA, "capture_state": "COMPLETE",
               "captured_complete": True, "dropped_bytes": 0, "child_signal": None,
               "wrapper_signal": None, "child_exit": 0, "original_stdout_sha256": digest,
               "retained_bytes": self.raw.stat().st_size, "retained_stdout_file": self.raw.name,
               "argv": ["cbmc", "--trace", str(self.goto_input), "--verbosity", "9", "--json-ui"]}
        doc.update(updates)
        self.meta.write_text(json.dumps(doc), encoding="utf-8")

    def _fake_tool(self, name, payload):
        path = self.root / name
        encoded = json.dumps(payload)
        path.write_text("#!/usr/bin/env python3\nimport json,sys\n"
                        f"print(json.dumps({encoded}))\n", encoding="utf-8")
        path.chmod(0o755)
        return str(path)

    def run_inventory(self, verification_exit=0, case="A"):
        return inventory.generate(self.raw, self.meta, "9" * 40, case, verification_exit,
                                  self.cbmc, self.goto, self.private)

    def test_success_binds_property_source_and_unique_assertion_pc(self):
        result = self.run_inventory()
        self.assertEqual(result["status"], "COMPLETE", result["errors"])
        self.assertEqual(result["input_sha256"], self.goto_hash)
        self.assertEqual(json.loads((self.private / "manifest.json").read_text())["root"]["pretty_name"], "harness")
        binding = json.loads((self.private / "bindings.json").read_text())["properties"]["p.check.1"]
        self.assertEqual(binding["goto_binding"], "harness#pc=42")
        self.assertEqual(binding["goto_pc_chain"]["labels"], ["claim_label"])
        self.assertEqual(binding["goto_pc_chain"]["targets"], ["43"])
        self.assertTrue((self.private / "curated.json").is_file())

    def test_failure_preserves_verdict_and_unknown_runtime_witness(self):
        self._write_solver("FAILURE", "FAILURE")
        self._write_metadata(child_exit=10)
        result = self.run_inventory(verification_exit=10)
        self.assertEqual(result["original_exits"]["solver"], 10)
        self.assertEqual(result["original_exits"]["cbmc_status"], "FAILURE")
        self.assertTrue(any("runtime operand and edge witness unavailable" in e for e in result["errors"]))
        witness = json.loads((self.private / "bindings.json").read_text())["properties"]["p.check.1"]["unknown_witness"]
        self.assertEqual(witness["status"], "UNKNOWN")

    def test_missing_capture_metadata_is_incomplete(self):
        self.meta.unlink()
        result = self.run_inventory()
        self.assertEqual(result["status"], "INCOMPLETE")
        self.assertTrue(any("invalid or unavailable JSON" in e for e in result["errors"]))

    def test_null_and_wrong_type_capture_metadata_is_incomplete(self):
        for field, value in (("capture_state", None), ("captured_complete", "true"),
                             ("dropped_bytes", "0"), ("argv", None), ("child_exit", "0")):
            with self.subTest(field=field):
                self._write_metadata(**{field: value})
                self.assertEqual(self.run_inventory()["status"], "INCOMPLETE")

    def test_capture_hash_mismatch_is_incomplete(self):
        self._write_metadata(original_stdout_sha256="0" * 64)
        result = self.run_inventory()
        self.assertTrue(any("SHA256 does not match" in e for e in result["errors"]))

    def test_solver_status_mismatch_is_incomplete(self):
        self._write_solver("FAILURE", "SUCCESS")
        self._write_metadata(child_exit=0)
        result = self.run_inventory(verification_exit=10)
        self.assertTrue(any("disagrees with cProverStatus" in e for e in result["errors"]))

    def test_exact_input_mismatch_is_incomplete(self):
        self._write_metadata(argv=["cbmc", "--trace", str(self.root / "missing.out"),
                                   "--verbosity", "9", "--json-ui"])
        result = self.run_inventory()
        self.assertIsNone(result["input_sha256"])
        self.assertTrue(any("exact solver input" in e or "roots mapping" in e for e in result["errors"]))

    def test_property_inventory_mismatch_is_incomplete(self):
        self.cbmc = self._fake_tool("bad-cbmc-tool", [{"properties": []}])
        result = self.run_inventory()
        self.assertTrue(any("cannot compare" in e for e in result["errors"]))

    def test_ambiguous_assertion_pc_is_incomplete(self):
        self.goto = self._fake_tool("ambiguous-goto", [{"functions": [{"name": "harness", "instructions": [
            {"locationNumber": "42", "instruction": "ASSERT x", "labels": [], "targets": [],
             "sourceLocation": self.location},
            {"locationNumber": "43", "instruction": "ASSERT x", "labels": [], "targets": [],
             "sourceLocation": self.location}]}]}])
        result = self.run_inventory()
        self.assertTrue(any("expected one exact GOTO assertion PC, found 2" in e for e in result["errors"]))

    def test_solver_source_location_mismatch_is_incomplete(self):
        solver = json.loads(self.raw.read_text())
        solver[0]["result"][0]["sourceLocation"]["line"] = "9"
        self.raw.write_text(json.dumps(solver), encoding="utf-8")
        self._write_metadata()
        result = self.run_inventory()
        self.assertTrue(any("solver and show-properties sourceLocation mismatch" in e for e in result["errors"]))

    def test_pair_case_is_accepted(self):
        result = self.run_inventory(case="pair")
        self.assertEqual(result["status"], "COMPLETE", result["errors"])


if __name__ == "__main__":
    unittest.main()
