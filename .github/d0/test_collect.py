# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import collect
from run import write


class CollectionTests(unittest.TestCase):
    def test_driver_version_probe_is_preserved_separately_from_solver(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw, meta = root / "probe.json", root / "probe.meta.json"
            raw.write_text("6.11.0\n")
            write(meta, {"argv": ["cbmc", "--version"], "capture_state": "COMPLETE", "captured_complete": True,
                         "dropped_bytes": 0, "child_exit": 0, "child_signal": None, "wrapper_signal": None,
                         "retained_bytes": raw.stat().st_size, "original_stdout_sha256": collect.digest(raw)})
            solver = root / "solver.meta.json"
            write(solver, {"argv": ["cbmc", "model.out", "--json-ui"]})
            solvers, probes, errors = collect.split_captures([meta, solver], "6.11.0")
            self.assertEqual(solvers, [solver])
            self.assertEqual(probes[0]["original_exit"], 0)
            self.assertTrue(probes[0]["complete"])
            self.assertEqual(errors, [])
            raw.write_text("6.10.0\n")
            self.assertTrue(collect.split_captures([meta], "6.11.0")[2])

    def test_terminal_verification_fail_is_reported_without_failing_infrastructure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private, output = root / "private", root / "curated"
            for source, cases in (("candidate", ("A", "B", "AB", "BA", "D")), ("baseline", ("A", "B", "pair"))):
                identity = {"source": collect.CANDIDATE if source == "candidate" else collect.BASELINE,
                            "tools": {"cbmc": {"path": "/fake/cbmc"}, "goto-instrument": {"path": "/fake/goto"}}}
                write(private / source / "identity.json", identity)
                write(private / source / "phases.json", {"setup": 0, "build": {"exit": 0}, "errors": []})
                for case in cases:
                    directory = private / source / "cases" / case
                    write(directory / "phases.json", {"setup": 0, "compiler": [{"exit": 0}], "compiler_ok": True,
                                                       "verification": {"exit": 1, "argv": [str(root / source / "scripts/kani")]},
                                                       "explicit_environment": {}, "actual_roots": []})
                    for index in range(1 if case in ("A", "B") else 2):
                        write(directory / f"cbmc-private/{index}.meta.json", {})
                        write(directory / f"cbmc-private/{index}.json", {"private_trace": "do not hand off"})

            def fake_inventory(raw, meta, source, case, verification, cbmc, goto, out):
                write(out / "curated.json", {"test": "selected data only"})
                write(out / "goto-functions.inventory.json", {"private_full_listing": True})
                name = "B" if case == "B" or raw.name == "1.json" else "A"
                write(out / "manifest.json", {"root": {"pretty_name": name}, "capture": {"input_sha256": "a" * 64}})
                write(out / "property-inventory.json", {"properties": [{"property_id": "exact-id", "result_status": "FAILURE"}]})
                return {"status": "COMPLETE", "original_exits": {"solver": 10, "verification": verification}}

            compiler = {"errors": [], "selected_events": [{"stage": "prewarm-begin", "payload": "actual-root-sequence"}]}
            with patch.object(collect.inventory, "generate", side_effect=fake_inventory), patch.object(collect, "summarize_compiler", return_value=compiler):
                self.assertEqual(collect.collect(private, output), 0)
            report = json.loads((output / "candidate/cases/AB/manifest.json").read_text())
            self.assertEqual(report["verification"]["exit"], 1)
            self.assertEqual(report["solvers"][0]["original_exits"]["solver"], 10)
            self.assertEqual(report["curation"], 0)
            for path in output.rglob("*.json"):
                self.assertNotIn("private_trace", path.read_text())
                self.assertNotIn("private_full_listing", path.read_text())
            self.assertEqual(json.loads((private / "candidate/cases/AB/phases.json").read_text())["curation"], 0)
            comparisons = json.loads((output / "controls.json").read_text())["baseline_comparisons"]
            self.assertTrue(all(row["property_inventories_equal"] for row in comparisons))
            self.assertTrue(all(row["goto_listings_equal"] for row in comparisons))
            write(private / "baseline/cases/pair/inventory/0/goto-functions.inventory.json", {"changed_edge": True})
            comparisons, errors = collect.compare_controls(private)
            self.assertEqual(comparisons[2]["status"], "MISMATCH_STOP")
            self.assertTrue(errors)

    def test_missing_phases_produce_bounded_explicit_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.assertEqual(collect.collect(root / "private", root / "curated"), 2)
            status = json.loads((root / "curated/status.json").read_text())
            self.assertGreater(status["error_count"], 0)
            manifest = json.loads((root / "curated/candidate/cases/A/manifest.json").read_text())
            self.assertEqual(manifest["verification"], "NOT_RUN")
            self.assertEqual(manifest["compiler"], "UNKNOWN")
            self.assertEqual(manifest["curation"], 2)
            self.assertFalse(manifest["causal_claim"])
            self.assertLess(sum(p.stat().st_size for p in (root / "curated").rglob("*") if p.is_file()), collect.MAX_PACKET)

    def test_compiler_cap_wrong_identity_and_missing_coverage(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = root / "A"
            output = root / "output"
            output.mkdir()
            result = collect.summarize_compiler(case, output)
            self.assertTrue(result["errors"])
            write(case / "compiler/1-coverage.json", {"codegen_completed": True, "counts": {"dropped": {"mir-original": 1}}})
            result = collect.summarize_compiler(case, output)
            self.assertIn("compiler sidecar cap reached", result["errors"])
            write(case / "compiler/1-000001-unit.json", {"schema": "kani3300-d0/v1", "case": "B", "unit": 0, "cache": 0})
            with self.assertRaisesRegex(ValueError, "source/stage/target mismatch"):
                collect.summarize_compiler(case, output)

    def test_emergency_packet_has_current_inventory_and_no_partial_payloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root / "candidate/partial.json", {"potentially_stale": True})
            collect.emergency_packet(root, "synthetic cap")
            self.assertFalse((root / "candidate").exists())
            manifest = json.loads((root / "packet-manifest.json").read_text())
            for row in manifest["files"]:
                self.assertEqual(collect.digest(root / row["file"]), row["sha256"])
            self.assertEqual(json.loads((root / "status.json").read_text())["curation_exit"], 2)

    def test_bounded_json_never_silently_truncates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "target.json"
            with self.assertRaisesRegex(ValueError, "curated file cap"):
                collect.bounded_write(path, {"required": "x" * 1000}, cap=32)
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
