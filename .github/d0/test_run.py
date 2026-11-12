# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import run


class RunnerTests(unittest.TestCase):
    def test_roots_use_metadata_artifact_mapping_and_reject_stubs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            linked = root / "model/harness.out"
            linked.parent.mkdir()
            linked.write_bytes(b"fake model")
            metadata = {"test_harnesses": [], "proof_harnesses": [{"pretty_name": run.A,
                        "mangled_name": "actual-mangled", "goto_file": str(root / "model/harness.symtab.out"),
                        "is_automatically_generated": False,
                        "attributes": {"kind": "Proof", "stubs": [], "verified_stubs": []}}]}
            path = root / "model/fixture.kani-metadata.json"
            run.write(path, metadata)
            rows = run.extract_roots(root, [run.A])
            self.assertEqual(rows[0]["solver_input"], str(linked))
            self.assertEqual(rows[0]["solver_input_sha256"], run.digest(linked))
            with self.assertRaisesRegex(AssertionError, "actual roots"):
                run.extract_roots(root, [run.B])
            metadata["proof_harnesses"][0]["attributes"]["stubs"] = ["unexpected"]
            run.write(path, metadata)
            with self.assertRaisesRegex(AssertionError, "mode/stubs"):
                run.extract_roots(root, [run.A])

    def test_process_original_failures_and_signals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for code in (0, 1, 10):
                result = run.command([sys.executable, "-c", f"raise SystemExit({code})"], root, root / "log", 5)
                self.assertEqual(result["exit"], code)
            result = run.command([sys.executable, "-c", "import os,signal; os.kill(os.getpid(),signal.SIGTERM)"], root, root / "log", 5)
            self.assertIsNone(result["exit"])
            self.assertEqual(result["signal"], 15)

    def test_timeout_and_missing_are_distinct(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run.command([sys.executable, "-c", "import time; time.sleep(10)"], root, root / "log", 0.02)
            self.assertEqual(result["exit"], "TIMEOUT")
            result = run.command([str(root / "absent")], root, root / "log", 1)
            self.assertEqual(result["exit"], "NOT_RUN")

    def test_setup_error_never_calls_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(run, "preflight", side_effect=AssertionError("wrong source")), patch.object(run, "command") as command:
                self.assertEqual(run.prepare(root, "candidate", root), 1)
                command.assert_not_called()
            state = json.loads((root / "phases.json").read_text())
            self.assertEqual(state["setup"], "NOT_RUN")
            self.assertEqual(state["build"], "NOT_RUN")

    def test_build_error_preserves_exact_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(run, "preflight", return_value={}), patch.object(run, "command", return_value={"exit": 23}):
                self.assertEqual(run.prepare(root, "candidate", root), 1)
            self.assertEqual(json.loads((root / "phases.json").read_text())["build"]["exit"], 23)

    def test_verification_fail_does_not_abort_later_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "candidate"
            compiler = repo / "target/kani/bin/kani-compiler"
            compiler.parent.mkdir(parents=True)
            compiler.write_text("fake built compiler")
            (repo / "target/kani/lib").mkdir()
            output = root / "private/candidate"
            identity = {"source": run.CANDIDATE, "rustc_vV": "same", "rust_sysroot": [],
                        "tools": {"cbmc": {"path": "/fake/cbmc"}}, "target_spec": {}, "kani_sysroot": []}
            run.write(output / "identity.json", identity)
            run.write(output / "phases.json", {"errors": []})
            calls = []

            def fake_command(argv, cwd, log, timeout, env):
                calls.append((argv, env))
                run.write(log.parent / "compiler-process/pid.json", {"is_compile": True,
                          "state": "COMPLETE", "exit": 0, "signal": None})
                return {"exit": 1, "argv": argv}

            with patch.object(run, "command", side_effect=fake_command):
                self.assertEqual(run.run_cases(repo, "candidate", output, root / "private"), 0)
            self.assertEqual([env["KANI_D0_CASE"] for _, env in calls], ["A", "B", "AB", "BA", "D"])
            for case in ("A", "B", "AB", "BA", "D"):
                state = json.loads((output / "cases" / case / "phases.json").read_text())
                self.assertEqual(state["verification"]["exit"], 1)
                self.assertTrue(state["compiler_ok"])
            # AB/BA selectors are identical, only diagnostic CASE and output paths differ.
            normalize = lambda argv: [item.replace("/AB/", "/CASE/").replace("/BA/", "/CASE/") for item in argv]
            self.assertEqual(normalize(calls[2][0]), normalize(calls[3][0]))

    def test_compiler_supervisor_observes_real_child_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("compiler_supervisor.py", "capture_cbmc.py"):
                shutil.copyfile(run.HERE / name, root / name)
            launcher = root / "kani-compiler"
            shutil.copyfile(root / "compiler_supervisor.py", launcher)
            real = root / "kani-compiler.d0-real"
            real.write_text("#!/usr/bin/env python3\nraise SystemExit(17)\n")
            real.chmod(0o755)
            result = subprocess.run([sys.executable, str(launcher), "--kani-compiler", "fixture.rs"],
                                    env=dict(os.environ, D0_CAPTURE_DIR=str(root / "capture")), timeout=5)
            self.assertEqual(result.returncode, 17)
            records = list((root / "compiler-process").glob("*.json"))
            self.assertEqual(len(records), 1)
            data = json.loads(records[0].read_text())
            self.assertEqual(data["exit"], 17)
            self.assertEqual(data["state"], "COMPLETE")
            self.assertTrue(data["is_compile"])
            self.assertIsNone(data["signal"])


if __name__ == "__main__":
    unittest.main()
