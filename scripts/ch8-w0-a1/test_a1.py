#!/usr/bin/env python3
"""Synthetic wrapper controls; no Kani, Rust, setup, or compiler invocation."""
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import a1


R1 = sorted(a1.R1_SUFFIXES)
R2 = sorted(a1.R2_SELECTORS)


def mk_r1(suffix):
    selector = "slice::sort::shared::smallsort::verify::wave0_a1::" + suffix
    return {"id": suffix, "selector": selector, "mode": "actual-body",
            "argv": ["<KANI>", "verify-std", "-Zuninit-checks", "--no-assert-contracts",
                     "./library", "--harness", selector, "--harness-timeout", "600s",
                     "--cbmc-args", "--object-bits", "12", "--export-json", "<OUT>/export.json"],
            "environment": {"RUSTFLAGS": "--cfg kani_smallsort_controls"}}


def mk_r2(selector):
    issue = {"nonnull_field": "5020", "initialized_same_type_companion": "5020",
             "reassemble_ptr_fragments_in_static": "4854", "explicit_proof_observes_initialized_null": "4854",
             "drop_uninit_in_array": "5151", "drop_initialized_slot_in_array": "5151"}[selector]
    original = selector in ("nonnull_field", "reassemble_ptr_fragments_in_static", "drop_uninit_in_array")
    mode = "autoharness" if selector == "reassemble_ptr_fragments_in_static" else "proof"
    argv = ["<KANI>"]
    if mode == "autoharness":
        argv += ["autoharness", "-Zautoharness", "<FIXTURE>", "--run-sanity-checks", "-Zuninit-checks", "-Zuninit-checks"]
    else:
        argv += ["-Zuninit-checks", "<FIXTURE>", "--harness", selector]
    argv += ["--export-json", "<OUT>/export.json"]
    fixture = a1.R2_FIXTURES[selector]
    environment = {"NO_COLOR": "1"}
    if selector == "reassemble_ptr_fragments_in_static":
        environment.update({"RUSTFLAGS": "--edition=2021 --cap-lints=warn", "RUST_BACKTRACE": "full"})
    return {"id": f"issue-{issue}-{'original' if original else 'companion'}-{selector}",
            "selector": selector, "mode": mode, "fixture": fixture,
            "fixture_sha256": hashlib.sha256(f"synthetic fixture {selector}".encode()).hexdigest(), "argv": argv,
            "environment": environment}


def request_doc():
    return {"pins": {n: {"sha": a1.PIN_IDENTITIES[n][0], "tree": a1.PIN_IDENTITIES[n][1], "binding": f"{n}-source-binding.json"}
                     for n in a1.PIN_NAMES},
            "std": {"base_sha": "c" * 40, "base_tree": "d" * 40, "base_library_tree": "e" * 40,
                    "patch": "std-test-only.patch", "patch_sha256": "f" * 64,
                    "patched_files": {"library/core/src/verify.rs": "1" * 64}},
            "r1": {"rows": [mk_r1(s) for s in R1]},
            "r2": {"rows": [mk_r2(s) for s in R2]}}


class RequestTests(unittest.TestCase):
    def setup_request(self, root, req=None):
        path = root / "CI-REQUEST.json"; body = json.dumps(req or request_doc()).encode(); path.write_bytes(body)
        (root / "std-test-only.patch").write_bytes(b"synthetic patch")
        doc = json.loads(body); doc["std"]["patch_sha256"] = hashlib.sha256((root / "std-test-only.patch").read_bytes()).hexdigest()
        for row in doc["r2"]["rows"]:
            fixture = root / row["fixture"]; fixture.parent.mkdir(parents=True, exist_ok=True)
            fixture.write_text("synthetic fixture " + row["selector"])
        body = json.dumps(doc).encode(); path.write_bytes(body)
        return doc, path

    def test_accepts_exact_r1_r2_rows_and_null_environment_removal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); _, path = self.setup_request(root)
            with mock.patch.object(a1, "HERE", root), mock.patch.object(a1, "REQUEST", path):
                req = a1.load_request()
            self.assertEqual(len(req["r1"]["rows"]), 8)
            self.assertEqual(len(req["r2"]["rows"]), 6)
            for row in req["r2"]["rows"]:
                if row["selector"] != "reassemble_ptr_fragments_in_static":
                    self.assertNotIn("RUSTFLAGS", row["environment"])

    def test_rejects_missing_row_or_native_std_mixup(self):
        req = request_doc(); req["r2"]["rows"].pop()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); _, path = self.setup_request(root, req)
            with mock.patch.object(a1, "HERE", root), mock.patch.object(a1, "REQUEST", path), \
                 self.assertRaisesRegex(ValueError, "exact three originals"):
                a1.load_request()
        row = mk_r2("nonnull_field"); row["argv"].append("./library")
        with self.assertRaisesRegex(ValueError, "cannot use verify-std/library"):
            a1.validate_row("r2", row)

    def _validate_request_rows(self, req):
        rows = req["r2"]["rows"]
        self.assertNotEqual({r["selector"] for r in rows}, a1.R2_SELECTORS)
        with self.assertRaisesRegex(ValueError, "outside the exact native-case"):
            a1.validate_row("r2", {**rows[-1], "selector": "unknown"})

    def test_rejects_wrong_mode_and_selector_binding(self):
        row = mk_r2("reassemble_ptr_fragments_in_static")
        row["argv"] = ["<KANI>", "<FIXTURE>", "-Zuninit-checks", "--harness", row["selector"], "<OUT>/export.json"]
        with self.assertRaisesRegex(ValueError, "autoharness mode"):
            a1.validate_row("r2", row)
        row = mk_r1(R1[0]); row["argv"][row["argv"].index("--harness") + 1] = "wrong"
        with self.assertRaisesRegex(ValueError, "r1 mode/selector"):
            a1.validate_row("r1", row)


class ExportTests(unittest.TestCase):
    def test_parser_states_are_unknown_and_selector_mismatch_is_not_success(self):
        def envelope(name="wanted", state="COMPLETE", matched=1, unmatched=None):
            return {"run_state": state,
                    "harness_selection": {"requested_filters": ["wanted"], "exact": True,
                                          "matched_count": matched, "unmatched_filters": unmatched or []},
                    "harnesses": [{"name": name, "file": "fixture.rs", "line": 1,
                                   "is_automatically_generated": False,
                                   "outcome": {"kind": "COMPLETED", "verdict": "SUCCESS"},
                                   "n_properties": 4, "n_failed": 0, "failed_properties": [],
                                   "unsupported_constructs": [],
                                   "checks": {"total": 4, "success": 4, "failure": [], "unreachable": [],
                                              "undetermined": [], "error": [], "unknown": [], "other": []},
                                   "covers": {"total": 0, "satisfied": [], "unsatisfiable": [], "unreachable": [],
                                              "undetermined": [], "error": [], "unknown": [], "other": []}}]}
        cases = [(None, "MISSING"), (b"", "EMPTY"), (b'{"result":', "INVALID_OR_PARTIAL"),
                 (b"null", "NULL"), (b"[]", "WRONG_TOP_LEVEL_TYPE"),
                 (json.dumps(envelope(name="other")).encode(), "UNKNOWN_WRONG_SELECTOR"),
                 (json.dumps(envelope(state="PARTIAL")).encode(), "PARTIAL"),
                 (json.dumps(envelope(matched=0, unmatched=["wanted"])).encode(), "UNKNOWN_HARNESS_SELECTION"),
                 (json.dumps(envelope()).encode(), "UNVALIDATED_COMPLETE_SINGLE_HARNESS")]
        with tempfile.TemporaryDirectory() as td:
            for i, (raw, state) in enumerate(cases):
                path = Path(td) / str(i)
                if raw is not None: path.write_bytes(raw)
                parsed = a1.parse_export(path, "wanted")
                self.assertEqual(parsed["state"], state)
                self.assertEqual(parsed["outcome"], "UNKNOWN")
                self.assertIsNone(parsed.get("generated_property_binding"))
                if state == "UNVALIDATED_COMPLETE_SINGLE_HARNESS":
                    self.assertEqual(parsed["harness"]["outcome"]["verdict"], "SUCCESS")
                    self.assertEqual(parsed["harness"]["n_failed"], 0)


class SourceBindingTests(unittest.TestCase):
    def test_wrong_pin_tree_dirty_status_and_bound_file_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); bind = root / "baseline-source-binding.json"
            payload = b"literal git blob"; digest = hashlib.sha256(payload).hexdigest()
            baseline_sha, baseline_tree = a1.PIN_IDENTITIES["baseline"]
            binding = {"state": "FROZEN", "export_sha": baseline_sha, "export_tree": baseline_tree,
                       "files": {"source": digest}, "subtrees": {"src": "c"*40}, "submodules": []}
            bind.write_text(json.dumps(binding)); pin = {"sha": baseline_sha, "tree": baseline_tree, "binding": bind.name}
            req = {"pins": {"baseline": pin}}
            def fake_git(repo, *args):
                if args == ("cat-file", "-t", pin["sha"]): return "commit"
                if args == ("rev-parse", pin["sha"] + "^{tree}"): return "wrong" if mode[0] == "tree" else pin["tree"]
                if args == ("rev-parse", "HEAD"): return "wrong" if mode[0] == "pin" else pin["sha"]
                if args == ("status", "--porcelain"): return " M x" if mode[0] == "dirty" else ""
                if args == ("rev-parse", pin["sha"] + ":src"): return "wrong" if mode[0] == "subtree" else "c"*40
                self.fail(f"unexpected git args {args}")
            (root / "source").write_bytes(payload)
            def fake_run(argv, **kwargs):
                if "show" in argv:
                    out = b"wrong blob" if mode[0] == "file" else payload
                    return type("P", (), {"stdout": out})()
                self.fail(f"unexpected subprocess {argv}")
            mode = ["ok"]
            with mock.patch.object(a1, "HERE", root), mock.patch.object(a1, "git", side_effect=fake_git), \
                 mock.patch.object(a1.subprocess, "run", side_effect=fake_run):
                self.assertEqual(a1.verify_source(root, "baseline", req)["status"], "VALID")
                for bad in ("pin", "tree", "dirty", "subtree", "file"):
                    mode[0] = bad
                    with self.subTest(bad=bad), self.assertRaises(ValueError): a1.verify_source(root, "baseline", req)

    def test_fixture_hash_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); p = root / "native.rs"; p.write_text("fixture")
            row = {"fixture": "native.rs", "fixture_sha256": "0"*64}
            with mock.patch.object(a1, "HERE", root), self.assertRaisesRegex(ValueError, "fixture byte hash"):
                a1._fixture_for(row)

    def test_frozen_pin_request_rejects_wrong_commit_even_before_git(self):
        req = {"pins": {"baseline": {"sha": "0"*40, "tree": "1"*40}}}
        with self.assertRaisesRegex(ValueError, "literal frozen"):
            a1.verify_source(Path("/unused"), "baseline", req)


class ExecutionTests(unittest.TestCase):
    def run_code(self, code, timeout=2):
        td = tempfile.TemporaryDirectory(); out = Path(td.name) / "out"
        high_ram = {"available_bytes_before_dispatch": 16 * 1024**3, "reserve_bytes": a1.RSS_RESERVE_BYTES,
                    "group_rss_kill_threshold_bytes": 14 * 1024**3, "status": "OBSERVED"}
        with mock.patch.object(a1, "_memory_threshold", return_value=high_ram):
            r = a1.execute([sys.executable, "-c", code], Path(td.name), os.environ.copy(), out, timeout)
        return td, out, r

    def test_success_intended_failure_and_signal_preserve_child_status(self):
        td, _, r = self.run_code("print('ok')")
        self.assertEqual(r["original_exit_code"], 0); self.assertEqual(r["outcome"], "UNKNOWN"); td.cleanup()
        td, _, r = self.run_code("raise SystemExit(7)")
        self.assertEqual(a1.root_exit_code({**r, "postprocessing_state": "COMPLETE", "rss": {"status": r["rss_status"], "max_bytes": r["rss_max_bytes"]}, "export": {"state": "UNVALIDATED_JSON_OBJECT_UNKNOWN"}}), 7); td.cleanup()
        td, _, r = self.run_code("import os,signal; os.kill(os.getpid(), signal.SIGTERM)")
        self.assertEqual(r["signal"], signal.SIGTERM); self.assertLess(r["original_exit_code"], 0); td.cleanup()

    def test_timeout_kills_descendant_after_leader_exits(self):
        code = "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)'])"
        td, _, r = self.run_code(code, timeout=.25)
        self.assertTrue(r["timed_out"]); self.assertIn("group cap", r["runner_error"]); td.cleanup()

    def test_output_stream_cap_is_enforced_during_execution(self):
        with mock.patch.object(a1, "STDOUT_LIMIT", 256):
            td, _, r = self.run_code("import sys; sys.stdout.write('x'*100000); sys.stdout.flush()")
        self.assertTrue(r["output_capped"]); self.assertTrue(r["stdout_truncated"])
        self.assertLessEqual(r["stdout_bytes"], 256); td.cleanup()

    def test_frozen_job_rss_policy_is_used_and_cannot_exceed_reserve(self):
        env = {"A1_MEM_AVAILABLE_BYTES": str(8 * 1024**3), "A1_RSS_LIMIT_BYTES": str(5 * 1024**3)}
        with mock.patch.dict(os.environ, env, clear=False):
            self.assertEqual(a1._memory_threshold()["status"], "FROZEN_JOB_POLICY")
            with mock.patch.dict(os.environ, {"A1_RSS_LIMIT_BYTES": str(7 * 1024**3)}, clear=False):
                with self.assertRaisesRegex(ValueError, "exceeds recorded"):
                    a1._memory_threshold()

    def test_setup_only_or_unknown_receipt_is_nonzero_and_never_pass(self):
        self.assertNotEqual(a1.root_exit_code({"original_exit_code": None, "phase": "SETUP_ONLY",
                                               "postprocessing_state": "INCOMPLETE", "outcome": "UNKNOWN"}), 0)
        receipt = {"original_exit_code": 0, "timed_out": False, "runner_error": None,
                   "postprocessing_state": "COMPLETE", "export": {"state": "UNVALIDATED_JSON_OBJECT_UNKNOWN"},
                   "rss": {"status": "OBSERVED_WAIT4_LINUX_RU_MAXRSS", "max_bytes": 1},
                   "post_run_validation": {"source_valid": True, "controls_valid": True}, "outcome": "UNKNOWN"}
        self.assertEqual(a1.root_exit_code(receipt), 0)
        self.assertEqual(receipt["outcome"], "UNKNOWN")

    def test_durable_run_receipt_marks_post_run_source_drift_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); request = request_doc(); fixture = root / a1.R2_FIXTURES["nonnull_field"]
            fixture.parent.mkdir(parents=True); fixture.write_text("x")
            (root / "std-test-only.patch").write_text("patch")
            for name in a1.PIN_NAMES: (root / f"{name}-source-binding.json").write_text("binding")
            binary = root / "scripts" / "kani"; binary.parent.mkdir(); binary.write_text("synthetic"); binary.chmod(0o755)
            out = root / "out"; row = mk_r2("nonnull_field"); row["fixture_sha256"] = hashlib.sha256(b"x").hexdigest(); request["r2"] = {"rows": [row]}
            req_path = root / "CI-REQUEST.json"; req_path.write_text("{}")
            before = {"pin": "baseline", "tree": "before", "status": "VALID"}
            after = {"pin": "baseline", "tree": "after", "status": "VALID"}
            synthetic_exec = {"original_exit_code": 0, "signal": None, "timed_out": False,
                              "output_capped": False, "artifact_capped": False, "rss_watchdog_killed": False,
                              "runner_error": None, "rss_max_bytes": 1234, "rss_status": "OBSERVED_WAIT4_LINUX_RU_MAXRSS",
                              "group_rss_peak_bytes": 1, "driver_rss_peak_bytes": 1, "backend_rss_peak_bytes": 0,
                              "rss_max_kib": 1, "rss_max_mib": .001, "rss_max_gib": .000001,
                              "elapsed_seconds": .01, "stdout_bytes": 0, "stderr_bytes": 0,
                              "stdout_truncated": False, "stderr_truncated": False,
                              "stdout_sha256": "0"*64, "stderr_sha256": "0"*64, "outcome": "UNKNOWN"}
            with mock.patch.object(a1, "HERE", root), mock.patch.object(a1, "REQUEST", req_path), mock.patch.object(a1, "load_request", return_value=request), \
                 mock.patch.object(a1, "verify_source", side_effect=[before, after]), \
                 mock.patch.object(a1, "_fixture_for", return_value=(fixture, hashlib.sha256(b"x").hexdigest())), \
                 mock.patch.object(a1, "execute", return_value=synthetic_exec), \
                 mock.patch.object(a1.origin, "runtime_inventory", return_value={}), \
                 mock.patch.object(a1, "parse_export", return_value={"state": "MISSING", "outcome": "UNKNOWN"}):
                result = a1.run(root, "baseline", "r2", row["id"], binary, out)
            self.assertEqual(result["postprocessing_state"], "COMPLETE")
            self.assertFalse(result["post_run_validation"]["source_valid"])
            self.assertNotEqual(a1.root_exit_code(result), 0)
            self.assertEqual(json.loads((out / "receipt.json").read_text())["outcome"], "UNKNOWN")
            self.assertEqual(Path(result["cwd"]).name, "cwd")
            self.assertEqual(Path(result["input_abs_path"]).read_bytes(), b"x")

    def test_successful_r1_records_std_and_does_not_need_native_fixture(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); binary = root / "scripts" / "kani"; binary.parent.mkdir()
            binary.write_text("synthetic"); binary.chmod(0o755)
            (root / "std-test-only.patch").write_text("patch")
            for name in a1.PIN_NAMES: (root / f"{name}-source-binding.json").write_text("binding")
            out = root / "r1" / "row"; std = root / "std"
            row = mk_r1(R1[0]); request = {"pins": request_doc()["pins"], "r1": {"rows": [row]}, "std": {}}
            req_path = root / "CI-REQUEST.json"; req_path.write_text("{}")
            source = {"pin": "sel1", "sha": "same", "status": "VALID"}
            base = {"head": "frozen", "tree": "tree", "library_tree": "library"}
            overlay = {"paths": ["test.rs"], "sha256": {"test.rs": "hash"}}
            synthetic_exec = {"original_exit_code": 0, "signal": None, "timed_out": False,
                              "output_capped": False, "artifact_capped": False, "rss_watchdog_killed": False,
                              "runner_error": None, "rss_max_bytes": 1234, "rss_status": "OBSERVED_WAIT4_LINUX_RU_MAXRSS",
                              "group_rss_peak_bytes": 1, "driver_rss_peak_bytes": 1, "backend_rss_peak_bytes": 0,
                              "rss_max_kib": 1, "rss_max_mib": .001, "rss_max_gib": .000001,
                              "elapsed_seconds": .01, "stdout_bytes": 0, "stderr_bytes": 0,
                              "stdout_truncated": False, "stderr_truncated": False,
                              "stdout_sha256": "0"*64, "stderr_sha256": "0"*64, "outcome": "UNKNOWN"}
            with mock.patch.object(a1, "HERE", root), mock.patch.object(a1, "REQUEST", req_path), \
                 mock.patch.object(a1, "load_request", return_value=request), \
                 mock.patch.object(a1, "verify_source", side_effect=[source, source]), \
                 mock.patch.object(a1, "_verify_std_base", side_effect=[base, base]), \
                 mock.patch.object(a1, "_verify_std_overlay", side_effect=[overlay, overlay]), \
                 mock.patch.object(a1, "execute", return_value=synthetic_exec), \
                 mock.patch.object(a1.origin, "runtime_inventory", return_value={}), \
                 mock.patch.object(a1, "parse_export", return_value={"state": "UNVALIDATED_JSON_OBJECT_UNKNOWN", "outcome": "UNKNOWN"}):
                result = a1.run(root, "sel1", "r1", row["id"], binary, out, std)
            self.assertEqual(result["postprocessing_state"], "COMPLETE")
            self.assertTrue(result["post_run_validation"]["source_valid"])
            self.assertTrue(result["post_run_validation"]["std_base_valid"])
            self.assertIsNone(result["input_abs_path"])


class ArtifactTests(unittest.TestCase):
    def test_artifact_trimming_preserves_receipt_and_marks_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root / "receipt.json").write_text(json.dumps({"outcome": "UNKNOWN", "postprocessing_state": "COMPLETE"}))
            (root / "big.bin").write_bytes(b"x"*1024)
            with mock.patch.object(a1, "JOB_OUTPUT_LIMIT", 512):
                result = a1.bound_artifacts(root)
            self.assertEqual(result["state"], "TRUNCATED")
            self.assertTrue((root / "receipt.json").is_file())
            self.assertFalse((root / "big.bin").exists())
            receipt = json.loads((root / "receipt.json").read_text())
            self.assertEqual(receipt["postprocessing_state"], "INCOMPLETE")


if __name__ == "__main__":
    unittest.main()
