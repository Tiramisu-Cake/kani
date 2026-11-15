# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Synthetic observer tests; these never run Cargo, Kani, CBMC, or setup."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from receipt import (FROZEN_SHA, FROZEN_TREE, MARK, STAGES, capture_process, identify,
                     run_child, self_test, summarize, validate_observer_binding)

HERE = Path(__file__).resolve().parent
SOURCE = "/checkout/scripts/kani-regression.sh"
REAL_BINDING = json.loads((HERE / "binding.json").read_text(encoding="utf-8"))


def binding():
    return copy.deepcopy(REAL_BINDING)


def event(stage=None, rc=0, kind="DEBUG", source=SOURCE, command_text=None, line=None, suite=None, mode=None):
    stage_info = next((x for x in REAL_BINDING["stages"] if x["id"] == stage), {})
    command_text = command_text if command_text is not None else stage_info.get("command", "echo synthetic")
    line = line if line is not None else stage_info.get("line", 1)
    suite = suite if suite is not None else (stage.split(":", 1)[1] if stage and stage.startswith("suite:") else "")
    mode = mode if mode is not None else stage_info.get("mode", "")
    fields = (kind, rc, source, line, command_text, suite, mode, 5, 101)
    return MARK + b"\0".join(str(value).encode("utf-8") for value in fields) + b"\0"


class ReceiptTests(unittest.TestCase):
    def test_full_33_stage_stream_is_complete_and_ordered(self):
        data = bytearray()
        summary = b"test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        for stage in STAGES:
            data += event(stage, mode="exec" if stage in STAGES[-4:] else None)
            if stage.startswith(("suite:", "unit:")):
                data += summary
        data += event(kind="EXIT", command_text="exit")
        result = summarize(bytes(data), 0, binding=REAL_BINDING)
        self.assertEqual(result["status"], "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW")
        self.assertEqual(result["stage_order_seen"], STAGES)
        self.assertEqual(len(result["stages"]), 33)
        self.assertEqual(result["formal_proof_credit"], "NOT_ESTABLISHED")
        self.assertEqual(result["stages"]["warnings-build"]["mode"], "")
        self.assertEqual(result["stages"]["warnings-build"]["observed_mode"], "exec")

    def test_full_33_stage_shell_observer_end_to_end_without_toolchain(self):
        with tempfile.TemporaryDirectory(prefix="kani-gatea-full-shell-") as temp:
            root = Path(temp)
            scripts = root / "scripts"
            scripts.mkdir()
            lines = [":"] * 126
            lines[0] = "#!/usr/bin/env bash"
            lines[1] = "set -e"
            lines[2:7] = [
                "cargo() {",
                "  case ${1-} in test|run) printf 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\\n' ;; esac",
                "  return 0",
                "}",
                "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"",
            ]
            for stage in REAL_BINDING["stages"]:
                if not stage["id"].startswith("suite:"):
                    command = stage["command"]
                    if stage["id"] == "firecracker-codegen":
                        command = 'time "$SCRIPT_DIR"/codegen-firecracker.sh'
                    lines[stage["line"] - 1] = command
            suite_pairs = [(x["id"].split(":", 1)[1], x["mode"]) for x in REAL_BINDING["stages"] if x["id"].startswith("suite:")]
            lines[89] = "TESTS=( " + " ".join('"%s %s"' % pair for pair in suite_pairs) + " )"
            lines[94] = "timeout_secs=2400"
            lines[95] = 'for testp in "${TESTS[@]}"; do'
            lines[96] = "  testl=($testp); suite=${testl[0]}; mode=${testl[1]}"
            lines[97] = REAL_BINDING["stages"][14]["command"]
            lines[98] = "done"
            # Stubs are shell-only; no compiler or verifier binary can be reached.
            for name in ("check-cbmc-version.py", "check_kissat_version.sh"):
                stub = scripts / name
                stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                stub.chmod(0o755)
            for name in ("kani-fmt.sh", "codegen-firecracker.sh"):
                stub = scripts / name
                stub.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                stub.chmod(0o755)
            source = scripts / "kani-regression.sh"
            source.write_text("\n".join(lines) + "\n", encoding="utf-8")
            hook = root / "observe.bash"
            from receipt import HOOK
            hook.write_text(HOOK, encoding="utf-8")
            log = root / "events.log"
            env = dict(os.environ, BASH_ENV=str(hook), PATH=str(scripts) + os.pathsep + os.environ.get("PATH", ""))
            env.pop("KANI_GATE_OWNER_PID", None)
            captured = capture_process(["bash", "scripts/kani-regression.sh"], root, env,
                                       10, log, output_cap=4 * 1024 * 1024, grace_seconds=0.2)
            self.assertEqual(captured["returncode"], 0)
            self.assertIsNone(captured["termination"])
            result = summarize(log.read_bytes(), captured["returncode"], captured["termination"],
                               captured["truncated"], REAL_BINDING)
            self.assertEqual(result["status"], "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW", result["problems"])
            self.assertEqual(result["stage_order_seen"], STAGES)
            self.assertTrue(result["event_complete"])

    def test_original_nonzero_exit_and_last_stage_status_are_retained(self):
        data = event("build-dev") + b"build error\n" + event(kind="EXIT", rc=37, command_text="exit")
        result = summarize(data, 37, binding=REAL_BINDING)
        self.assertEqual(result["script_exit"], 37)
        self.assertEqual(result["stages"]["build-dev"]["exit"], 37)
        self.assertEqual(result["stages"]["suite:kani"]["status"], "NOT_RUN")
        self.assertEqual(result["script_exit_kind"], "EXIT")
        self.assertIsNone(result["script_exit_signal"])
        self.assertNotEqual(result["status"], "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW")

    def test_missing_repeated_and_out_of_order_stage_rejected(self):
        complete = bytearray()
        summary = b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        for stage in STAGES:
            complete += event(stage)
            if stage.startswith(("suite:", "unit:")):
                complete += summary
        complete += event(kind="EXIT")
        cases = [bytes(complete).replace(event("unit:kani-driver"), b"", 1),
                 event("build-dev") + bytes(complete),
                 event("kissat") + event("cbmc") + bytes(complete)]
        for data in cases:
            self.assertNotEqual(summarize(data, 0, binding=REAL_BINDING)["status"],
                                "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW")

    def test_missing_failed_and_overflow_counts_rejected(self):
        data = bytearray()
        for stage in STAGES:
            data += event(stage)
            if stage.startswith(("suite:", "unit:")):
                data += b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n"
        data += event(kind="EXIT")
        no_counts = bytes(data).replace(b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n", b"no summary\n", 1)
        failed = bytes(data).replace(b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out", b"test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out", 1)
        overflow = bytes(data).replace(b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n", (b"test result: " + b"x" * 4100 + b"\n"), 1)
        filtered = bytes(data).replace(b"0 filtered out", b"1 filtered out", 1)
        for candidate in (no_counts, failed, overflow, filtered):
            self.assertNotEqual(summarize(candidate, 0, binding=REAL_BINDING)["status"],
                                "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW")
        self.assertIn("unit:cprover_bindings:filtered-count-nonzero",
                      summarize(filtered, 0, binding=REAL_BINDING)["problems"])

    def test_timeout_signal_and_output_truncation_are_incomplete(self):
        partial = event("build-dev")
        for rc, termination in ((-15, {"kind": "TIMEOUT"}), (-9, {"kind": "PARENT_SIGNAL", "signal": 15})):
            result = summarize(partial, rc, termination, binding=REAL_BINDING)
            self.assertEqual(result["termination"], termination)
            self.assertEqual(result["script_exit"], rc)
            self.assertEqual(result["script_exit_kind"], "SIGNAL")
            self.assertNotEqual(result["status"], "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW")
        result = summarize(partial, -15, {"kind": "OUTPUT_CAP"}, truncated=True, binding=REAL_BINDING)
        self.assertFalse(result["event_complete"])
        self.assertIn("output-cap-truncated", result["problems"])

    def test_command_line_mode_and_exit_trace_are_bound(self):
        wrongs = ((event("build-dev", command_text="cargo build-dev --verbose"), "build-dev:command-mismatch"),
                  (event("build-dev", line=999), "build-dev:source-line-mismatch"),
                  (event("suite:ui", mode="kani"), "suite:ui:mode-mismatch"))
        for bad, expected_problem in wrongs:
            data = bad + event(kind="EXIT", command_text="exit")
            result = summarize(data, 0, binding=REAL_BINDING)
            self.assertIn(expected_problem, result["problems"])
        proper = event("build-dev") + event(kind="EXIT", command_text="exit")
        for trace in (proper[:-len(event(kind="EXIT", command_text="exit"))],
                      proper + event(kind="DEBUG", command_text="echo too late"),
                      event("build-dev") + event(kind="EXIT", rc=3, command_text="exit")):
            result = summarize(trace, 0, binding=REAL_BINDING)
            self.assertFalse(result["event_complete"])
            self.assertNotEqual(result["status"], "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW")

    def test_setup_only_failure_has_no_regression_success(self):
        result = summarize(b"setup failed before regression\n", 1, binding=REAL_BINDING)
        self.assertEqual(result["stage_order_seen"], [])
        self.assertEqual(result["stages"]["cbmc"]["status"], "NOT_RUN")
        self.assertNotEqual(result["status"], "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW")

    def test_existing_partial_receipt_is_preserved(self):
        with tempfile.TemporaryDirectory(prefix="kani-gatea-existing-receipt-") as temp:
            path = Path(temp) / "receipt.json"
            path.write_text('{"status":"PARTIAL"}\n', encoding="utf-8")
            self.assertEqual(run_child(HERE / "binding.json", temp, 10), 2)
            self.assertEqual(path.read_text(encoding="utf-8"), '{"status":"PARTIAL"}\n')

    def test_exclusive_starting_receipt_is_valid_before_capture(self):
        with tempfile.TemporaryDirectory(prefix="kani-gatea-starting-receipt-") as temp:
            path = Path(temp) / "receipt.json"
            observed = {}

            def stop_before_capture(*_args, **_kwargs):
                observed.update(json.loads(path.read_text(encoding="utf-8")))
                raise RuntimeError("synthetic controller interruption")

            env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "Tiramisu-Cake/kani"}
            with mock.patch.dict(os.environ, env, clear=True), \
                 mock.patch("receipt.capture_process", side_effect=stop_before_capture):
                self.assertEqual(run_child(HERE / "binding.json", temp, 10), 2)
            self.assertEqual(observed["status"], "INCOMPLETE_OBSERVER_STARTING")
            self.assertIsNone(observed["script_exit"])
            self.assertIn("observer-process-not-yet-started", observed["problems"])
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["status"], "NOT_RUN")

    def test_binding_rejects_wrong_sha_tree_and_stage_contract(self):
        validate_observer_binding(binding())
        for key, value in (("export_sha", "0" * 40), ("export_tree", "1" * 40)):
            wrong = binding()
            wrong[key] = value
            with self.assertRaises(ValueError):
                validate_observer_binding(wrong)
        wrong = binding()
        wrong["stages"] = wrong["stages"][1:]
        with self.assertRaises(ValueError):
            validate_observer_binding(wrong)
        self.assertEqual(REAL_BINDING["export_sha"], FROZEN_SHA)
        self.assertEqual(REAL_BINDING["export_tree"], FROZEN_TREE)

    def test_classifier_matches_all_bound_stage_commands(self):
        for item in REAL_BINDING["stages"]:
            # Use actual stage command shape, with the loop variables bound from the map.
            suite = item["id"].split(":", 1)[1] if item["id"].startswith("suite:") else ""
            self.assertEqual(identify(item["command"], suite, item["mode"]), item["id"])

    def test_real_bash_env_hook_success_failure_exit_order_and_child_guard(self):
        result = self_test()
        self.assertEqual(result["status"], "PASS")
        self.assertIn("child-not-instrumented", result["coverage"])

    def test_process_controller_timeout_signal_and_output_cap(self):
        with tempfile.TemporaryDirectory(prefix="kani-gatea-capture-") as temp:
            root = Path(temp)
            cap_path = root / "cap.log"
            writer = "import os,time; os.write(1,b'x'*1000000); time.sleep(5)"
            capped = capture_process([sys.executable, "-c", writer], root, os.environ.copy(),
                                     3, cap_path, output_cap=1024, grace_seconds=0.1)
            self.assertEqual(capped["termination"]["kind"], "OUTPUT_CAP")
            self.assertTrue(capped["truncated"])
            self.assertLessEqual(capped["bytes"], 1024)
            self.assertIsNotNone(capped["returncode"])

            marker = root / "late-child-marker"
            timeout_path = root / "timeout.log"
            child_code = "import time,pathlib; time.sleep(.7); pathlib.Path(%r).write_text('late')" % str(marker)
            parent_code = "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',%r]); time.sleep(5)" % child_code
            timed = capture_process([sys.executable, "-c", parent_code], root, os.environ.copy(),
                                    0.15, timeout_path, output_cap=4096, grace_seconds=0.1)
            self.assertEqual(timed["termination"]["kind"], "TIMEOUT")
            time.sleep(0.8)
            self.assertFalse(marker.exists(), "timeout left a process-group descendant running")

            signal_path = root / "signal.log"
            timer = threading.Timer(0.15, os.kill, args=(os.getpid(), 15))
            timer.start()
            signaled = capture_process([sys.executable, "-c", "import time; time.sleep(5)"], root,
                                       os.environ.copy(), 3, signal_path, output_cap=4096,
                                       install_signal_handlers=True, grace_seconds=0.1)
            timer.join()
            self.assertEqual(signaled["termination"]["kind"], "PARENT_SIGNAL")
            self.assertEqual(signaled["termination"]["signal"], 15)


if __name__ == "__main__":
    unittest.main()
