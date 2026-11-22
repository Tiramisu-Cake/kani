# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import campaign as c
import evidence
import observations as o
import request as r
from test_evidence import export_document


def request():
    result = dict(r.FIXED)
    result["tool_files"] = {r.FIXTURE: hashlib.sha256(b"fixture bytes").hexdigest()}
    return result


class CampaignTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.checkouts = {key: self.tmp / key for key in r.PINS}
        for path in self.checkouts.values():
            path.mkdir()
        source = self.checkouts["tool"] / r.FIXTURE
        source.parent.mkdir(parents=True)
        source.write_bytes(b"fixture bytes")
        self.out = self.tmp / "out"

    def test_manifest_order_two_pins_flags_and_fresh_paths(self):
        ids = [case["id"] for case in r.ROOTS]
        self.assertEqual(ids[:2], ["positive", "negative"])
        labels = ["S2", "UF2", "N18", "M8-C", "M8-R", "S2-C", "F2-C"]
        self.assertEqual(ids[2:], [f"{pin}-{label}-{mode}" for pin, roster in
                                  (("candidate", labels), ("pr752", labels[:5]))
                                  for label in roster for mode in ("off", "on")])
        self.assertEqual(sum(x["wall_seconds"] for x in r.ROOTS), 7920)
        self.assertEqual(r.LIMITS["memory_reserve_kib"], c.pilot.stock_runner.MEMORY_RESERVE_KIB)
        prepared = [c.prepare(self.out, root, self.checkouts, request()) for root in r.ROOTS]
        self.assertEqual(len({i["cwd"] for i in prepared}), 26)
        for item, case in zip(prepared, r.ROOTS):
            argv = item["argv"]
            self.assertEqual(argv.count("--harness"), 1)
            self.assertEqual(argv[argv.index("--harness") + 1], case["selector"])
            self.assertEqual(argv[argv.index("--harness-timeout") + 1], f"{case['harness_seconds']}s")
            self.assertEqual(argv[-3:], ["--cbmc-args", "--object-bits", "12"])
            self.assertEqual(argv.count("uninit-checks"), int(case["uninit"]))
            for key in r.FIXED["environment_unset"]:
                self.assertIsNone(item["environment"][key])
            if case["pin"] == "tool":
                self.assertEqual(argv[1], "main.rs")
                self.assertIn("--default-unwind", argv)
                self.assertEqual(item["fixture"], request()["tool_files"][r.FIXTURE])
                self.assertNotIn("--target-dir", argv)
            else:
                self.assertIn(str(self.checkouts[case["pin"]] / "library"), argv)
                self.assertIn("--no-assert-contracts", argv)
                self.assertNotIn("--default-unwind", argv)
        for off, on in zip(prepared[2::2], prepared[3::2]):
            def normalized(item):
                return [arg.replace(item["cwd"], "/private") for arg in item["argv"]]
            a, b = normalized(off), normalized(on)
            i = b.index("uninit-checks")
            self.assertEqual(a, b[:i - 1] + b[i + 1:])

    def run_child(self, name, code, seconds=3, rss=8 * 1024 * 1024, capture_cap=1024):
        root = r.ROOTS[0] | {"id": name}
        work = c.prepare(self.out, root, self.checkouts, request())
        work.update(argv=[sys.executable, "-c", code], timeout_seconds=seconds,
                    phase_deadline_monotonic=time.monotonic() + seconds + r.LIMITS["child_cleanup_seconds"] + 1)
        Path(work["cwd"]).mkdir(parents=True)
        journal = self.out / "state" / name
        limits = r.LIMITS | {"local_rss_kib": rss, "stdout_bytes_per_root": capture_cap}
        with patch.object(c.pilot.stock_runner, "group_memory_budget",
                          return_value={"group_cap_kib": 12 * 1024 * 1024}):
            receipt = c.execute_root(journal, work, limits)
        self.assertIs(receipt["child_shutdown_verified"], True, receipt)
        self.assertFalse(c.pilot.stock_runner._group_has_live_members(receipt["started"]["pid"]))
        return work, receipt

    def test_deliberate_nonzero_then_positive_and_verified_reap(self):
        _, negative = self.run_child("negative", "raise SystemExit(1)")
        _, positive = self.run_child("positive", "raise SystemExit(0)")
        self.assertEqual((negative["original_exit_code"], positive["original_exit_code"]), (1, 0))
        self.assertIsNone(negative["termination_reason"])

    def test_timeout_and_rss_then_another_child(self):
        _, timed = self.run_child("timed", "import time; time.sleep(20)", seconds=.15)
        _, rss = self.run_child("rss", "import time; x = bytearray(32*1024*1024); time.sleep(20)", rss=20*1024)
        _, last = self.run_child("later", "print('next case')")
        self.assertEqual(timed["termination_reason"], "timeout")
        self.assertEqual(rss["termination_reason"], "rss_cap")
        self.assertEqual(last["original_exit_code"], 0)

    def test_short_output_preserves_head_and_terminal_tail_at_exact_offsets(self):
        head = b"error[E0557]: feature has been removed\n"
        end = b"\nVERIFICATION:- FAILED\n"
        data = head + b"x" * 700 + end
        work, child = self.run_child("truncated", f"import os; os.write(1, {data!r})", capture_cap=128)
        captured = c.capture(Path(work["paths"]["execution"]) / "stdout.log", 128,
                             child["stdout_bytes"], child["stdout_truncated"], tail=True)
        result = o.native({"stdout": captured, "stderr": (None, {})})
        self.assertEqual(result["diagnostics"][0]["code"], "E0557")
        marker = result["markers"]["harness_terminal"]
        self.assertEqual(marker["source_coordinate"]["byte_start"], len(data) - len(end) + 1)
        self.assertEqual(marker["text"], "VERIFICATION:- FAILED")
        self.assertIsNone(marker["source_coordinate"]["line"])
        self.assertTrue(captured[1]["truncated"])
        self.assertEqual(captured[1]["layout"], "PREFIX_AND_TAIL")

    def test_confirmed_older_compiler_incompatibility_requires_source_and_cargo_failure(self):
        root = r.ROOTS[16]
        self.assertEqual(root["id"], "pr752-S2-off")
        source = self.checkouts["pr752"]
        lib = source / "library/core/src/lib.rs"
        lib.parent.mkdir(parents=True)
        lib.touch()
        captures = {"stdout": (None, {}), "stderr": (f"error[E0557]: feature has been removed\n"
                    f" --> {source}/library/core/src/lib.rs:28:1\n"
                    "error: Failed to execute cargo (exit status: 101). Found 1 compilation errors.\n".encode(),
                    {"truncated": False, "cap_bytes": 4096, "observed_bytes": 200})}
        native = o.native(captures)
        result = o.blocker(root, native, {"original_exit_code": 1}, source)
        self.assertEqual(result["scope"], "pr752")
        self.assertEqual(result["diagnostic"]["code"], "E0557")
        self.assertIsNone(o.blocker(root | {"uninit": True}, native, {"original_exit_code": 1}, source))
        self.assertIsNone(o.blocker(root, native, {"original_exit_code": 0}, source))
        self.assertIsNone(o.blocker(root, native, {"original_exit_code": 1, "termination_reason": "timeout"}, source))

    def test_sequence_scopes_not_run_and_keeps_canary_order(self):
        record = {"receipt": {"status": "COMPLETE"}}
        seen = []
        def supervise(repo, out, _paths, _request, root, *_args):
            seen.append(root["id"])
            if root["id"] == "pr752-S2-off":
                c.pilot.atomic(out / "state" / root["id"] / "observation-summary.json",
                               {"shared_blocker": {"scope": "pr752", "reason": "STD_TREE_COMPILER_INCOMPATIBILITY"}})
            return True
        receipt = self.tmp / "receipt"
        epoch = self.tmp / "epoch"
        epoch.write_text(str(time.monotonic()))
        with (patch.object(c, "load_request", return_value=request()),
              patch.object(c, "validate_control", return_value={"checked": True}),
              patch.object(c.pilot, "digest", return_value="sha"),
              patch.object(c, "validate_inputs", return_value={}),
              patch.object(c, "read_attestation", return_value=record),
              patch.object(c.tool_attestation, "verify"),
              patch.object(c.pilot, "setup_ready", return_value=True),
              patch.object(c, "supervise_root", side_effect=supervise)):
            self.assertEqual(c.campaign(self.tmp / "repo", self.checkouts, self.out, receipt, receipt, epoch), 0)
        self.assertEqual(seen, [row["id"] for row in r.ROOTS[:17]])
        for row in r.ROOTS[17:]:
            not_run = c.pilot.read_record(self.out / "state" / row["id"] / "not_run.json")
            self.assertEqual(not_run["blocker"]["root"], "pr752-S2-off")

    def test_setup_failure_finalization_and_aggregate_cutoff_keep_index(self):
        repo = self.tmp / "repo"
        repo.mkdir()
        missing = self.tmp / "missing"
        for limit, pairs in ((r.LIMITS["artifact_bytes"], 12), (8192, 0)):
            out = self.tmp / f"out-{limit}"
            manifest = request() | {"limits": r.LIMITS | {"artifact_bytes": limit}}
            with patch.dict(os.environ, {"BUILD_OUTCOME": "failure"}), patch.object(c, "load_request", return_value=manifest):
                index = c.finish(repo, self.checkouts, out, missing, missing, missing)
            self.assertEqual(len(index["roots"]), 26)
            self.assertTrue(all(row["status"] == "NOT_RUN" for row in index["roots"]))
            self.assertEqual(len(list((out / "artifact" / "pairs").glob("*.json"))), pairs)
            self.assertLessEqual(sum(f.stat().st_size for f in (out / "artifact").rglob("*") if f.is_file()), limit)

    def test_copy_and_outer_rss_reap_then_next_worker(self):
        repo = self.tmp / "repo"
        worker = repo / r.ENTRYPOINT
        worker.parent.mkdir(parents=True)
        worker.write_text(
            "import json, sys, time\nfrom pathlib import Path\n"
            "row = json.loads((Path(sys.argv[sys.argv.index('--journal') + 1])"
            " / 'prepared.json').read_text())\n"
            "assert (Path(row['cwd']) / 'main.rs').read_bytes() == b'fixture bytes'\n"
            "if row['root']['id'] == 'positive':\n"
            "    allocation = bytearray(36 * 1024 * 1024)\n"
            "    time.sleep(20)\n"
        )
        manifest = request()
        manifest["limits"] = r.LIMITS | {"outer_rss_kib": 20 * 1024}
        tool_receipt = {"binaries": {"kani_compiler": {"path": "/fake/compiler"}},
                        "rustc_release": "fake", "rust_toolchain": {}}
        with patch.object(c.pilot.stock_runner, "group_memory_budget",
                          return_value={"group_cap_kib": 21 * 1024}):
            for root in r.ROOTS[:2]:
                self.assertTrue(c.supervise_root(repo, self.out, self.checkouts, manifest,
                                                root, {"verification_end_monotonic": time.monotonic() + 300},
                                                self.tmp / "setup", tool_receipt))
        positive, negative = (c.pilot.read_record(self.out / "state" / case / "supervisor.json")
                              for case in ("positive", "negative"))
        self.assertEqual(positive["cutoff"], "outer_sampled_rss")
        self.assertEqual(positive["rss_cap_kib"], 20 * 1024)
        self.assertIsNone(negative["cutoff"])
        self.assertEqual(negative["worker_exit"], 0)
        self.assertEqual(list((self.out / "work").iterdir()), [])

    def test_supervisor_budgets_full_child_watchdogs_and_refuses_short_launches(self):
        manifest = request()
        limits = manifest["limits"]
        job_spare = (limits["job_minutes"] * 60 - limits["setup_and_build_seconds"]
                     - limits["job_cleanup_upload_seconds"] - limits["child_wall_sum_seconds"])
        self.assertEqual(job_spare, 540)
        self.assertEqual(job_spare - 26 * (3 + 6 + 8) - 30, 68)

        tool_receipt = {"binaries": {"kani_compiler": {"path": "/fake/compiler"}},
                        "rustc_release": "fake", "rust_toolchain": {}}
        roots = {root["wall_seconds"]: root for root in r.ROOTS}
        cases = [
            ("canary", 120, 90, .5, 2, None),
            ("std", 300, 240, .5, 2, None),
            ("n18", 420, 360, .5, 2, None),
            ("early-refusal", 120, 90, -.5, 2, "no preparation"),
            ("after-preparation", 300, 240, .25, 2, "JOB_LAUNCH_BUDGET_EXHAUSTED"),
            ("late-worker", 420, 360, .5, 3, "ROOT_WINDOW_UNAVAILABLE_BEFORE_CHILD"),
        ]
        for name, wall, harness, preparation, startup, refusal in cases:
            with self.subTest(case=name):
                root = roots[wall] | {"id": name}
                journal = self.out / "state" / name
                start = 1000
                boundary = {"verification_end_monotonic": start + preparation + wall + 3 + 6 + 8 + 30}

                def memory_budget():
                    clock.return_value += .5
                    return {"group_cap_kib": 12 * 1024 * 1024}

                def run_worker(argv, *_):
                    clock.return_value += startup
                    worker_journal = Path(argv[argv.index("--journal") + 1])
                    worker_exit = c.worker(worker_journal, manifest, tool_receipt)
                    return {"worker_exit": worker_exit, "containment": {"verified": True}}

                with (patch.object(c.time, "monotonic", return_value=start) as clock,
                      patch.object(c.pilot.stock_runner, "group_memory_budget", side_effect=memory_budget),
                      patch.object(c.pilot.s3_runtime, "supervise", side_effect=run_worker) as outer,
                      patch.object(c.pilot.stock_runner, "execute", return_value={"child_shutdown_verified": True}) as execute,
                      patch.object(c, "project")):
                    result = c.supervise_root(self.tmp / "repo", self.out, self.checkouts, manifest,
                                              root, boundary, self.tmp / "setup", tool_receipt)
                if refusal:
                    execute.assert_not_called()
                    if refusal == "ROOT_WINDOW_UNAVAILABLE_BEFORE_CHILD":
                        self.assertIs(result, True)
                        outer.assert_called_once()
                    else:
                        self.assertIsNone(result)
                        outer.assert_not_called()
                    if refusal == "no preparation":
                        self.assertFalse(journal.exists())
                    else:
                        not_run = c.pilot.read_record(journal / "not_run.json")
                        self.assertEqual((not_run["state"], not_run["reason"]), ("NOT_RUN", refusal))
                    continue

                self.assertIs(result, True)
                execute.assert_called_once()
                argv, _, _, seconds = execute.call_args.args
                self.assertEqual(seconds, wall)
                self.assertEqual(argv[argv.index("--harness-timeout") + 1], f"{harness}s")
                self.assertEqual(outer.call_args.args[3], wall + 3 + 6)
                prepared = c.pilot.read_record(journal / "prepared.json")
                self.assertEqual(prepared["root_deadline_monotonic"], boundary["verification_end_monotonic"] - 30)
                self.assertEqual(prepared["root_deadline_monotonic"] - prepared["phase_deadline_monotonic"], 8)

    def test_missing_and_truncated_capture_are_incomplete(self):
        prepared = c.prepare(self.out, r.ROOTS[0], self.checkouts, request())
        journal = self.out / "state" / "positive"
        Path(prepared["paths"]["execution"]).mkdir(parents=True)
        child = {"child_shutdown_verified": True, "stdout_bytes": 0, "stdout_truncated": True}
        (Path(prepared["paths"]["execution"]) / "stdout.log").write_bytes(b"")
        c.project(journal, prepared, request(), {}, child)
        entries = c.pilot.read_record(journal / "files.json")
        self.assertEqual(entries["regular"]["reason"], "SOURCE_TRUNCATED_OR_UNCONFIRMED")
        self.assertEqual(entries["stock"]["reason"], "FILE_MISSING")


class NativeTests(unittest.TestCase):
    def test_bcdc_native_canary_and_unreachable_unsupported_inventory(self):
        root = r.ROOTS[1]
        pin = r.PINS["tool"]["sha"]
        entries = [
            ("main::buffer_partly_written_ub.safety_check.1", "safety_check", "FAILURE",
             "Undefined Behavior: Reading from an uninitialized pointer of type `*const u32`"),
            ("core::ptr::read.safety_check.9", "safety_check", "FAILURE",
             "Undefined Behavior: Reading from an uninitialized pointer of type `u32`"),
            ("main::buffer_partly_written_ub.assertion.1", "assertion", "SUCCESS", "success"),
            ("core::ptr::read.assertion.2", "assertion", "UNKNOWN", "unresolved after prior UB"),
        ]
        for unsupported in (False, True):
            props = entries + ([("core::ptr::read.unsupported_construct.3", "unsupported_construct",
                                 "UNREACHABLE", "Unions nested inside unions")] if unsupported else [])
            output = [f"Checking harness {root['selector']}...", "", "RESULTS:"]
            stock_props = []
            for i, (prop_id, cls, status, desc) in enumerate(props, 1):
                output.extend([f"Check {i}: {prop_id}", f"\t - Status: {'UNDETERMINED' if status == 'UNKNOWN' else status}", f'\t - Description: "{desc}"',
                               "\t - Location: main.rs:52:24 in function buffer_partly_written_ub", ""])
                stock_props.append({"id": prop_id, "class": cls, "status": status, "description": desc,
                                    "file": "main.rs", "line": "52", "trace_available": status == "FAILURE"})
            output.extend(["SUMMARY:", f" ** 2 of {len(props)} failed", "VERIFICATION:- FAILED", ""])
            stock = export_document()
            stock.update(kani_commit=pin, enabled_unstable_features=["uninit-checks", "unstable-options", "export-json"],
                         harness_timeout_s=90, harness_selection={"requested_filters": [root["selector"]],
                         "exact": True, "unmatched_filters": [], "matched_count": 1})
            stock["tools"]["rustc"] = "pinned-rustc"
            item = stock["harnesses"][0]
            item.update(name=root["selector"], resolved_unwind=8, n_properties=len(props), n_failed=2,
                        failed_properties=stock_props[:2], unsupported_constructs=stock_props[4:])
            item["checks"].update(total=len(props), success=1, failure=[p["id"] for p in stock_props[:2]],
                                  unreachable=[p["id"] for p in stock_props[4:]], unknown=[stock_props[3]["id"]])
            item["covers"].update(total=0, satisfied=[])
            stock["summary"].update(checks_total=len(props), checks_success=1, covers_total=0, covers_satisfied=0)
            regular = evidence.regular("\n".join(output).encode(), root["selector"])
            exported = evidence.stock_export(json.dumps(stock).encode(), root["selector"])
            self.assertEqual(exported["state"], "COMPLETE", exported)
            joined = o.reconcile(regular, exported, root, request(), "pinned-rustc", 1)
            self.assertEqual(joined["state"], "CONSISTENT", joined)
            self.assertEqual(joined["calibration"]["state"], "INCOMPLETE" if unsupported else "MATCH")
            self.assertEqual(len(joined["unsupported"]), int(unsupported))
            self.assertEqual(len(joined["uninit_reads"]), 2)
            self.assertEqual(joined["native_property_counts"]["checks.success"], 1)
