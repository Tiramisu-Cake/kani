"""Bounded collection tests using temporary Git checkouts and tiny Python children."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import run as pilot


# Exercise sequencing and fallback across multiple roots independently of the frozen roster.
SYNTHETIC_ROOTS = [
    {"id": rid, "selector": pilot.PREFIX + selector, "cfg": cfg,
     "object_bits": 12, "cbmc_args": ["--refine-arrays"] if rid == "P-2" else [],
     "timeout_seconds": 600}
    for rid, selector, cfg in (
        ("P-1", "sorting_q_pilot::p1_swap_u8_v34_q_any", "merge_a"),
        ("P-2", "sorting_q_pilot::p2_sort13_u8_b01_len17_q_any", "merge_a"),
        ("P-3", "sorting_q_pilot::p3_insert_u8_b01_rel1_16_q_any", "merge_a"),
        ("P-4", "sorting_q_pilot::p4_network_u8_b01_n17_q_any", "merge_a"),
        ("P-5a", "sorting_q_controls::p5_swap_false_or_q_any", "merge_b"),
        ("P-5b", "sorting_q_controls::p5_swap_false_or_q_fixed0", "merge_b"),
        ("P-5c", "sorting_q_controls::p5_network_n17_qpost_corrupt", "merge_a"),
    )
]

FAKE_TOOL = '''import json, os, sys
from pathlib import Path

args = sys.argv[1:]
selector = args[args.index("--harness") + 1].split("::")[-1]
export = Path(args[args.index("--export-json") + 1])
Path(args[args.index("--target-dir") + 1]).mkdir()
Path(os.environ["CARGO_TARGET_DIR"]).mkdir()
print(json.dumps({"args": args, "env": dict(os.environ)}))
for prefix, payload, exit_code in (
    ("p1_", b"{broken", 7), ("p2_", None, 11),
    ("p3_", b"null", 0), ("p4_", b"17", 0),
    ("p5_swap_false_or_q_any", b'{"run_state":"INCOMPLETE"}', 1),
    ("p5_swap_false_or_q_fixed0", b'{"run_state":"PARTIAL"}', 0),
    ("p5_network", b'{"run_state":"COMPLETE"}', 1),
):
    if selector.startswith(prefix):
        if payload is not None:
            export.write_bytes(payload)
        sys.exit(exit_code)
if selector in {
    "mw_network_n25", "mw_network_n25_corrupt",
    "compact_network_n25", "compact_network_n25_corrupt",
    "compact_network_n20", "compact_network_n20_corrupt",
    "compact_network_n20_actual_insert",
    "mw_insert_left_literal_rel9", "mw_insert_left_literal_rel10", "mw_insert_left_literal_rel11",
    "nm_sort13_left_len17",
    "p3_insert_u8_b01_rel1_16_q_any", "nm_network_n13", "nm_network_n14",
    "nm_network_n15", "nm_network_n16", "nm_network_n17",
    "nm_network_n13_corrupt", "nm_network_n17_corrupt",
}:
    export.write_bytes(b'{"synthetic":true}')
    sys.exit(int(selector in {"mw_network_n25_corrupt", "compact_network_n25_corrupt",
                              "compact_network_n20_corrupt", "nm_network_n13_corrupt",
                              "nm_network_n17_corrupt"}))
sys.exit(90)
'''


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.base = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.std, self.tool, self.repo, self.out = (
            self.base / name for name in ("std", "tool", "control", "out")
        )
        self.request = {
            "std_files": {}, "source_root": "library", "cfg": pilot.CFG, "argv": pilot.ARGV,
            "roots": [root.copy() for root in SYNTHETIC_ROOTS],
            "limits": pilot.LIMITS.copy(), "result_schema": pilot.SCHEMA,
            "event_ref": pilot.EVENT_REF,
        }
        self.memory = {"group_cap_kib": 128 * 1024}
        self.enterContext(patch.object(pilot.stock_runner, "group_memory_budget", return_value=self.memory))
        self.enterContext(patch.object(pilot, "load_request", return_value=self.request))
        # Use an isolated Git configuration and avoid site hooks in all synthetic repos.
        self.enterContext(patch.dict(os.environ, {
            "HOME": str(self.base), "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Synthetic", "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
            "GIT_COMMITTER_NAME": "Synthetic", "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
            "RUSTFLAGS": "INHERITED_RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS": "INHERITED_ENCODED",
            "CARGO_BUILD_RUSTFLAGS": "INHERITED_CARGO_BUILD_FLAGS",
            "KANI_FLAGS": "INHERITED_KANI_FLAGS", "RUSTC_WRAPPER": "INHERITED_WRAPPER",
            "CARGO_TARGET_DIR": str(self.base / "shared"),
            "GITHUB_REPOSITORY": "Tiramisu-Cake/kani", "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": pilot.EVENT_REF, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "synthetic",
            "CONTROL_OUTCOME": "", "SOURCE_OUTCOME": "", "SETUP_OUTCOME": "",
            "BUILD_OUTCOME": "", "COLLECTION_OUTCOME": "",
        }))
        for path in (self.std, self.tool, self.repo):
            path.mkdir()
            self.git(path, "init", "--quiet")
        for rel in pilot.STD_FILES:
            path = self.std / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(rel + "\n")
            self.request["std_files"][rel] = pilot.digest(path)
        self.commit(self.std)
        self.pin("std", self.std)
        self.write_tool(FAKE_TOOL)
        self.git(self.repo, "commit", "--quiet", "--allow-empty", "-m", "synthetic parent")
        self.request["control_parent"] = pilot.git(self.repo, "rev-parse", "HEAD")

        self.setup_receipt = self.base / "setup-receipt.json"
        self.setup_receipt.write_text(json.dumps({
            "original_exit_code": 0, "child_shutdown_verified": True, "setup_total_seconds": 2,
        }))
        self.epoch = self.base / "epoch"
        self.epoch.write_text(str(time.monotonic()))

    def git(self, repo, *args):
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(repo), *args],
                       check=True, capture_output=True)

    def commit(self, repo):
        self.git(repo, "add", ".")
        self.git(repo, "commit", "--quiet", "-m", "synthetic input")

    def pin(self, label, repo):
        for key, value in pilot.checkout(repo).items():
            self.request[f"{label}_{key}"] = value

    def write_tool(self, body):
        script = self.tool / "scripts" / "kani"
        script.parent.mkdir(exist_ok=True)
        script.write_text(f"#!{os.path.realpath('/proc/self/exe')}\n" + body)
        script.chmod(0o755)
        self.commit(self.tool)
        self.pin("tool", self.tool)

    def freeze_control(self, *, child_memory=None):
        # Its worker enters the real child path with synthetic limits and a fake tool.
        if child_memory is None:
            child_memory = self.memory
        worker = f'''import sys
from pathlib import Path
sys.path.insert(0, {str(pilot.HERE)!r})
import run as pilot
pilot.stock_runner.group_memory_budget = lambda: {child_memory!r}
args = sys.argv
journal = Path(args[args.index("--journal") + 1])
std = Path(args[args.index("--std") + 1])
sys.exit(pilot.run_root(journal, pilot.read_record(journal / "prepared.json"), std,
                        {self.request["limits"]!r}))
'''
        for rel, contents in [(pilot.WORKFLOW, "synthetic workflow\n"), (pilot.PAYLOAD[1], worker),
                              (pilot.PAYLOAD[2], "synthetic tests\n"), (pilot.REQUEST, "{}\n")]:
            path = self.repo / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
        self.commit(self.repo)
        self.request["control_payload_sha256"] = {
            rel: pilot.digest(self.repo / rel) for rel in pilot.PAYLOAD
        }
        os.environ["GITHUB_SHA"] = pilot.git(self.repo, "rev-parse", "HEAD")

    def campaign(self):
        return pilot.campaign(self.repo, self.std, self.tool, self.out, self.setup_receipt, self.epoch)

    def finish(self):
        doc = pilot.finish(self.repo, self.std, self.tool, self.out, self.setup_receipt)
        self.assertEqual(doc, json.loads((self.out / "artifact" / pilot.RESULT).read_bytes()))
        self.assertEqual(doc["schema"], "ch8-q-pilot-raw-v1")
        self.assertEqual(doc["proof_credit"], "NONE")
        return doc

    def member(self, root, name):
        entry = root["files"][name]
        data = (self.out / "artifact" / entry["path"]).read_bytes()
        self.assertEqual((len(data), hashlib.sha256(data).hexdigest()), (entry["bytes"], entry["sha256"]))
        return data

    def test_order_argv_cleanup_and_raw_export(self):
        self.freeze_control()
        self.assertEqual(self.campaign(), 0)
        doc = self.finish()
        self.assertEqual(doc["identities"]["control"]["sha"], os.environ["GITHUB_SHA"])
        self.assertEqual(doc["identities"]["control"]["parents"], [self.request["control_parent"]])
        self.assertEqual(doc["identities"]["control"]["request_sha256"], pilot.digest(self.repo / pilot.REQUEST))
        self.assertIsNone(doc["stop_reason"])
        self.assertEqual([r["id"] for r in doc["roots"]], ["P-1", "P-2", "P-3", "P-4", "P-5a", "P-5b", "P-5c"])
        self.assertEqual([r["child"]["original_exit_code"] for r in doc["roots"]], [7, 11, 0, 0, 1, 0, 1])
        targets = set()
        for root, raw in zip(doc["roots"], [b"{broken", None, b"null", b"17",
                             b'{"run_state":"INCOMPLETE"}', b'{"run_state":"PARTIAL"}',
                             b'{"run_state":"COMPLETE"}']):
            self.assertEqual(root["status"], "EXITED")
            self.assertTrue(root["supervisor_cleanup_verified"])
            self.assertEqual(root["worker_exit_code"], 0)
            self.assertTrue(root["temp_cleanup"]["removed"])
            self.assertTrue(root["child"]["child_shutdown_verified"])
            self.assertIsNotNone(root["started"]["utc"])
            self.assertGreaterEqual(root["child"]["worker_observed_at_monotonic"], root["started"]["monotonic"])
            paths = root["invocation"]["paths"]
            extra_cbmc_args = ["--refine-arrays"] if root["id"] == "P-2" else []
            expected = [
                "verify-std", "-Z", "unstable-options", "-Z", "function-contracts",
                "-Z", "mem-predicates", "-Z", "float-lib", "-Z", "c-ffi", "-Z", "stubbing",
                "--no-assert-contracts", "--jobs=1", "--harness", root["selector"],
                "--exact", "--default-unwind", "36", "--harness-timeout",
                f"{root['timeout_seconds']}s",
                "--output-format=regular", "-Z", "export-json", "--export-json", paths["export"],
                "--target-dir", paths["kani_target_dir"], str(self.std / "library"),
                "--cbmc-args", "--object-bits", str(root["object_bits"]), *extra_cbmc_args,
            ]
            seen = json.loads(self.member(root, "stdout"))
            self.assertEqual(seen["args"], expected)
            self.assertEqual(root["argv"], [str(self.tool / "scripts/kani"), *expected])
            self.assertEqual(root["object_bits"], root["invocation"]["object_bits"])
            self.assertEqual(root["cbmc_args"], extra_cbmc_args)
            self.assertEqual(root["invocation"]["cbmc_args"], extra_cbmc_args)
            self.assertEqual(root["timeout_seconds"], root["invocation"]["timeout_seconds"])
            expected_cfg = ("--cfg=kani_smallsort_sorting --cfg=kani_smallsort_q_pilot"
                            " --cfg=kani_smallsort_q_merge")
            if root["id"] in ("P-5a", "P-5b"):
                expected_cfg += " --cfg=kani_smallsort_q_merge_b"
            self.assertEqual(seen["env"]["RUSTFLAGS"], expected_cfg)
            self.assertEqual(root["cfg"], expected_cfg)
            self.assertEqual(seen["env"]["CARGO_TARGET_DIR"], paths["cargo_target_dir"])
            self.assertEqual(seen["env"]["TMPDIR"], paths["tmpdir"])
            self.assertTrue(all("INHERITED_" not in value for value in seen["env"].values()))
            for name in ("kani_target_dir", "cargo_target_dir"):
                target = Path(paths[name])
                self.assertEqual(target.parent, Path(paths["root_temp"]))
                self.assertNotIn(target, targets)
                targets.add(target)
                self.assertFalse(target.exists())
            self.assertEqual(self.member(root, "stderr"), b"")
            if raw is None:
                self.assertEqual(root["files"]["export"]["reason"], "FILE_MISSING")
            else:
                self.assertEqual(self.member(root, "export"), raw)
                if raw == b"{broken":
                    self.assertEqual(root["files"]["export"]["decode_error"]["type"], "JSONDecodeError")
                else:
                    self.assertNotIn("decode_error", root["files"]["export"])

    def test_pilot18_roster_uses_frozen_profile_under_outer_cap(self):
        self.request["roots"] = pilot.ROOTS
        self.memory["group_cap_kib"] = 12582912
        self.freeze_control()

        self.assertEqual(self.campaign(), 0)
        doc = self.finish()
        self.assertEqual([root["id"] for root in doc["roots"]],
                         [root["id"] for root in pilot.ROOTS])
        self.assertEqual([root["child"]["original_exit_code"] for root in doc["roots"]],
                         [int(root["id"] in {"MW-N25-QPOST-CORRUPT-OB13",
                                             "COMPACT-N25-CORRUPT-OB12",
                                             "COMPACT-N20-CORRUPT-OB12"})
                          for root in pilot.ROOTS])
        cap = pilot.LIMITS["local_rss_kib"]
        self.assertEqual(doc["limits"]["local_rss_kib"], cap)
        self.assertIsNone(doc["stop_reason"])
        targets = set()
        for root, profile in zip(doc["roots"], pilot.ROOTS, strict=True):
            with self.subTest(root=root["id"]):
                self.assertEqual(root["status"], "EXITED")
                self.assertEqual(root["argv"][-3:], ["--cbmc-args", "--object-bits",
                                                     str(profile["object_bits"])])
                self.assertEqual(root["argv"][root["argv"].index("--harness") + 1], profile["selector"])
                self.assertEqual(root["argv"][root["argv"].index("--harness-timeout") + 1],
                                 f"{profile['timeout_seconds']}s")
                seen = json.loads(self.member(root, "stdout"))
                self.assertEqual(seen["args"], root["argv"][1:])
                self.assertEqual(seen["env"]["RUSTFLAGS"], pilot.CFG[profile["cfg"]])
                paths = root["invocation"]["paths"]
                for name in ("kani_target_dir", "cargo_target_dir"):
                    target = Path(paths[name])
                    self.assertNotIn(target, targets)
                    targets.add(target)
                    self.assertFalse(target.exists())
                self.assertEqual(root["child"]["nominal_rss_cap_kib"], cap)
                self.assertEqual(root["child"]["rss_cap_kib"], cap)
                self.assertEqual(root["supervisor"]["rss_cap_kib"], 12582912)
                self.assertTrue(root["supervisor_cleanup_verified"])
                self.assertTrue(root["temp_cleanup"]["removed"])

    def test_root_stops_at_lower_effective_cap(self):
        self.request["roots"] = pilot.ROOTS[:1]
        self.memory["group_cap_kib"] = 12582912
        self.write_tool("import time\ntime.sleep(30)\n")
        # Simulate lower available memory at the worker's second budget sample.
        self.freeze_control(child_memory={"group_cap_kib": 1024})

        self.assertEqual(self.campaign(), 0)
        root, = self.finish()["roots"]
        self.assertEqual(root["status"], "INTERRUPTED")
        self.assertEqual(root["reason"], "rss_cap")
        self.assertEqual(root["child"]["nominal_rss_cap_kib"], pilot.LIMITS["local_rss_kib"])
        self.assertEqual(root["child"]["rss_cap_kib"], 1024)
        self.assertGreater(root["child"]["rss_peak_kib"], 1024)
        self.assertIsInstance(root["child"]["component_group_peak_kib"], dict)
        self.assertEqual(root["child"]["component_rss_scope"],
                         "SAMPLED_PROCESS_GROUP_BY_COMM_NOT_PER_ROOT; peaks are not simultaneous")
        self.assertFalse(root["child"]["timed_out"])
        self.assertIsNone(root["supervisor"]["cutoff"])
        self.assertTrue(root["supervisor_cleanup_verified"])
        self.assertTrue(root["temp_cleanup"]["removed"])

    def test_timeout_reap_and_job_cutoff(self):
        self.write_tool('''import os, time
from pathlib import Path
pid = os.fork()
if pid == 0:
    os.setsid()
    os.close(1)
    os.close(2)
    time.sleep(30)
    os._exit(23)
print(pid, flush=True)
time.sleep(30)
''')
        self.request["roots"][0]["timeout_seconds"] = 1
        self.freeze_control()
        original = pilot.supervise_root

        def after_first(repo, out, std, tool, request, root, boundary):
            result = original(repo, out, std, tool, request, root, boundary)
            boundary["latest_root_start_monotonic_by_root"][request["roots"][1]["id"]] = time.monotonic() - 1
            return result

        with patch.object(pilot, "supervise_root", side_effect=after_first):
            self.assertEqual(self.campaign(), 0)
        doc = self.finish()
        first, *rest = doc["roots"]
        self.assertEqual(first["status"], "INTERRUPTED")
        self.assertEqual(first["timeout_seconds"], 1)
        self.assertEqual(first["argv"][first["argv"].index("--harness-timeout") + 1], "1s")
        self.assertEqual(first["child"]["termination_reason"], "timeout")
        self.assertTrue(first["child"]["timed_out"])
        self.assertIn(first["child"]["original_exit_code"], (-15, -9))
        self.assertEqual(first["child"]["signal"], -first["child"]["original_exit_code"])
        self.assertGreaterEqual(first["child"]["elapsed_seconds"], 1)
        self.assertTrue(first["supervisor_cleanup_verified"])
        pid = int(self.member(first, "stdout"))
        self.assertIn(pid, {p["pid"] for p in first["supervisor"]["containment"]["reaped_adopted"]})
        self.assertEqual(doc["stop_reason"], "JOB_LAUNCH_BUDGET_EXHAUSTED")
        self.assertTrue(all(r["status"] == "NOT_RUN" and r["reason"] == doc["stop_reason"] for r in rest))
        self.assertEqual(rest[0]["cbmc_args"], ["--refine-arrays"])
        self.assertIsNone(rest[0]["argv"])

    def test_caps_prefix_and_artifact_members(self):
        limits = self.request["limits"]
        limits.update(stdout_bytes_per_root=32, stderr_bytes_per_root=24, export_bytes_per_root=8)
        self.write_tool('''import os, sys
from pathlib import Path
path = Path(sys.argv[sys.argv.index("--export-json") + 1])
path.write_bytes(b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
os.write(1, b'0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ')
os.write(2, b'abcdefghijklmnopqrstuvwxyz')
sys.exit(9)
''')
        self.freeze_control()
        self.assertEqual(self.campaign(), 0)
        doc = self.finish()
        root = doc["roots"][0]
        for kind, data in (("stdout", b"0123456789ABCDEFGHIJKLMNOPQRSTUV"),
                           ("stderr", b"abcdefghijklmnopqrstuvwx"), ("export", b"01234567")):
            self.assertEqual(self.member(root, kind), data)
            self.assertTrue(root["files"][kind]["truncated"])
        code = root["child"]["original_exit_code"]
        self.assertIn(code, (9, -15, -9))
        self.assertEqual(root["child"]["signal"], -code if code < 0 else None)
        self.assertEqual(root["child"]["termination_reason"], "export_cap")
        artifact = self.out / "artifact"
        with self.assertRaisesRegex(pilot.PilotError, "artifact cap"):
            pilot.validate_artifact(artifact, doc, limits | {"artifact_bytes": 100})
        extra = artifact / "undeclared"
        extra.write_bytes(b"extra")
        with self.assertRaisesRegex(pilot.PilotError, "unexpected artifact member"):
            pilot.validate_artifact(artifact, doc, limits)
        extra.unlink()
        member = artifact / root["files"]["stdout"]["path"]
        member.unlink()
        member.symlink_to(self.setup_receipt)
        with self.assertRaisesRegex(pilot.PilotError, "unexpected artifact member"):
            pilot.validate_artifact(artifact, doc, limits)

    def test_fallback_preserves_started_and_setup_without_outer_receipt(self):
        self.freeze_control()
        for index, root in enumerate(self.request["roots"][:3]):
            journal = self.out / "state" / root["id"]
            prepared = pilot.prepare(self.out, root, self.std, self.tool, self.request)
            Path(prepared["paths"]["root_temp"]).mkdir(parents=True)
            pilot.atomic(journal / "prepared.json", prepared)
            if index == 0:
                self.assertEqual(pilot.run_root(journal, prepared, self.std, self.request["limits"]), 0)
            if index == 1:
                pilot.atomic(journal / "started.json", {"pid": 4321, "utc": "synthetic", "monotonic": 1})
        doc = self.finish()
        self.assertEqual(doc["setup"]["sha256"], pilot.digest(self.setup_receipt))
        self.assertEqual(doc["setup"]["receipt"]["original_exit_code"], 0)
        returned, started, prepared, absent, *_ = doc["roots"]
        self.assertEqual(returned["child"]["original_exit_code"], 7)
        self.assertEqual(self.member(returned, "export"), b"{broken")
        self.assertFalse(returned["files"]["export"]["snapshot_after_reap"])
        for root in (returned, started):
            self.assertEqual(root["status"], "INTERRUPTED")
            self.assertIsNotNone(root["started"])
            self.assertIsNone(root["supervisor_cleanup_verified"])
            self.assertIsNone(root["temp_cleanup"]["removed"])
        self.assertIsNone(started["child"])
        self.assertEqual(prepared["status"], "UNKNOWN")
        self.assertEqual(absent["status"], "NOT_RUN")

    def test_worker_preparation_failure_allows_next_root_after_reap(self):
        self.freeze_control()
        original = pilot.s3_runtime.supervise

        def with_existing_tmp(argv, cwd, env, timeout, rss, stderr):
            if Path(argv[argv.index("--journal") + 1]).name == "P-1":
                (stderr.parent / "tmp").mkdir()
            return original(argv, cwd, env, timeout, rss, stderr)

        with patch.object(pilot.s3_runtime, "supervise", side_effect=with_existing_tmp):
            self.assertEqual(self.campaign(), 0)
        doc = self.finish()
        first, second, *_ = doc["roots"]
        self.assertEqual(first["status"], "NOT_RUN")
        self.assertEqual(first["reason"], "CHILD_PREPARATION_ERROR")
        self.assertEqual(first["launch_error"]["type"], "FileExistsError")
        self.assertIsNone(first["argv"])
        self.assertEqual(first["worker_exit_code"], 1)
        self.assertTrue(first["supervisor_cleanup_verified"])
        self.assertTrue(first["temp_cleanup"]["removed"])
        self.assertEqual(second["child"]["original_exit_code"], 11)

    def test_read_error_and_unconfirmed_supervisor_stop(self):
        self.write_tool('''import os, sys
from pathlib import Path
Path(sys.argv[sys.argv.index("--export-json") + 1]).symlink_to("/dev/null")
sys.exit(12)
''')
        self.freeze_control()
        original = pilot.s3_runtime.supervise

        def without_confirmation(*args, **kwargs):
            receipt = original(*args, **kwargs)
            receipt["containment"]["verified"] = False
            return receipt

        with patch.object(pilot.s3_runtime, "supervise", side_effect=without_confirmation):
            self.assertEqual(self.campaign(), 1)
        doc = self.finish()
        first, *rest = doc["roots"]
        self.assertEqual(first["child"]["original_exit_code"], 12)
        self.assertEqual(first["files"]["export"]["reason"], "READ_ERROR")
        self.assertIn("message", first["files"]["export"]["error"])
        self.assertFalse(first["supervisor_cleanup_verified"])
        self.assertEqual(doc["stop_reason"], "SUPERVISOR_REAP_UNCONFIRMED")
        self.assertTrue(all(r["status"] == "NOT_RUN" for r in rest))

    def test_identity_mismatch_untracked_and_mid_sequence_drift(self):
        self.freeze_control()
        for label, path in (("std", self.std), ("tool", self.tool)):
            for key in ("sha", "tree"):
                field = f"{label}_{key}"
                with self.subTest(field=field), patch.dict(self.request, {field: "0" * 40}):
                    with self.assertRaisesRegex(pilot.PilotError, f"{label} identity mismatch"):
                        pilot.validate_source(self.std, self.tool, self.request)
            dirty = path / "unexpected"
            dirty.touch()
            with self.assertRaisesRegex(pilot.PilotError, f"dirty {label} checkout"):
                pilot.validate_source(self.std, self.tool, self.request)
            dirty.unlink()
        with patch.dict(os.environ, {"GITHUB_SHA": "0" * 40}):
            with self.assertRaisesRegex(pilot.PilotError, "trigger SHA"):
                pilot.check_control(self.repo, self.request)
        self.request["control_payload_sha256"][pilot.PAYLOAD[1]] = "0" * 64
        with self.assertRaisesRegex(pilot.PilotError, "payload hash mismatch"):
            pilot.check_control(self.repo, self.request)
        self.request["control_payload_sha256"][pilot.PAYLOAD[1]] = pilot.digest(
            self.repo / pilot.PAYLOAD[1]
        )
        (self.repo / "unexpected").touch()
        with self.assertRaisesRegex(pilot.PilotError, "dirty control checkout"):
            pilot.check_control(self.repo, self.request)
        (self.repo / "unexpected").unlink()

        original = pilot.supervise_root

        def after_first(*args, **kwargs):
            result = original(*args, **kwargs)
            (self.std / "unexpected").touch()
            return result

        with patch.object(pilot, "supervise_root", side_effect=after_first):
            self.assertEqual(self.campaign(), 1)
        doc = self.finish()
        self.assertEqual(doc["stop_reason"], "INPUT_VALIDATION_FAILED")
        self.assertIn("dirty std checkout", doc["stop_error"]["message"])
        self.assertEqual(doc["roots"][0]["child"]["original_exit_code"], 7)
        self.assertTrue(all(r["status"] == "NOT_RUN" for r in doc["roots"][1:]))

    def test_expired_job_budget_before_first_root(self):
        self.freeze_control()
        self.epoch.write_text("1")
        with (patch.object(pilot.s3_runtime, "supervise") as supervise,
              patch.object(pilot.time, "monotonic", return_value=180 * 60 + 1)):
            self.assertEqual(self.campaign(), 0)
        supervise.assert_not_called()
        doc = self.finish()
        self.assertEqual(doc["stop_reason"], "JOB_LAUNCH_BUDGET_EXHAUSTED")
        self.assertTrue(all(r["status"] == "NOT_RUN" and r["invocation"] is None for r in doc["roots"]))


class FrozenRequestTests(unittest.TestCase):
    def test_pilot18_root_profiles_and_argv(self):
        request = pilot.load_request()
        prefix = "slice::sort::shared::smallsort::verify::"
        merge_cfg = "--cfg=kani_smallsort_sorting --cfg=kani_smallsort_q_pilot --cfg=kani_smallsort_q_merge"
        merge_b_cfg = merge_cfg + " --cfg=kani_smallsort_q_merge_b"
        merge_c_sort9_cfg = merge_b_cfg + " --cfg=kani_smallsort_q_merge_sort9"
        wide = merge_c_sort9_cfg + " --cfg=kani_smallsort_q_merge_wide"
        no_merge = wide + " --cfg=kani_smallsort_q_no_merge_sort13"
        compact_no_merge = no_merge + " --cfg=kani_smallsort_q_compact_presort13"
        profiles = [
            ("MW-NETWORK-N25-OB13", "sorting_q_merge::mw_network_n25", "merge_wide", 13, 450),
            ("MW-N25-QPOST-CORRUPT-OB13", "sorting_q_merge::mw_network_n25_corrupt", "merge_wide", 13, 300),
            ("COMPACT-N25-OB12", "sorting_q_merge::compact_network_n25", "merge_wide", 12, 450),
            ("COMPACT-N25-CORRUPT-OB12", "sorting_q_merge::compact_network_n25_corrupt", "merge_wide", 12, 300),
            ("COMPACT-N20-OB12", "sorting_q_merge::compact_network_n20", "merge_wide", 12, 450),
            ("COMPACT-N20-CORRUPT-OB12", "sorting_q_merge::compact_network_n20_corrupt", "merge_wide", 12, 300),
            ("COMPACT-N20-ACT-INSERT-OB12", "sorting_q_merge::compact_network_n20_actual_insert", "merge_wide", 12, 600),
            ("MW-INSERT-L9-OB11", "sorting_q_merge::mw_insert_left_literal_rel9", "merge_wide", 11, 600),
            ("MW-INSERT-L10-OB11", "sorting_q_merge::mw_insert_left_literal_rel10", "merge_wide", 11, 600),
            ("MW-INSERT-L11-OB11", "sorting_q_merge::mw_insert_left_literal_rel11", "merge_wide", 11, 600),
            ("NM-S13-L17-COMPACT-OB11", "sorting_q_merge::nm_sort13_left_len17", "no_merge_sort13_compact", 11, 1200),
        ]
        expected_budget, expected_cap = 5850, 10485760
        expected_cfg = {
            "merge_a": merge_cfg, "merge_b": merge_b_cfg,
            "merge_c_sort9": merge_c_sort9_cfg, "merge_wide": wide,
            "no_merge_sort13": no_merge, "no_merge_sort13_compact": compact_no_merge,
        }
        self.assertEqual(request["cfg"], expected_cfg)
        self.assertEqual({root["object_bits"] for root in request["roots"]}, {11, 12, 13})
        self.assertEqual([r["id"] for r in request["roots"]], [p[0] for p in profiles])
        for root, (rid, selector, cfg, bits, timeout) in zip(request["roots"], profiles, strict=True):
            with self.subTest(root=rid):
                self.assertEqual(root, {
                    "id": rid, "selector": prefix + selector, "cfg": cfg,
                    "object_bits": bits, "timeout_seconds": timeout, "cbmc_args": [],
                })
                prepared = pilot.prepare(Path("/out"), root, Path("/std"), Path("/tool"), request)
                argv = prepared["argv"]
                self.assertEqual(prepared["cfg"], expected_cfg[cfg])
                self.assertEqual(argv[argv.index("--harness") + 1:argv.index("--harness") + 3],
                                 [prefix + selector, "--exact"])
                self.assertEqual(argv[argv.index("--harness-timeout") + 1], f"{timeout}s")
                self.assertEqual(argv[argv.index("--cbmc-args"):],
                                 ["--cbmc-args", "--object-bits", str(bits)])
        child_budget = sum(root["timeout_seconds"] for root in request["roots"])
        self.assertEqual(child_budget, expected_budget)
        limits = request["limits"]
        self.assertNotIn("child_seconds_per_root", limits)
        self.assertEqual(limits["job_minutes"], 180)
        self.assertEqual(limits["setup_and_build_seconds"], 1800)
        self.assertEqual(limits["job_cleanup_upload_seconds"], 540)
        self.assertEqual(limits["root_launch_headroom_seconds"], 30)
        self.assertEqual(limits["local_rss_kib"], expected_cap)
        self.assertEqual(limits["outer_rss_kib"], 12582912)
        self.assertEqual(limits["memory_reserve_kib"], 2097152)
        self.assertEqual(limits["stdout_bytes_per_root"], 16 * 1024**2)
        self.assertEqual(limits["stderr_bytes_per_root"], 1024**2)
        self.assertEqual(limits["export_bytes_per_root"], 8 * 1024**2)
        self.assertEqual(limits["artifact_bytes"], 384 * 1024**2)
        root_capture_bytes = sum(limits[key] for key in (
            "stdout_bytes_per_root", "stderr_bytes_per_root", "export_bytes_per_root",
        ))
        self.assertEqual(len(request["roots"]) * root_capture_bytes,
                         len(request["roots"]) * 25 * 1024**2)
        self.assertEqual(
            limits["job_minutes"] * 60 - limits["setup_and_build_seconds"]
            - limits["job_cleanup_upload_seconds"] - child_budget,
            2610,
        )

    def test_per_root_latest_start_uses_each_timeout(self):
        request = pilot.load_request()
        roots = request["roots"]
        with tempfile.TemporaryDirectory() as temp:
            epoch = Path(temp) / "epoch"
            epoch.write_text(str(time.monotonic()))
            boundary = pilot.launch_boundary(epoch, request["limits"], roots)
        starts = boundary["latest_root_start_monotonic_by_root"]
        self.assertEqual(list(starts), [root["id"] for root in roots])
        expected_headroom = {seconds: seconds + 30 for seconds in
                             {root["timeout_seconds"] for root in roots}}
        self.assertEqual({root["timeout_seconds"] for root in roots}, set(expected_headroom))
        self.assertEqual({root["timeout_seconds"] for root in roots}, {300, 450, 600, 1200})
        for root in roots:
            headroom = boundary["supervisor_cutoff_monotonic"] - pilot.latest_root_start(boundary, root)
            self.assertAlmostEqual(headroom, expected_headroom[root["timeout_seconds"]])

    def test_request_rejects_config_and_roster_drift(self):
        request = pilot.load_request()
        root, *remaining = request["roots"]
        previous_selector = pilot.PREFIX + "sorting_q_merge::mb_merge_n18"
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            path = repo / pilot.REQUEST
            path.parent.mkdir()
            for key, invalid in (("argv", request["argv"] + ["--extra"]),
                                 ("roots", []), ("roots", [root, root, *remaining[1:]]),
                                 ("roots", [*remaining, root]),
                                 ("roots", [root | {"id": "MB-MERGE-N18"}, *remaining]),
                                 ("roots", [root | {"object_bits": 12}, *remaining]),
                                 ("roots", [root | {"timeout_seconds": 300}, *remaining]),
                                 ("roots", [root | {"selector": previous_selector}, *remaining]),
                                 ("roots", [root | {"cfg": "merge_a"}, *remaining]),
                                 ("limits", request["limits"] | {
                                     "local_rss_kib": 6291456 if request["limits"]["local_rss_kib"] != 6291456
                                     else 10485760}),
                                 ("cfg", request["cfg"] | {"profile": "drift"}),
                                 ("limits", request["limits"] | {"artifact_bytes": 256 * 1024**2}),
                                 ("tool_tree", "0" * 40)):
                path.write_text(json.dumps(request | {key: invalid}))
                with self.subTest(key=key), self.assertRaisesRegex(pilot.PilotError, f"mismatch: {key}"):
                    pilot.load_request(repo)
            for key, invalid in (("roots", [root | {"object_bits": 11.0}, *remaining]),
                                 ("roots", [root | {"timeout_seconds": 600.0}, *remaining]),
                                 ("roots", [root | {"timeout_seconds": True}, *remaining]),
                                 ("limits", request["limits"] | {"local_rss_kib": 10485760.0}),
                                 ("limits", request["limits"] | {"local_rss_kib": True})):
                path.write_text(json.dumps(request | {key: invalid}))
                with self.subTest(key=key, invalid=invalid), self.assertRaisesRegex(
                        pilot.PilotError, "invalid (per-root object bits or timeout|numeric limit types)"):
                    pilot.load_request(repo)

    def test_request_rejects_non_frozen_cbmc_args(self):
        request = pilot.load_request()
        root, *remaining = request["roots"]
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            path = repo / pilot.REQUEST
            path.parent.mkdir()
            for args in (["--refine-arrays"], "--refine-arrays", None, ["--show-array-constraints"],
                         ["--object-bits", "12"]):
                path.write_text(json.dumps(request | {
                    "roots": [root | {"cbmc_args": args}, *remaining],
                }))
                with self.subTest(args=args), self.assertRaisesRegex(pilot.PilotError, "mismatch: roots"):
                    pilot.load_request(repo)

    def test_request_rejects_hash_inventory_drift_and_errors(self):
        request = pilot.load_request()
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            path = repo / pilot.REQUEST
            path.parent.mkdir()
            mutations = (
                ("std_files", request["std_files"] | {"unexpected.rs": "0" * 64}, "std_files"),
                ("std_files", request["std_files"] | {next(iter(request["std_files"])): "bad"}, "std_files"),
                ("control_payload_sha256", {}, "control_payload_sha256"),
            )
            for key, invalid, inventory in mutations:
                path.write_text(json.dumps(request | {key: invalid}))
                with self.subTest(key=key, inventory=inventory), self.assertRaisesRegex(
                        pilot.PilotError, f"hash inventory mismatch: {inventory}"):
                    pilot.load_request(repo)
            path.write_text("not json")
            with self.assertRaises(json.JSONDecodeError):
                pilot.load_request(repo)


if __name__ == "__main__":
    unittest.main()
