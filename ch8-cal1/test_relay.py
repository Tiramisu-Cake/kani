# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Deferred CBMC stdout relay against synthetic children; no Kani, Rust, CBMC or CI."""
from copy import deepcopy
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import cbmc_relay
import request as spec
import results
import run
import stdout_relay
import supervisor
from telemetry import MemoryTelemetry
import test_results

FROZEN = spec.load()


def kernel_monotonic():
    """CLOCK_MONOTONIC as the relay and its children see it, even when a self-test shifts time.monotonic."""
    return time.clock_gettime(time.CLOCK_MONOTONIC)

# By coordinator decision 2026-11-28 the frozen Wide N32 control is the only relay slot of the closure.
# The machinery is tested on that exact frozen row, with a smaller synthetic spill cap.
N16_ROW = FROZEN["roster"][-1]
assert N16_ROW["id"] == spec.RELAY_SLOT_ID and N16_ROW["stdout_delivery"] == spec.STDOUT_RELAY_DELIVERY
RELAY_ID = N16_ROW["id"]
RELAY_SLOT = (RELAY_ID, "singleton", [N16_ROW], N16_ROW["seconds"])
VERSION = "6.11.0 (cbmc-6.11.0)"
# A stand-in for the real binary. It reports what it received and when it finished writing.
FAKE_CBMC = r'''
import hashlib, json, os, signal, sys, time
args = sys.argv[1:]
if args == ["--version"]:
    print("6.11.0 (cbmc-6.11.0)")
    sys.exit(0)
mode = os.environ["FAKE_CBMC_MODE"]
payload = open(os.environ["FAKE_CBMC_PAYLOAD"], "rb").read()
if mode == "signal":
    payload = payload[:len(payload) // 2]
view = memoryview(payload)
first = None
while view:
    written = os.write(1, view[:65536])
    first = first or time.monotonic()
    view = view[written:]
if mode == "hang":
    time.sleep(60)
time.sleep(float(os.environ.get("FAKE_CBMC_LINGER", "0")))
with open("/proc/self/environ", "rb") as stream:
    environment = hashlib.sha256(stream.read()).hexdigest()
mark = {"first_write_monotonic": first, "exit_monotonic": time.monotonic(), "argv": args, "cwd": os.getcwd(),
        "environment_sha256": environment, "pgid": os.getpgid(0), "sid": os.getsid(0)}
with open(os.environ["FAKE_CBMC_MARK"], "w") as stream:
    json.dump(mark, stream)
if mode == "signal":
    os.kill(os.getpid(), signal.SIGKILL)
sys.exit(int(os.environ.get("FAKE_CBMC_EXIT", "0")))
'''


def cbmc_argv(goto):
    return [str(goto) if item == "{goto}" else item for item in spec.EXPECTED_CBMC_ARGV]


def json_ui_payload(fixture_stdout, export, filler_items):
    """A CBMC-like JSON-UI array carrying the relay witness projection fixture and a large trace-like filler."""
    items = [{"program": "CBMC 6.11.0 (cbmc-6.11.0) 64-bit x86_64 linux"},
             {"messageText": "4956964 variables, 25517502 clauses", "messageType": "STATUS-MESSAGE"},
             {"messageText": fixture_stdout.decode(), "messageType": "STATUS-MESSAGE"},
             {"kaniExport": export}]
    filler = json.dumps({"stepType": "assignment", "lhs": "dst", "value": {"data": "0x" + "ab" * 96},
                         "hidden": False, "thread": 0}, indent=2)
    lines = [json.dumps(item, indent=2) for item in items] + [filler] * filler_items
    return ("[\n" + ",\n".join(lines) + "\n]\n").encode()


# A slow reader keeps the relay in its replay phase across several census samples.
DRIVER = (
    "import os, subprocess, sys, time\n"
    "if os.environ.get('DRIVER_ECHO'):\n"
    "    print('[Kani] Running: `cbmc ' + ' '.join(sys.argv[1:]) + '`', flush=True)\n"
    "proc = subprocess.Popen(['cbmc', *sys.argv[1:]], stdout=subprocess.PIPE)\n"
    "while block := proc.stdout.read1(65536):\n"
    "    sys.stdout.buffer.write(block)\n"
    "    time.sleep(float(os.environ.get('DRIVER_DELAY', '0')))\n"
    "sys.stdout.flush()\n"
    "sys.exit(proc.wait() != 0)\n"
)


class RelayFixture(unittest.TestCase):
    def setUp(self):
        # Relay marks come from other processes. Cross-process order is only defined on the kernel clock.
        self.enterContext(patch.object(time, "monotonic", kernel_monotonic))
        # An in-process relay failure ignores termination signals. Ignored dispositions survive exec,
        # so restore them before any later test starts children.
        for name in cbmc_relay.TERMINATION_SIGNALS:
            number = getattr(signal, name)
            self.addCleanup(signal.signal, number, signal.getsignal(number))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.real_dir = self.root / "real"
        self.real_dir.mkdir()
        self.real = self.real_dir / "cbmc"
        self.real.write_text(f"#!{sys.executable} -I\n{FAKE_CBMC}")
        self.real.chmod(0o755)
        info = self.real.stat()
        self.setup_tool = {"binaries": {"cbmc": {
            "path": str(self.real.resolve()), "sha256": stdout_relay.file_sha256(self.real), "bytes": info.st_size,
            "version": f"CBMC version {VERSION} 64-bit"}}}
        # The relay checks real free space for cap + reserve before every install and spill. Keep the cap just
        # above the largest synthetic stream (about 21.2 MiB): each check then needs 25 MiB free, not 65 MiB.
        self.config = spec.STDOUT_RELAY | {"slot": RELAY_ID, "spill_cap_bytes": 24 * spec.MIB,
                                            "disk_reserve_bytes": spec.MIB, "term_grace_seconds": 0.5}

    def slot(self, name=None):
        self.slots = getattr(self, "slots", 0) + 1
        directory = self.root / (name or f"slot-{self.slots}")
        directory.mkdir()
        real = stdout_relay.resolve_real(self.setup_tool, str(self.real_dir))
        return directory, stdout_relay.install(directory, real, config=self.config)

    def env(self, directory, payload, *, relay_state=None, mode="emit", exit_code=0, linger=0.0):
        path = str(self.real_dir) if relay_state is None else relay_state["path_prefix"] + os.pathsep + str(self.real_dir)
        return {"PATH": path, "LANG": "C.UTF-8", "FAKE_CBMC_MODE": mode, "FAKE_CBMC_PAYLOAD": str(payload),
                "FAKE_CBMC_MARK": str(directory / f"mark-{mode}.json"), "FAKE_CBMC_EXIT": str(exit_code),
                "FAKE_CBMC_LINGER": str(linger)}

    def consume(self, directory, env, argv):
        """Read CBMC stdout as the stock driver does: until EOF, then wait."""
        proc = subprocess.Popen(["cbmc", *argv], cwd=directory, env=env, stdout=subprocess.PIPE,
                                stdin=subprocess.DEVNULL)
        with proc.stdout:
            first = proc.stdout.read(1)
            first_at = time.monotonic() if first else None
            data = first + proc.stdout.read()
        return data, first_at, proc.wait()

    def journals(self, relay_state):
        records, problems, _ = stdout_relay.read_journals(relay_state["journal_dir"])
        self.assertEqual(problems, [])
        return {record["mode"]: record for record in records}


class RelayTransportTests(RelayFixture):
    def test_direct_and_relay_deliver_identical_large_json_and_the_same_projection(self):
        stdout, export = test_results.ResultProjectionTests._projection_fixture(N16_ROW)
        payloads = {10: self.root / "large.json", 0: self.root / "small.json"}
        payloads[10].write_bytes(json_ui_payload(stdout, export, 72000))
        payloads[0].write_bytes(json_ui_payload(stdout, export, 100))
        self.assertGreater(payloads[10].stat().st_size, 16 * spec.MIB)
        observed, peaks = {}, {}
        for transport in ("direct", "relay"):
            for exit_code, payload in payloads.items():
                size, digest = payload.stat().st_size, stdout_relay.file_sha256(payload)
                with self.subTest(transport=transport, exit_code=exit_code):
                    directory, relay_state = self.slot(f"{transport}-{exit_code}")
                    env = self.env(directory, payload, relay_state=relay_state if transport == "relay" else None,
                                   exit_code=exit_code, linger=0.3)
                    goto = directory / "kani-target" / "harness.out"
                    data, first_at, status = self.consume(directory, env, cbmc_argv(goto))
                    mark = json.loads((directory / "mark-emit.json").read_text())
                    self.assertEqual((len(data), hashlib.sha256(data).hexdigest(), status), (size, digest, exit_code))
                    self.assertEqual(mark["argv"], cbmc_argv(goto))
                    self.assertEqual(mark["cwd"], str(directory))
                    if transport == "direct":
                        # The stock pipe streams while the child still runs.
                        self.assertLess(first_at, mark["exit_monotonic"])
                    else:
                        self.assertGreater(first_at, mark["exit_monotonic"])
                        call = self.journals(relay_state)["SPILL_THEN_REPLAY"]
                        self.assertEqual(call["outcome"], "COMPLETE")
                        self.assertEqual((call["spill_bytes"], call["replay_bytes"]), (size, size))
                        self.assertEqual(call["spill_sha256"], digest)
                        self.assertEqual(call["replay_sha256"], digest)
                        self.assertEqual(call["cbmc_returncode"], exit_code)
                        self.assertEqual(call["environment_sha256"], mark["environment_sha256"])
                        self.assertEqual((call["cbmc_pgid"], call["cbmc_sid"]), (mark["pgid"], mark["sid"]))
                        self.assertEqual((call["relay_pgid"], call["relay_sid"]), (mark["pgid"], mark["sid"]))
                        self.assertLess(call["wait_done_monotonic"], call["replay_first_byte_monotonic"])
                        self.assertLess(mark["exit_monotonic"], call["replay_first_byte_monotonic"])
                        self.assertTrue(call["spill_removed"])
                        self.assertEqual(os.listdir(relay_state["spill_dir"]), [])
                        peaks[exit_code] = call["relay_peak_rss_kib"]
                    observed[(transport, exit_code)] = data
                    document = json.loads(data)
                    (directory / "stdout.log").write_bytes(document[2]["messageText"].encode())
                    (directory / "stderr.log").write_bytes(b"")
                    (directory / "export.json").write_text(json.dumps(document[3]["kaniExport"]))
                    child = {"stop_reason": "EXITED", "exit_code": 1, "signal": None, "reaped": True,
                             "sampler_valid": True, "stdout_complete": True, "stderr_complete": True}
                    projected = results.project(directory, [N16_ROW], child, mode="singleton")
                    self.assertEqual(projected["expected_result"]["status"], "MATCHED", projected["reason"])
                    failures = [p for p in projected["native_checks"] if p["status"] == "FAILURE"]
                    self.assertEqual([p["description"] for p in failures], [N16_ROW["expected_failure"]["label"]])
                    self.assertEqual(projected["cover_summary"]["expected_reached_labels"], N16_ROW["covers"])
        self.assertEqual(observed[("direct", 10)], observed[("relay", 10)])
        # Constant 64 KiB blocks: a 16 MiB larger stream leaves the relay peak RSS nearly unchanged.
        self.assertLess(peaks[10] - peaks[0], 4 * 1024)
        self.assertLess(peaks[10] * 1024, 48 * spec.MIB)

    def test_version_call_is_replaced_by_the_real_binary(self):
        directory, relay_state = self.slot()
        env = self.env(directory, self.root / "unused")
        env["PATH"] = relay_state["path_prefix"] + os.pathsep + str(self.real_dir)
        out = subprocess.run(["cbmc", "--version"], env=env, capture_output=True, check=True, text=True)
        self.assertEqual(out.stdout.strip(), VERSION)
        call = self.journals(relay_state)["VERSION_PASSTHROUGH"]
        self.assertEqual((call["argv"], call["phase"]), (["--version"], "EXEC"))
        self.assertEqual(os.listdir(relay_state["spill_dir"]), [])

    def test_real_cbmc_signal_is_mirrored_after_the_complete_replay(self):
        payload = self.root / "payload.bin"
        payload.write_bytes(os.urandom(3 * spec.MIB))
        results_by_transport = {}
        for transport in ("direct", "relay"):
            directory, relay_state = self.slot(transport)
            env = self.env(directory, payload, relay_state=relay_state if transport == "relay" else None,
                           mode="signal")
            data, _, status = self.consume(directory, env, ["--json-ui"])
            results_by_transport[transport] = (hashlib.sha256(data).hexdigest(), status)
            if transport == "relay":
                call = self.journals(relay_state)["SPILL_THEN_REPLAY"]
                self.assertEqual((call["outcome"], call["signal"], call["cbmc_returncode"]),
                                 ("CBMC_SIGNALED", signal.SIGKILL, -signal.SIGKILL))
                self.assertTrue(call["replay_complete"])
        self.assertEqual(results_by_transport["direct"], results_by_transport["relay"])
        self.assertEqual(results_by_transport["relay"][1], -signal.SIGKILL)

    def test_spill_cap_stops_and_reaps_cbmc_without_replay(self):
        payload = self.root / "payload.bin"
        payload.write_bytes(os.urandom(4 * spec.MIB))
        self.config["spill_cap_bytes"] = spec.MIB
        directory, relay_state = self.slot()
        env = self.env(directory, payload, relay_state=relay_state, mode="hang")
        started = time.monotonic()
        data, _, status = self.consume(directory, env, ["--json-ui"])
        self.assertLess(time.monotonic() - started, 20)
        self.assertEqual((data, status), (b"", cbmc_relay.EXIT_RELAY_FAILURE))
        call = self.journals(relay_state)["SPILL_THEN_REPLAY"]
        self.assertEqual(call["outcome"], "SPILL_LIMIT")
        self.assertLessEqual(call["spill_bytes"], spec.MIB)
        self.assertIn(call["cbmc_returncode"], (-signal.SIGTERM, -signal.SIGKILL))
        self.assertNotIn("replay_first_byte_monotonic", call)
        self.assertFalse((directory / "mark-hang.json").exists())

    def test_broken_pipe_in_the_middle_of_replay_is_reported_and_keeps_the_spill(self):
        payload = self.root / "payload.bin"
        payload.write_bytes(os.urandom(2 * spec.MIB))
        directory, relay_state = self.slot()
        env = self.env(directory, payload, relay_state=relay_state)
        proc = subprocess.Popen(["cbmc", "--json-ui"], cwd=directory, env=env, stdout=subprocess.PIPE,
                                stdin=subprocess.DEVNULL)
        with proc.stdout:
            head = proc.stdout.read(131072)
        status = proc.wait()
        self.assertEqual((len(head), status), (131072, cbmc_relay.EXIT_RELAY_FAILURE))
        call = self.journals(relay_state)["SPILL_THEN_REPLAY"]
        self.assertEqual(call["outcome"], "REPLAY_INCOMPLETE")
        self.assertIn("BrokenPipeError", call["error"])
        self.assertEqual(call["cbmc_returncode"], 0)
        self.assertGreaterEqual(call["replay_bytes"], 131072)
        self.assertLess(call["replay_bytes"], call["spill_bytes"])
        self.assertEqual(call["spill_bytes"], 2 * spec.MIB)
        self.assertFalse(call["replay_complete"])
        self.assertEqual(len(os.listdir(relay_state["spill_dir"])), 1)
        judged = stdout_relay.collect(relay_state, directory, {"reaped": True}, config=self.config)
        self.assertEqual(judged["status"], "INCOMPLETE")
        self.assertIn("relay outcome REPLAY_INCOMPLETE", judged["reasons"])

    def test_spill_on_memory_backed_filesystem_is_refused(self):
        directory = self.root / "slot"
        directory.mkdir()
        real = stdout_relay.resolve_real(self.setup_tool, str(self.real_dir))
        with patch.object(stdout_relay, "filesystem_type", return_value="tmpfs"), \
                self.assertRaisesRegex(stdout_relay.RelayError, "memory-backed tmpfs"):
            stdout_relay.install(directory, real, config=self.config)
        mounts = self.root / "mounts"
        mounts.write_text("none / ext4 rw 0 0\ntmpfs /dev/shm tmpfs rw 0 0\n/dev/sdb1 /mnt/with\\040space xfs rw 0 0\n")
        (self.root / "shm").mkdir()
        with patch.object(Path, "resolve", lambda self, strict=False: self):
            self.assertEqual(stdout_relay.filesystem_type("/dev/shm/x", mounts), "tmpfs")
            self.assertEqual(stdout_relay.filesystem_type("/mnt/with space/a", mounts), "xfs")
            self.assertEqual(stdout_relay.filesystem_type("/mnt/withspace", mounts), "ext4")
        (self.root / "ok").mkdir()
        installed = stdout_relay.install(self.root / "ok", real, config=self.config)
        self.assertEqual(installed["receipt"]["spill_filesystem"], stdout_relay.filesystem_type(self.root / "ok"))

    def test_disk_reserve_is_checked_before_install_and_before_spill(self):
        directory = self.root / "slot"
        directory.mkdir()
        real = stdout_relay.resolve_real(self.setup_tool, str(self.real_dir))
        with patch.object(stdout_relay, "free_bytes", return_value=self.config["spill_cap_bytes"]), \
                self.assertRaisesRegex(stdout_relay.RelayError, "spill disk"):
            stdout_relay.install(directory, real, config=self.config)
        directory, relay_state = self.slot("huge")
        settings = json.loads((Path(relay_state["path_prefix"]) / "cbmc-relay.json").read_text())
        settings["spill_cap_bytes"] = 1 << 62
        journal = cbmc_relay.Journal(relay_state["journal_dir"], 1)
        with self.assertRaises(cbmc_relay.RelayFailure) as caught:
            cbmc_relay.relay(["--json-ui"], settings, journal, {})
        self.assertEqual(caught.exception.outcome, "SPILL_DISK_UNAVAILABLE")
        self.assertEqual(os.listdir(relay_state["spill_dir"]), [])

    def test_install_binds_the_attested_binary_and_private_files(self):
        directory, relay_state = self.slot()
        script = Path(relay_state["path_prefix"]) / "cbmc"
        config = Path(relay_state["path_prefix"]) / "cbmc-relay.json"
        self.assertEqual(oct(script.stat().st_mode & 0o777), "0o700")
        self.assertEqual(oct(config.stat().st_mode & 0o777), "0o600")
        self.assertEqual(script.read_bytes().split(b"\n", 1)[1], (spec.HERE / "cbmc_relay.py").read_bytes())
        self.assertEqual(relay_state["receipt"]["source_sha256"], spec.RELAY_SOURCE_SHA256)
        for field, value in (("sha256", "0" * 64), ("path", "/elsewhere/cbmc"), ("version", "CBMC version 6.10.0")):
            tool = deepcopy(self.setup_tool)
            tool["binaries"]["cbmc"][field] = value
            with self.subTest(field=field), self.assertRaises(stdout_relay.RelayError):
                stdout_relay.resolve_real(tool, str(self.real_dir))
        with self.assertRaisesRegex(stdout_relay.RelayError, "frozen hash"):
            stdout_relay.install(self.root / "slot", stdout_relay.resolve_real(self.setup_tool, str(self.real_dir)),
                                 config=self.config | {"source_sha256": "1" * 64})
        # A replaced binary after install is refused by the relay itself.
        settings = json.loads(config.read_text())
        settings["real_cbmc_identity"][1] += 1
        with self.assertRaises(cbmc_relay.RelayFailure) as caught:
            cbmc_relay.check_real(settings)
        self.assertEqual(caught.exception.outcome, "REAL_CBMC_CHANGED")


class RelayWriteTests(RelayFixture):
    def test_short_writes_are_retried_until_every_byte_is_delivered(self):
        data = os.urandom(200000)
        chunks = []

        def short(fd, view):
            part = bytes(view[:777])
            chunks.append(part)
            return len(part)

        calls = cbmc_relay.write_all(5, data, short)
        self.assertEqual((b"".join(chunks), calls), (data, -(-len(data) // 777)))
        with self.assertRaises(OSError):
            cbmc_relay.write_all(5, b"x", lambda fd, view: 0)

    def run_in_process(self, payload, *, spill_write=os.write, replay_write=os.write):
        directory, relay_state = self.slot()
        settings = json.loads((Path(relay_state["path_prefix"]) / "cbmc-relay.json").read_text())
        journal = cbmc_relay.Journal(relay_state["journal_dir"], os.getpid())
        env = {key.encode(): value.encode() for key, value in self.env(directory, payload).items()}
        read_fd, write_fd = os.pipe()
        received = bytearray()

        def drain():
            while block := os.read(read_fd, 65536):
                received.extend(block)

        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        try:
            status = cbmc_relay.relay(["--json-ui"], settings, journal, env, stdout_fd=write_fd,
                                      spill_write=spill_write, replay_write=replay_write)
            write_fd = None
        finally:
            if write_fd is not None:
                os.close(write_fd)
            reader.join(10)
            os.close(read_fd)
        return status, bytes(received), journal.record, relay_state

    def test_short_replay_writes_keep_order_and_hash(self):
        payload = self.root / "payload.bin"
        payload.write_bytes(os.urandom(256 * 1024))

        def short(fd, view):
            return os.write(fd, view[:1000])

        status, received, record, _ = self.run_in_process(payload, replay_write=short)
        self.assertEqual((status, received), (0, payload.read_bytes()))
        self.assertEqual(record["replay_sha256"], stdout_relay.file_sha256(payload))

    def test_group_signals_are_ignored_while_the_relay_stops_and_reaps_cbmc(self):
        payload = self.root / "payload.bin"
        payload.write_bytes(os.urandom(512 * 1024))
        names = cbmc_relay.TERMINATION_SIGNALS
        seen = []
        real_stop = cbmc_relay.stop_child

        def stop(proc, grace):
            seen.append({name: signal.getsignal(getattr(signal, name)) for name in names})
            return real_stop(proc, grace)

        def full(fd, view):
            raise OSError(errno.ENOSPC, "No space left on device")

        with patch.object(cbmc_relay, "stop_child", side_effect=stop), self.assertRaises(cbmc_relay.RelayFailure):
            self.run_in_process(payload, spill_write=full)
        self.assertEqual(seen, [{name: signal.SIG_IGN for name in names}])

    def test_spill_write_error_reaps_cbmc_and_keeps_no_replay(self):
        payload = self.root / "payload.bin"
        payload.write_bytes(os.urandom(512 * 1024))

        def full(fd, view):
            raise OSError(errno.ENOSPC, "No space left on device")

        with self.assertRaises(cbmc_relay.RelayFailure) as caught:
            self.run_in_process(payload, spill_write=full)
        self.assertEqual(caught.exception.outcome, "SPILL_WRITE_ERROR")


class RelaySupervisionTests(RelayFixture):

    def supervise(self, directory, env, argv, seconds):
        memory = {"physical_kib": 64 * spec.GIB_KIB, "available_kib": 32 * spec.GIB_KIB, "pressure": "CLEAR"}
        telemetry = MemoryTelemetry(None, relay_phase=stdout_relay.phase_probe(self.relay_state["journal_dir"]))
        child = supervisor.run([sys.executable, "-I", "-c", DRIVER, *argv], cwd=directory, env=env,
                               directory=directory, deadline=time.monotonic() + seconds, nominal_kib=8 * spec.GIB_KIB,
                               reserve_kib=spec.MIB, term_grace=1.0, kill_grace=1.0, memory_probe=lambda: memory,
                               sample_interval=0.1, diagnostics=telemetry)
        return child, telemetry

    def test_group_stop_cancels_relay_reaps_cbmc_and_reads_the_spill_prefix(self):
        payload = self.root / "payload.json"
        payload.write_bytes(json_ui_payload(b"Starting Bounded Model Checking\n", {}, 200))
        directory, self.relay_state = self.slot()
        env = self.env(directory, payload, relay_state=self.relay_state, mode="hang")
        child, telemetry = self.supervise(directory, env, ["--json-ui"], 3.0)
        self.assertEqual((child["stop_reason"], child["reaped"]), ("TIMEOUT", True))
        self.assertEqual(child["remaining_processes"], [])
        self.assertEqual((directory / "stdout.log").read_bytes(), b"")
        call = self.journals(self.relay_state)["SPILL_THEN_REPLAY"]
        self.assertEqual((call["outcome"], call["signal"]), ("CANCELLED", signal.SIGTERM))
        self.assertIn(call["cbmc_returncode"], (-signal.SIGTERM, -signal.SIGKILL))
        self.assertNotIn("replay_first_byte_monotonic", call)
        self.assertEqual(len(os.listdir(self.relay_state["spill_dir"])), 1)
        judged = stdout_relay.collect(self.relay_state, directory, child, config=self.config)
        self.assertEqual(judged["status"], "INCOMPLETE")
        self.assertIn("relay outcome CANCELLED", judged["reasons"])
        self.assertIn("spill was not removed by a complete replay", judged["reasons"])
        # Judgement leaves the spill; the prefix read is a separate step after projection.
        self.assertEqual(len(os.listdir(self.relay_state["spill_dir"])), 1)
        drained = stdout_relay.drain_spill(self.relay_state, self.config)
        prefix, = drained["spill_prefix"].values()
        self.assertEqual((prefix["first_cnf"]["variables"], prefix["first_cnf"]["clauses"]), (4956964, 25517502))
        self.assertTrue(drained["spill_removed_after_reap"])
        self.assertEqual(os.listdir(self.relay_state["spill_dir"]), [])
        census = telemetry.census_publication()
        self.assertTrue(census["relay_phase_probe"])
        self.assertIn("group_peak_before_wait_done", census["samples"])
        last = census["samples"]["last"]
        self.assertTrue(any(process["pid"] == call["relay_pid"] and not process["cbmc"]
                            for process in last["processes"]))

    def test_complete_supervised_relay_is_judged_complete_only_with_its_evidence(self):
        payload = self.root / "payload.json"
        payload.write_bytes(json_ui_payload(b"VERIFICATION:- FAILED\n", {}, 12000))
        directory, self.relay_state = self.slot()
        goto = directory / "cargo-target" / "core.out"
        argv = cbmc_argv(goto)
        command = "[Kani] Running: `cbmc " + " ".join(argv) + "`\n"
        env = self.env(directory, payload, relay_state=self.relay_state, exit_code=10, linger=0.5)
        env["DRIVER_DELAY"] = "0.02"
        child, telemetry = self.supervise(directory, env, argv, 20.0)
        self.assertEqual((child["stop_reason"], child["reaped"], child["exit_code"]), ("EXITED", True, 1))
        self.assertEqual(stdout_relay.file_sha256(directory / "stdout.log"), stdout_relay.file_sha256(payload))
        call = self.journals(self.relay_state)["SPILL_THEN_REPLAY"]
        # The synthetic CBMC runs under python3, so the census cannot name it; supply the PID it would see.
        observed = child | {"cbmc_pid_transitions": [{"at": 0, "pids": [call["cbmc_pid"]]}]}
        (directory / "stdout.log").write_text(command + "rendered output\n")
        judged = stdout_relay.collect(self.relay_state, directory, observed, config=self.config)
        self.assertEqual((judged["status"], judged["reasons"]), ("COMPLETE", []))
        self.assertTrue(judged["kani_command_matches"])
        self.assertFalse(judged["relay_counted_as_cbmc"])
        samples = telemetry.census_publication()["samples"]
        self.assertIn("group_peak_replay", samples)
        self.assertIn("group_peak_before_wait_done", samples)
        for key, update, reason in (
            ("cbmc_pid_transitions", [{"at": 0, "pids": [call["cbmc_pid"], call["relay_pid"]]}],
             "relay was counted"),
            ("cbmc_pid_transitions", [], "real CBMC PID was not observed"),
            ("pgid", 1, "process group"),
            ("monotonic_observation_end", call["relay_start_monotonic"], "phase marks"),
        ):
            with self.subTest(key=key, reason=reason):
                rejected = stdout_relay.collect(self.relay_state, directory, observed | {key: update}, config=self.config)
                self.assertEqual(rejected["status"], "INCOMPLETE")
                self.assertTrue(any(reason in item for item in rejected["reasons"]), rejected["reasons"])
        (directory / "stdout.log").write_text(command.replace("--slice-formula ", "") + "rendered output\n")
        rejected = stdout_relay.collect(self.relay_state, directory, observed, config=self.config)
        self.assertIn("relay argv differs from the Kani verbose CBMC command", rejected["reasons"])


class RelayRunnerTests(RelayFixture):
    def test_measure_slot_keeps_s8_and_u64_on_the_stock_pipe_and_judges_the_wide_relay_slot(self):
        payload = self.root / "payload.json"
        payload.write_bytes(json_ui_payload(b"VERIFICATION:- FAILED\n", {}, 2000))
        request = deepcopy(FROZEN)
        request["stdout_relay"] = self.config
        slots = run.expected_slots(request)
        self.assertEqual([slot[0] for slot in slots], list(spec.SLOT_IDS))
        self.assertEqual(slots[-1][0], RELAY_ID)
        stock_ids = spec.SLOT_IDS[:-1]
        state = self.root / "state"
        memory = {"physical_kib": 64 * spec.GIB_KIB, "available_kib": 32 * spec.GIB_KIB, "pressure": "CLEAR"}
        launched = {}

        def argv(std, tool, directory, row, request):
            return [sys.executable, "-I", "-c", DRIVER, *cbmc_argv(directory / "cargo-target" / "core.out")]

        environment = self.env(self.root, payload, exit_code=10) | {"DRIVER_ECHO": "1"}
        environment["PATH"] = str(self.real_dir) + os.pathsep + os.environ["PATH"]
        real_invoke = run.invoke

        def invoke(*args, **kwargs):
            launched[kwargs["directory"].name] = kwargs.get("path_prefix")
            if kwargs.get("path_prefix") is None:
                return {"status": "COMPLETED", "stop_reason": "EXITED", "exit_code": 1, "reaped": True}
            return real_invoke(*args, **kwargs)

        with (patch.dict(os.environ, environment), patch.object(run, "verify_argv", side_effect=argv),
              patch.object(run, "invoke", side_effect=invoke),
              patch.object(supervisor, "memory_snapshot", return_value=memory)):
            for slot in slots:
                record = run.measure_slot(state, self.root, self.root, request, slot, time.monotonic() + 30,
                                          setup={"tool": self.setup_tool})
        # The left S8 and the u64 control keep the stock PATH; only the Wide control gets the prefix.
        self.assertEqual({key: launched[key] for key in stock_ids}, dict.fromkeys(stock_ids))
        self.assertEqual(record["id"], RELAY_ID)
        prefix = launched[RELAY_ID]
        self.assertEqual(prefix, str(state / "work" / RELAY_ID / "relay" / "bin"))
        self.assertEqual(record["env"]["PATH_PREFIX"], prefix)
        relay = record["stdout_relay"]
        self.assertEqual(relay["real_cbmc"]["sha256"], self.setup_tool["binaries"]["cbmc"]["sha256"])
        self.assertEqual(relay["call"]["outcome"], "COMPLETE")
        self.assertTrue(relay["kani_command_matches"])
        # The synthetic CBMC runs under python3, so only the census attribution is missing.
        self.assertEqual(relay["reasons"], ["the real CBMC PID was not observed by the census"])
        self.assertEqual(relay["status"], "INCOMPLETE")
        self.assertEqual(os.listdir(state / "work" / RELAY_ID / "relay" / "spill"), [])
        self.assertIn("group_census", record["memory_telemetry"])
        for key in stock_ids:
            stock = spec.read(state / "artifact" / "slots" / key / "receipt.json")
            self.assertNotIn("stdout_relay", stock)
            self.assertEqual(stock["stdout_delivery"], "STOCK_PIPE")
            self.assertNotIn("PATH_PREFIX", stock["env"])

    def test_rss_stop_keeps_census_and_full_spill_prefix_inside_the_real_receipt_window(self):
        """A worst-case 16 MiB prefix of short native messages, parsed after projection under receipt_seconds."""
        request = deepcopy(FROZEN)
        request["stdout_relay"] = self.config | {"spill_prefix_read_bytes": spec.STDOUT_RELAY["spill_prefix_read_bytes"]}
        n16 = RELAY_SLOT
        state = self.root / "state"
        message = b'  {\n    "messageText": "Runtime Symex: 0.1s",\n    "messageType": "STATUS-MESSAGE"\n  },\n'
        head = (b'[\n  {\n    "messageText": "converting SSA",\n    "messageType": "STATUS-MESSAGE"\n  },\n'
                b'  {\n    "messageText": "4956964 variables, 25517502 clauses",\n    "messageType": "STATUS-MESSAGE"\n  },\n')
        spill_bytes = head + message * (17 * spec.MIB // len(message))
        self.assertGreater(len(spill_bytes), spec.STDOUT_RELAY["spill_prefix_read_bytes"])

        def invoke(*args, **kwargs):
            directory = kwargs["directory"]
            relay_dir = directory / "relay"
            (relay_dir / "spill" / "spill-11.bin").write_bytes(spill_bytes)
            (relay_dir / "journal" / "invocation-11.json").write_text(json.dumps(
                {"mode": "SPILL_THEN_REPLAY", "outcome": "CANCELLED", "phase": "CBMC_RUNNING", "relay_pid": 11,
                 "cbmc_pid": 12, "signal": 15, "replay_complete": False}))
            (directory / "stdout.log").write_text("Checking harness x...\n")
            (directory / "stderr.log").write_text("")
            diagnostics = kwargs["diagnostics"]
            for at, rss in ((1.0, 3 * spec.GIB_KIB), (2.0, 4 * spec.GIB_KIB + 5)):
                diagnostics.observe({"rss_kib": rss + 900000, "phase": "cbmc", "verifier_pids": [12],
                                     "records": [{"pid": 7, "ppid": 1, "start_id": 70, "rss": 900000, "image": "kani"},
                                                 {"pid": 11, "ppid": 7, "start_id": 110, "rss": 9000, "image": "python3"},
                                                 {"pid": 12, "ppid": 11, "start_id": 120, "rss": rss, "image": "cbmc"}],
                                     "pid_records_skipped": 0}, at)
            now = time.monotonic()
            return {"status": "COMPLETED", "stop_reason": "RSS_LIMIT", "exit_code": -15, "reaped": True,
                    "sampler_valid": True, "stdout_complete": True, "stderr_complete": True, "pgid": 7,
                    "monotonic_start": now - 3, "monotonic_observation_end": now - 0.5,
                    "cbmc_pid_transitions": [{"at": 1.0, "pids": [12]}], "peak_rss_kib": 5 * spec.GIB_KIB}

        environment = {"PATH": str(self.real_dir) + os.pathsep + os.environ["PATH"]}
        with patch.dict(os.environ, environment), patch.object(run, "invoke", side_effect=invoke):
            started = time.monotonic()
            record = run.measure_slot(state, self.root, self.root, request, n16, time.monotonic() + 30,
                                      setup={"tool": self.setup_tool})
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, spec.LIMITS["receipt_seconds"] - run.RECEIPT_COMMIT_RESERVE_SECONDS)
        saved = spec.read(state / "artifact" / "slots" / RELAY_ID / "receipt.json")
        self.assertEqual(saved["outcome"], "RSS_LIMIT")
        self.assertNotEqual(saved["projection_status"], "DEADLINE")
        self.assertFalse(saved.get("receipt_deadline_exceeded"))
        relay = saved["stdout_relay"]
        prefix = relay["spill_prefix"]["spill-11.bin"]
        self.assertEqual((prefix["first_cnf"]["variables"], prefix["first_cnf"]["clauses"]), (4956964, 25517502))
        self.assertEqual(prefix["prefix_bytes_read"], spec.STDOUT_RELAY["spill_prefix_read_bytes"])
        self.assertEqual((prefix["native_messages"], prefix["marker_scan_limit_reached"]),
                         (stdout_relay.MARKER_SCAN_LIMIT, True))
        self.assertGreater(prefix["messages"], stdout_relay.MARKER_SCAN_LIMIT)
        self.assertNotIn("spill_prefix_reason", relay)
        self.assertTrue(relay["spill_removed_after_reap"])
        self.assertEqual(os.listdir(state / "work" / RELAY_ID / "relay" / "spill"), [])
        self.assertEqual((saved["stdout_delivery"], relay["status"]), ("INCOMPLETE", "INCOMPLETE"))
        census = saved["memory_telemetry"]["group_census"]["samples"]
        self.assertEqual(census["group_peak"]["group_rss_kib"], 4 * spec.GIB_KIB + 5 + 900000)
        self.assertEqual([row["image"] for row in census["group_peak"]["processes"]], ["cbmc", "kani", "python3"])
        # The same prefix also fits the window alone, measured against the projection budget.
        spill = self.root / "alone.bin"
        spill.write_bytes(spill_bytes)
        with run.receipt_window(time.monotonic() + spec.LIMITS["receipt_seconds"] - run.RECEIPT_COMMIT_RESERVE_SECONDS):
            alone = stdout_relay.spill_prefix_markers(spill, spec.STDOUT_RELAY["spill_prefix_read_bytes"])
        self.assertTrue(alone["native_marker_found"])

    def test_cnf_after_thousands_of_unwinding_messages_is_found_inside_the_window(self):
        """R2: ordinary CBMC messages must not exhaust the budget before the first CNF."""
        def message(text):
            return b'  {\n    "messageText": "' + text + b'",\n    "messageType": "STATUS-MESSAGE"\n  },\n'

        loop = (b"Unwinding loop core::slice::sort::shared::smallsort::insert_tail::<slice::sort::shared::smallsort::"
                b"verify::rev2_gen_stable_n16_pilot::Wide, &mut fn(&Wide, &Wide) -> bool>.0 iteration %d file "
                b"/home/runner/work/kani/kani/std/library/core/src/slice/sort/shared/smallsort.rs line 713 column 9 "
                b"function slice::sort::shared::smallsort::insert_tail thread 0")
        unwinding = b"".join(message(loop % (index % 36)) for index in range(8000))
        self.assertGreater(len(unwinding), 2 * spec.MIB)
        tail = b"".join(message(text) for text in (
            b"Runtime Symex: 21.3s", b"size of program expression: 120921 steps",
            b"Generated 1712 VCC(s), 1689 remaining after simplification", b"converting SSA",
            b"Runtime Convert SSA: 9.1s", b"Running propositional reduction", b"Solving with CaDiCaL 3.0.0",
            b"4956964 variables, 25517502 clauses"))
        trace = b'  {\n    "stepType": "assignment", "value": "' + b"a" * 4000 + b'"\n  },\n'
        data = (b"[\n" + message(b"CBMC version 6.11.0 (cbmc-6.11.0) 64-bit x86_64 linux")
                + message(b"Starting Bounded Model Checking") + unwinding + tail)
        data += trace * ((17 * spec.MIB - len(data)) // len(trace) + 1)
        directory, relay_state = self.slot()
        spill = Path(relay_state["spill_dir"]) / "spill-11.bin"
        spill.write_bytes(data)
        window = spec.LIMITS["receipt_seconds"] - run.RECEIPT_COMMIT_RESERVE_SECONDS
        started = time.monotonic()
        with run.receipt_window(time.monotonic() + window, "spill prefix"):
            drained = stdout_relay.drain_spill(relay_state, spec.STDOUT_RELAY)
        self.assertLess(time.monotonic() - started, window)
        prefix = drained["spill_prefix"]["spill-11.bin"]
        cnf = prefix["first_cnf"]
        self.assertEqual((cnf["variables"], cnf["clauses"], cnf["solve_context"]), (4956964, 25517502, "INITIAL_SOLVE"))
        self.assertEqual(prefix["messages"], 8010)
        self.assertEqual(prefix["native_messages"], 9)
        self.assertFalse(prefix["prefix_complete"])
        kinds = [marker["kind"] for marker in prefix["markers"]]
        self.assertEqual(kinds, ["symex_start", "symex_seconds", "symex_steps", "vcc", "ssa_start", "ssa_seconds",
                                 "sat_start", "sat_start"])
        self.assertNotIn("spill_prefix_reason", drained)
        self.assertTrue(drained["spill_removed_after_reap"])

    def test_missing_cnf_reasons_separate_the_scan_bound_from_an_absent_marker(self):
        def message(text):
            return b'{"messageText": "' + text + b'"},\n'

        cases = (
            (message(b"Runtime Solver: 0.1s") * (stdout_relay.MARKER_SCAN_LIMIT + 1)
             + message(b"13 variables, 26 clauses"), "CNF_NOT_FOUND_BEFORE_MARKER_SCAN_LIMIT"),
            (message(b"Starting Bounded Model Checking") + message(b"Unwinding loop x.0 iteration 1"), "NO_CNF_IN_PREFIX"),
            (message(b"Unwinding loop x.0 iteration 1") * 3, "NO_RECOGNIZED_NATIVE_MARKER_IN_PREFIX"),
            (message(b"13 variables, 26 clauses"), None),
        )
        for data, reason in cases:
            with self.subTest(reason=reason):
                directory, relay_state = self.slot()
                (Path(relay_state["spill_dir"]) / "spill-11.bin").write_bytes(data)
                self.assertEqual(stdout_relay.drain_spill(relay_state, self.config).get("spill_prefix_reason"), reason)

    def test_spill_prefix_deadline_is_recorded_and_the_spill_still_removed(self):
        request = deepcopy(FROZEN)
        request["stdout_relay"] = self.config
        n16 = RELAY_SLOT
        state = self.root / "state"

        def invoke(*args, **kwargs):
            (kwargs["directory"] / "relay" / "spill" / "spill-11.bin").write_bytes(b"x")
            return {"status": "COMPLETED", "stop_reason": "RSS_LIMIT", "reaped": True, "sampler_valid": True}

        def slow(*args):
            raise run.ReceiptDeadlineExceeded("spill prefix window exhausted")

        with (patch.dict(os.environ, {"PATH": str(self.real_dir) + os.pathsep + os.environ["PATH"]}),
              patch.object(run, "invoke", side_effect=invoke), patch.object(stdout_relay, "drain_spill", side_effect=slow)):
            record = run.measure_slot(state, self.root, self.root, request, n16, time.monotonic() + 30,
                                      setup={"tool": self.setup_tool})
        self.assertEqual(record["stdout_relay"]["spill_prefix_reason"], "SPILL_PREFIX_DEADLINE")
        self.assertEqual(os.listdir(state / "work" / RELAY_ID / "relay" / "spill"), [])
        self.assertEqual(spec.read(state / "artifact" / "slots" / RELAY_ID / "receipt.json")
                         ["stdout_relay"]["spill_prefix_reason"], "SPILL_PREFIX_DEADLINE")

    def test_unavailable_relay_never_starts_its_slot(self):
        request = deepcopy(FROZEN)
        request["stdout_relay"] = self.config
        with patch.object(run, "invoke") as invoke:
            record = run.measure_slot(self.root / "state", self.root, self.root, request, RELAY_SLOT,
                                      time.monotonic() + 30, setup={"tool": {"binaries": {}}})
        invoke.assert_not_called()
        self.assertEqual((record["outcome"], record["reason"]), ("NOT_STARTED", "STDOUT_RELAY_UNAVAILABLE"))
        self.assertEqual(record["stdout_relay"]["status"], "NOT_INSTALLED")

    def test_relay_named_for_any_stock_pipe_slot_never_starts_that_slot(self):
        stock = [slot for slot in run.expected_slots(FROZEN) if slot[0] != spec.RELAY_SLOT_ID]
        self.assertEqual([slot[2][0]["stdout_delivery"] for slot in stock], ["STOCK_PIPE"] * 2)
        for index, slot in enumerate(stock):
            with self.subTest(slot=slot[0]):
                request = deepcopy(FROZEN)
                request["stdout_relay"] = self.config | {"slot": slot[0]}
                with patch.object(run, "invoke") as invoke, patch.object(stdout_relay, "install") as install:
                    record = run.measure_slot(self.root / f"state-{index}", self.root, self.root, request, slot,
                                              time.monotonic() + 30, setup={"tool": self.setup_tool})
                invoke.assert_not_called()
                install.assert_not_called()
                self.assertEqual((record["outcome"], record["reason"]), ("NOT_STARTED", "STDOUT_DELIVERY_CONFLICT"))
                saved = spec.read(self.root / f"state-{index}" / "artifact" / "slots" / slot[0] / "receipt.json")
                self.assertEqual(saved["stdout_relay"]["status"], "REFUSED")

    def test_frozen_relay_slot_never_runs_on_the_stock_pipe(self):
        """The Wide control is frozen as STDOUT_RELAY: if the relay names another slot, it is refused, never stock."""
        wide = run.expected_slots(FROZEN)[-1]
        self.assertEqual((wide[0], wide[2][0]["stdout_delivery"]), (spec.RELAY_SLOT_ID, "STDOUT_RELAY"))
        for index, other in enumerate((spec.SLOT_IDS[0], None)):
            with self.subTest(relay_slot=other):
                request = deepcopy(FROZEN)
                request["stdout_relay"] = self.config | {"slot": other}
                with patch.object(run, "invoke") as invoke, patch.object(stdout_relay, "install") as install:
                    record = run.measure_slot(self.root / f"wide-{index}", self.root, self.root, request, wide,
                                              time.monotonic() + 30, setup={"tool": self.setup_tool})
                invoke.assert_not_called()
                install.assert_not_called()
                self.assertEqual((record["outcome"], record["reason"]), ("NOT_STARTED", "STDOUT_DELIVERY_CONFLICT"))
                self.assertIn("is not the configured relay slot", record["stdout_relay"]["error"])
        # A relay slot whose frozen row lost its label is refused as well, before any install.
        unlabelled = (wide[0], wide[1], [wide[2][0] | {"stdout_delivery": "STOCK_PIPE"}], wide[3])
        request = deepcopy(FROZEN)
        request["stdout_relay"] = self.config
        with patch.object(run, "invoke") as invoke, patch.object(stdout_relay, "install") as install:
            record = run.measure_slot(self.root / "wide-unlabelled", self.root, self.root, request, unlabelled,
                                      time.monotonic() + 30, setup={"tool": self.setup_tool})
        invoke.assert_not_called()
        install.assert_not_called()
        self.assertEqual((record["reason"], record["stdout_relay"]["error"]),
                         ("STDOUT_DELIVERY_CONFLICT", "relay configured for a STOCK_PIPE slot"))


class RelayJudgementTests(RelayFixture):
    def judged(self, mutate):
        directory, relay_state = self.slot()
        goto = directory / "cargo-target" / "core.out"
        argv = cbmc_argv(goto)
        (directory / "stdout.log").write_text("[Kani] Running: `cbmc " + " ".join(argv) + "`\n")
        digest = "a" * 64
        call = {"mode": "SPILL_THEN_REPLAY", "outcome": "COMPLETE", "phase": "REPLAY_DONE", "relay_pid": 11,
                "relay_pgid": 7, "relay_sid": 7, "cbmc_pid": 12, "cbmc_pgid": 7, "cbmc_sid": 7, "cbmc_returncode": 10,
                "argv": argv, "argv_count": len(argv), "argv_complete": True, "argv_sha256": cbmc_relay.argv_digest(argv),
                "cwd": str(directory), "spill_bytes": 5, "spill_sha256": digest, "replay_bytes": 5,
                "replay_sha256": digest, "replay_complete": True, "spill_removed": True, "relay_start_monotonic": 2,
                "cbmc_start_monotonic": 3, "wait_done_monotonic": 4, "replay_start_monotonic": 5,
                "replay_first_byte_monotonic": 6, "replay_end_monotonic": 7, "relay_end_monotonic": 8}
        version = {"mode": "VERSION_PASSTHROUGH", "argv": ["--version"], "relay_pid": 9, "phase": "EXEC"}
        journals = [version, call]
        child = {"pgid": 7, "monotonic_start": 1, "monotonic_observation_end": 9, "reaped": True,
                 "cbmc_pid_transitions": [{"at": 3, "pids": [12]}]}
        mutate(journals, child, Path(relay_state["spill_dir"]))
        for index, record in enumerate(journals):
            (Path(relay_state["journal_dir"]) / f"invocation-{index + 1}.json").write_text(json.dumps(record))
        return stdout_relay.collect(relay_state, directory, child, config=self.config)

    def test_collect_accepts_one_complete_call_and_rejects_each_broken_binding(self):
        self.assertEqual(self.judged(lambda journals, child, spill: None)["status"], "COMPLETE")

        def call(update):
            return lambda journals, child, spill: journals[1].update(update)

        cases = (
            (call({"outcome": "REPLAY_INCOMPLETE", "replay_complete": False}), "relay outcome"),
            (call({"replay_sha256": "b" * 64}), "SHA-256 differ"),
            (call({"replay_bytes": 4}), "SHA-256 differ"),
            (call({"replay_first_byte_monotonic": 3.5}), "out of order"),
            (call({"wait_done_monotonic": None}), "out of order"),
            (call({"argv": ["--json-ui"], "argv_sha256": cbmc_relay.argv_digest(["--json-ui"])}), "argv has"),
            (call({"argv_sha256": "c" * 64}), "argv record"),
            (call({"cbmc_sid": 99}), "session or process group"),
            (call({"cbmc_returncode": -9}), "did not exit normally"),
            (call({"spill_bytes": 5 + (1 << 40), "replay_bytes": 5 + (1 << 40)}), "exceeded its cap"),
            (call({"cwd": "/elsewhere"}), "cwd"),
            (lambda journals, child, spill: journals.append(dict(journals[1], relay_pid=13)), "2 JSON-UI relay calls"),
            (lambda journals, child, spill: journals.pop(), "0 JSON-UI relay calls"),
            (lambda journals, child, spill: journals.append({"mode": "OTHER_PASSTHROUGH", "argv": ["--help"]}),
             "non-version passthrough"),
            (lambda journals, child, spill: (spill / "spill-11.bin").write_bytes(b"x"), "spill was not removed"),
        )
        for mutate, reason in cases:
            with self.subTest(reason=reason):
                judged = self.judged(mutate)
                self.assertEqual(judged["status"], "INCOMPLETE")
                self.assertTrue(any(reason in item for item in judged["reasons"]), judged["reasons"])
        # Goto files must stay inside the slot directory.
        outside = cbmc_argv(Path("/tmp/other.out"))
        judged = self.judged(call({"argv": outside, "argv_sha256": cbmc_relay.argv_digest(outside)}))
        self.assertIn("CBMC goto binary is outside the slot directory", judged["reasons"])

    def test_unconfirmed_reap_keeps_the_spill(self):
        def unreaped(journals, child, spill):
            child["reaped"] = False
            (spill / "spill-11.bin").write_bytes(b"x")

        judged = self.judged(unreaped)
        self.assertEqual(judged["spill_prefix_reason"], "REAP_UNCONFIRMED_SPILL_KEPT")

    def test_census_never_counts_the_relay_interpreter_as_cbmc(self):
        table = {
            7: {"pid": 7, "ppid": 1, "pgid": 7, "state": "S", "start_id": 70, "rss": 500, "image": "kani"},
            11: {"pid": 11, "ppid": 7, "pgid": 7, "state": "S", "start_id": 110, "rss": 9, "image": "python3"},
            12: {"pid": 12, "ppid": 11, "pgid": 7, "state": "R", "start_id": 120, "rss": 3000, "image": "cbmc"},
        }
        with patch.object(supervisor, "process_table", return_value=table):
            sample = supervisor._default_sample(7)
        self.assertEqual((sample["verifier_pids"], sample["rss_kib"]), ([12], 3509))
        telemetry = MemoryTelemetry(None, relay_phase=lambda: "CBMC_RUNNING")
        telemetry.observe(sample | {"pid_records_skipped": 0}, 1.0)
        entry = telemetry.census_publication()["samples"]["group_peak_before_wait_done"]
        self.assertEqual([(row["pid"], row["cbmc"]) for row in entry["processes"]], [(12, True), (7, False), (11, False)])
        self.assertTrue(entry["attribution_complete"])
        crowded = dict(sample, records=[dict(table[7], pid=100 + i, start_id=i) for i in range(70)],
                       pid_records_skipped=1)
        telemetry.relay_phase = lambda: "REPLAYING"
        telemetry.observe(crowded, 2.0)
        replay = telemetry.census_publication()["samples"]["group_peak_replay"]
        self.assertEqual((len(replay["processes"]), replay["processes_omitted"]), (64, 6))
        self.assertFalse(replay["attribution_complete"])



class RelayRequestTests(unittest.TestCase):
    def test_relay_source_stays_frozen_and_names_only_the_wide_control(self):
        self.assertEqual(FROZEN["stdout_relay"], spec.STDOUT_RELAY)
        self.assertEqual(FROZEN["stdout_relay"]["slot"], "GEN-N32-WIDE-WITNESS-CORRUPT")
        self.assertEqual(spec.RELAY_SLOT_ID, "GEN-N32-WIDE-WITNESS-CORRUPT")
        self.assertEqual([row["stdout_delivery"] for row in FROZEN["roster"]], ["STOCK_PIPE", "STOCK_PIPE", "STDOUT_RELAY"])
        self.assertEqual(FROZEN["stdout_relay"]["mode"], "SPILL_THEN_REPLAY")
        self.assertEqual(FROZEN["stdout_relay"]["source_sha256"],
                         "c8b4c070dbd12a8acafa4b23df0b74833b600333f539b66fc9d27eccee3613b7")
        self.assertEqual((spec.STDOUT_RELAY["chunk_bytes"], spec.STDOUT_RELAY["spill_cap_bytes"],
                          spec.STDOUT_RELAY["disk_reserve_bytes"]), (64 * 1024, 4 * 1024 ** 3, 2 * 1024 ** 3))
        self.assertEqual(stdout_relay.file_sha256(spec.HERE / "cbmc_relay.py"), spec.RELAY_SOURCE_SHA256)
        with tempfile.TemporaryDirectory() as temp:
            for update in (*({"slot": slot} for slot in (*spec.SLOT_IDS[:2], None, spec.N14_WITNESS_SLOT_ID,
                                                         spec.WIDE_WITNESS_SLOT_ID)),
                           {"spill_cap_bytes": 8 * 1024 ** 3}, {"disk_reserve_bytes": 1024 ** 3},
                           {"mode": "STREAM"}, {"expected_cbmc_argv": spec.EXPECTED_CBMC_ARGV[:-1]},
                           {"source_sha256": "0" * 64}):
                with self.subTest(update=update):
                    run.dump(Path(temp) / "CI-REQUEST.json", FROZEN | {"stdout_relay": FROZEN["stdout_relay"] | update})
                    with self.assertRaisesRegex(ValueError, "frozen request mismatch for stdout_relay"):
                        spec.load(Path(temp), verify_bundle=False)
            # A roster row that changes its frozen delivery is rejected even with an unchanged relay block,
            # also when the digests are recomputed for the changed roster.
            for index, delivery in ((0, "STDOUT_RELAY"), (1, "STDOUT_RELAY"), (2, "STOCK_PIPE"), (2, "COMPLETE"),
                                    (0, None)):
                bad = deepcopy(FROZEN)
                bad["roster"][index]["stdout_delivery"] = delivery
                bad["source_bindings"]["n32_closure_roster"] = bad["roster"]
                run.dump(Path(temp) / "CI-REQUEST.json", bad)
                with self.subTest(row=index, delivery=delivery):
                    with self.assertRaisesRegex(ValueError, "mismatch"):
                        spec.load(Path(temp), verify_bundle=False)
                    with patch.object(spec, "ROSTER_DIGEST", spec.roster_digest(bad["roster"])), \
                            patch.object(spec, "SOURCE_BINDINGS_DIGEST", spec.roster_digest(bad["source_bindings"])), \
                            self.assertRaisesRegex(ValueError, "stdout delivery must be stock for S8 and u64"):
                        spec.load(Path(temp), verify_bundle=False)
        with patch.object(spec, "RELAY_SOURCE_SHA256", "0" * 64), \
                self.assertRaisesRegex(ValueError, "frozen request mismatch|relay source digest"):
            spec.load()

    def test_summary_reports_delivery_and_spill_prefix_without_upgrading_the_slot(self):
        import report

        records = []
        for slot in run.expected_slots(FROZEN):
            record = run.receipt(slot, "RSS_LIMIT", "RSS_LIMIT")
            record.update(child={"exit_code": None, "reaped": True, "sampler_valid": True}, censored=True,
                          last_phase="cbmc")
            if slot[0] == spec.SLOT_IDS[1]:
                # A stray relay record on a stock slot is reported and withholds that slot.
                record["stdout_relay"] = {"status": "INCOMPLETE", "reasons": ["relay outcome CANCELLED"],
                                          "call": {"outcome": "CANCELLED", "spill_bytes": 4096, "replay_bytes": None},
                                          "spill_prefix": {"spill-1.bin": {"first_cnf": {"variables": 4956964,
                                                                                         "clauses": 25517502}}}}
            records.append(record)
        summary = report.summarize({"run_id": "1", "attempt": "1", "arch": "X64"}, records, "Linux", None,
                                   {"status": "COMPLETE", "started_monotonic": 1, "finished_monotonic": 2,
                                    "deadline_monotonic": 3})
        self.assertEqual(summary["slot_diagnoses"], {key: "OPEN" for key in spec.SLOT_IDS})
        self.assertEqual([row["stdout_relay"] is None for row in summary["rows"]], [True, False, True])
        self.assertEqual(summary["rows"][1]["profile"]["stdout_delivery"], "NOT_STOCK_PIPE")
        # The Wide relay slot without any relay record is INCOMPLETE, never stock.
        self.assertEqual((summary["rows"][2]["profile"]["delivery_route"], summary["rows"][2]["profile"]["stdout_delivery"]),
                         ("STDOUT_RELAY", "INCOMPLETE"))
        self.assertEqual(summary["type_diagnoses"], {"STABLE_U64": "OPEN", "GENERAL_WIDE": "OPEN"})
        with tempfile.TemporaryDirectory() as temp:
            report.write_summary(Path(temp), summary)
            text = (Path(temp) / "SUMMARY.md").read_text()
        self.assertIn("stdout delivery is INCOMPLETE, relay outcome CANCELLED", text)
        header = next(line for line in text.splitlines() if line.startswith("| Slot |"))
        separator = text.splitlines()[text.splitlines().index(header) + 1]
        self.assertIn("| Expected result | Stdout delivery |", header)
        self.assertEqual(header.count("|"), separator.count("|"))
        rows = [line for line in text.splitlines() if line.startswith("| GEN-")]
        # Receipts without a judged child carry no delivery yet, so no slot reads as STOCK_PIPE here.
        self.assertEqual([row.split(" | ")[6] for row in rows],
                         ["STOCK_PIPE NOT_STOCK_PIPE", "STOCK_PIPE NOT_STOCK_PIPE", "STDOUT_RELAY INCOMPLETE"])
        self.assertIn("first CNF of 4956964 variables / 25517502 clauses", text)

if __name__ == "__main__":
    unittest.main()
