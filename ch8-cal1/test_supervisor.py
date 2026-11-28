"""Synthetic tests for CAL1 resource supervision; no Kani/Rust/CBMC execution."""
import ctypes
import errno
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, mock_open, patch

import supervisor


FIXTURE_WAIT = 6

WAIT_FOR_RELEASE = """import time
from pathlib import Path
until = time.monotonic() + 15
while not Path('release').exists():
    if time.monotonic() >= until:
        raise SystemExit('test never released child')
    time.sleep(.005)
"""

PUBLISH_PID = """from pathlib import Path
import os
Path('ready.tmp').write_text(str(os.getpid()))
Path('ready.tmp').replace('ready')
"""

IGNORE_TERM = "import signal\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\n" + PUBLISH_PID + "signal.pause()"


class PlainOSError(OSError):
    """Exercise an errno-carrying error without Python's automatic subclass."""


class SupervisorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def memory(self, *, available=8_000_000, pressure="CLEAR"):
        return {"physical_kib": 16_000_000, "available_kib": available,
                "pressure": pressure}

    def invoke(self, code, **kwargs):
        deadline = kwargs.pop("deadline", time.monotonic() + 4)
        sample_interval = kwargs.pop("sample_interval", .03)
        term_grace = kwargs.pop("term_grace", .2)
        kill_grace = kwargs.pop("kill_grace", .5)
        kwargs.setdefault("memory_probe", self.memory)
        argv = [sys.executable, "-c", code]
        native_popen = subprocess.Popen
        proc = None

        def launch(command, *args, **kwargs):
            nonlocal proc
            launched = native_popen(command, *args, **kwargs)
            if command == argv:
                proc = launched
            return launched

        try:
            with patch.object(supervisor.subprocess, "Popen", side_effect=launch):
                return supervisor.run(
                    argv, cwd=self.root, env=os.environ.copy(),
                    directory=self.root / "out", deadline=deadline,
                    nominal_kib=4_000_000, reserve_kib=1_000_000,
                    sample_interval=sample_interval, term_grace=term_grace,
                    kill_grace=kill_grace, **kwargs)
        finally:
            # The receipt is already final. A failed test still owns its child.
            if proc is not None and proc.returncode is None:
                proc.kill()
                proc.wait(timeout=FIXTURE_WAIT)

    def invoke_single_child(self, code, **kwargs):
        if sys.platform == "darwin":
            # These children spawn no descendants. Keep real child exit and signals
            # while supplying RSS and cleanup snapshots without invoking ps.
            kwargs.setdefault("sampler", lambda pid, _pgid: {"rss_kib": 20, "pids": [pid]})
            with patch.object(supervisor, "process_table", return_value={}):
                return self.invoke(code, **kwargs)
        return self.invoke(code, **kwargs)

    def wait_for_fixture(self, check, description):
        deadline = time.monotonic() + FIXTURE_WAIT
        while time.monotonic() < deadline:
            value = check()
            if value:
                return value
            time.sleep(.005)
        raise TimeoutError(description)

    def run_descendant(self, worker, *, escaped, skip_term=None):
        parent = f"""import signal,subprocess,sys
subprocess.Popen([sys.executable, '-c', {worker!r}], start_new_session={escaped})
signal.pause()
"""
        ready = self.root / "ready"
        prctl = ctypes.CDLL(None, use_errno=True).prctl
        old_subreaper = ctypes.c_int()
        self.assertEqual(prctl(37, ctypes.byref(old_subreaper), 0, 0, 0), 0)
        children = Path(f"/proc/self/task/{os.getpid()}/children")
        prior_children = set(children.read_text().split())
        native_sample = supervisor._default_sample
        native_signal = supervisor._signal_owned
        identity = None
        targets = []
        # Each selective signal can require two complete native censuses.
        term_grace, kill_grace = .5, 6
        deadline = time.monotonic() + 3 * FIXTURE_WAIT + term_grace + kill_grace
        offset = 0

        def sample(pgid, *args, **kwargs):
            nonlocal identity, offset
            self.wait_for_fixture(ready.exists, "descendant did not publish readiness")
            pid = int(ready.read_text())
            view = native_sample(pgid, *args, **kwargs)
            row = next((row for row in view["records"] if row["pid"] == pid), None)
            self.assertIsNotNone(row, view)
            self.assertEqual(row["ppid"], pgid)
            self.assertEqual(row["pgid"], pid if escaped else pgid)
            identity = pid, row["start_id"]
            # Enter the real timeout branch after native census confirms readiness.
            offset = deadline - term_grace - kill_grace - time.monotonic()
            return view

        def signal_owned(row, sig, *args, **kwargs):
            nonlocal offset
            targets.append((row["pid"], row["start_id"], sig, row["state"]))
            if skip_term is not None and sig == signal.SIGTERM:
                self.assertEqual((row["pid"], row["start_id"]), identity)
                self.assertNotIn(row["state"], supervisor.DEAD_STATES, row)
                proc_dir = Path(f"/proc/{row['pid']}")

                def zombie_leader():
                    current = supervisor._linux_pid_record(proc_dir)
                    return current if current["state"] == "Z" else None

                # Shutdown has selected the live leader. Exclude only the
                # test-controlled handshake from the native cleanup budget.
                started = time.monotonic()
                try:
                    (self.root / "exit-leader").touch()
                    current = self.wait_for_fixture(zombie_leader, "thread leader did not exit")
                finally:
                    offset -= time.monotonic() - started
                self.assertEqual((current["pid"], current["start_id"]), identity)
                self.assertTrue(current["has_other_threads"], current)
                self.assertGreater(current["rss"], 0, current)
                if skip_term:
                    return False
                # Revalidate the original selection through the real signal path.
            return native_signal(row, sig, *args, **kwargs)

        def wait_descendant(pid):
            waited, status = os.waitpid(pid, os.WNOHANG)
            return (waited, status) if waited else None

        clock = SimpleNamespace(monotonic=lambda: time.monotonic() + offset, sleep=time.sleep)
        self.assertEqual(prctl(36, 1, 0, 0, 0), 0)
        try:
            with (patch.object(supervisor, "time", clock),
                  patch.object(supervisor, "_default_sample", side_effect=sample),
                  patch.object(supervisor, "_signal_owned", side_effect=signal_owned)):
                result = self.invoke(parent, deadline=deadline, term_grace=term_grace, kill_grace=kill_grace)
                waited, status = (os.waitpid(identity[0], os.WNOHANG)
                                  if identity is not None and result["reaped"] else (0, 0))
            self.assertIsNotNone(identity, result)
            self.assertGreater(result["samples_succeeded"], 0, result)
            self.assertEqual(result["stop_reason"], "TIMEOUT", result)
            self.assertTrue(result["sampler_valid"], result)
            self.assertTrue(result["reaped"], result)
            self.assertEqual(result["remaining_processes"], [], result)
            self.assertEqual(result["cleanup_errors"], [], result)
            self.assertEqual(result["exit_code"], -signal.SIGTERM, result)
            killed = skip_term is not False
            expected = signal.SIGKILL if killed else signal.SIGTERM
            self.assertEqual([e["event"] for e in result["timeline"] if e["event"] in ("TERM", "KILL")],
                             ["TERM", "KILL"] if killed else ["TERM"], result)
            pid, start_id = identity
            selected = [(e["event"], e["pid"]) for e in result["timeline"]
                        if e["event"].endswith("_DESCENDANT")]
            if escaped:
                signals = [signal.SIGTERM, signal.SIGKILL] if killed else [signal.SIGTERM]
                expected_events = [] if skip_term else [("TERM_DESCENDANT", pid)]
                if killed:
                    expected_events.append(("KILL_DESCENDANT", pid))
                self.assertEqual(selected, expected_events, result)
                self.assertEqual([entry[:3] for entry in targets],
                                 [(pid, start_id, sig) for sig in signals], result)
            else:
                # KILL can target the group or the known survivor, depending
                # on whether the direct child has been collected yet.
                self.assertIn(selected, ([], [("KILL_DESCENDANT", pid)]), result)
                self.assertEqual([entry[:3] for entry in targets],
                                 [(pid, start_id, signal.SIGKILL)] if selected else [], result)
            if skip_term:
                self.assertEqual(targets[-1][3], "Z", result)
            self.assertEqual(waited, pid, f"descendant was not waitable at receipt return: {result}")
            self.assertEqual(os.waitstatus_to_exitcode(status), -expected, result)
        finally:
            try:
                # As subreaper we own the orphan even if it escaped before publishing
                # readiness. An unreaped child PID cannot be reused before this wait.
                for child in set(children.read_text().split()) - prior_children:
                    pid = int(child)
                    if wait_descendant(pid) is None:
                        os.kill(pid, signal.SIGKILL)
                        self.wait_for_fixture(lambda: wait_descendant(pid), f"could not clean child {pid}")
            finally:
                self.assertEqual(prctl(36, old_subreaper.value, 0, 0, 0), 0)

    def test_linux_and_darwin_rss_fixtures(self):
        self.assertEqual(supervisor.parse_linux_status_rss("Name:\tpython\nVmRSS:\t12345 kB\n"), 12345)
        with self.assertRaises(supervisor.SupervisorError):
            supervisor.parse_linux_status_rss("Name:\tpython\n")
        self.assertEqual(supervisor.parse_darwin_ps_rss(" 4096\n"), 4096)
        for malformed in ("", "4096\n8192\n", "rss=4M\n", "-1\n"):
            with self.subTest(malformed=malformed), self.assertRaises(supervisor.SupervisorError):
                supervisor.parse_darwin_ps_rss(malformed)
        table = supervisor._parse_darwin_table(
            "12 1 12 4096 Ss Mon Nov 23 10:00:01 2026 /with space/cbmc\n"
            "15 12 12 0 Z+ Mon Nov 23 10:00:02 2026 (exited)\n"
        )
        self.assertEqual(table[12]["rss"], 4096)
        self.assertEqual(table[12]["image"], "cbmc")
        self.assertEqual([row["pid"] for row in supervisor._tree(table, 12)], [12])

    @unittest.skipUnless(sys.platform == "linux", "native Linux /proc descendant census required")
    def test_deadline_terminates_and_reaps_descendant_group(self):
        self.run_descendant(IGNORE_TERM, escaped=False)

    def test_lost_sampler_fails_closed_and_cleans_process(self):
        def lost(_pid, _pgid):
            raise OSError("synthetic sampler loss")
        result = self.invoke_single_child("import time; time.sleep(10)", sampler=lost)
        self.assertEqual(result["stop_reason"], "SAMPLER_ERROR")
        self.assertFalse(result["sampler_valid"])
        self.assertTrue(result["reaped"], result)
        self.assertEqual(result["missed_sample_fraction"], 1.0)

    def fake_linux_pid(self, pid, ppid, pgid, rss, start=10, *, state="S", threads=1):
        entry = self.root / str(pid)
        entry.mkdir()
        fields = [state, str(ppid), str(pgid), *(["0"] * 14), str(threads), "0", str(start)]
        (entry / "stat").write_text(f"{pid} (worker) " + " ".join(fields))
        (entry / "cmdline").write_bytes(b"/tmp/worker\0")
        (entry / "status").write_text(f"VmRSS: {rss} kB\n")
        return entry

    def test_linux_pid_reads_skip_vanished_record_and_keep_sibling_rss(self):
        vanished = self.fake_linux_pid(11, 10, 10, 1000)
        sibling = self.fake_linux_pid(12, 10, 10, 20)
        grandchild = self.fake_linux_pid(13, 12, 13, 30)
        root = self.fake_linux_pid(10, 1, 10, 10)
        native_open = os.open

        for step in (vanished, "stat", "cmdline", "status"):
            for error in (FileNotFoundError(), ProcessLookupError(), PlainOSError(errno.ESRCH, "gone")):
                with self.subTest(step=step, error=type(error).__name__):
                    skipped = Mock()
                    known = {11: supervisor._linux_pid_record(vanished)}
                    entries = [root, vanished, sibling, grandchild]
                    reading = None

                    def open_path(path, flags, *, dir_fd=None):
                        nonlocal reading
                        if path == vanished and step == vanished:
                            raise error
                        if dir_fd is None:
                            reading = path
                        return native_open(path, flags, dir_fd=dir_fd)

                    unreadable = mock_open()
                    unreadable.return_value.read.side_effect = error

                    def open_record_file(name, mode="r", *, opener):
                        if reading == vanished and name == step:
                            return unreadable()
                        return open(name, mode, opener=opener)

                    with patch.object(supervisor, "sys_platform", return_value="linux"), \
                            patch.object(Path, "iterdir", side_effect=lambda: iter(entries)), \
                            patch.object(os, "open", side_effect=open_path), \
                            patch.object(supervisor, "open", side_effect=open_record_file, create=True):
                        dropped = supervisor._default_sample(10, known, on_pid_skip=skipped)
                        skipped.assert_called_once_with()
                        entries.remove(vanished)
                        absent = supervisor._default_sample(10, known, on_pid_skip=skipped)
                        skipped.assert_called_once_with()
                    if step != vanished:
                        unreadable.return_value.read.assert_called_once_with()
                    for sample in (dropped, absent):
                        self.assertEqual(sample["pids"], [10, 12, 13])
                        self.assertEqual(sample["rss_kib"], 60)
                    self.assertEqual(set(known), {10, 11, 12, 13})

    def test_linux_pid_directory_fd_pins_identity_across_reads(self):
        old = self.fake_linux_pid(11, 10, 10, 20)
        replacement = self.fake_linux_pid(12, 1, 12, 900, start=30)
        (replacement / "cmdline").write_bytes(b"/tmp/replacement\0")
        native_open = os.open

        def replace_before_cmdline(path, flags, *, dir_fd=None):
            if path == "cmdline":
                old.rename(self.root / "retired")
                replacement.rename(old)
            return native_open(path, flags, dir_fd=dir_fd)

        with patch.object(os, "open", side_effect=replace_before_cmdline):
            row = supervisor._linux_pid_record(old)
        self.assertEqual((row["ppid"], row["start_id"], row["rss"], row["image"]), (10, 10, 20, "worker"))

    def test_linux_zombie_leader_is_retained_when_a_worker_races_task_walk(self):
        leader = self.fake_linux_pid(11, 10, 11, 0, state="Z", threads=2)
        (leader / "task").mkdir()
        # Neither the departed worker nor the leader's own memory is readable.
        (leader / "status").unlink()
        with patch.object(os, "listdir", return_value=["11", "12"]):
            row = supervisor._linux_pid_record(leader)
        known = {11: row}
        self.assertEqual(supervisor._owned_live({11: row}, 10, known), [row])
        self.assertEqual(row["rss"], 0)

        stat = leader / "stat"
        tail = stat.read_text().rsplit(")", 1)[1].split()
        tail[17] = "1"
        stat.write_text("11 (worker) " + " ".join(tail))
        (leader / "status").write_text("State:\tZ (zombie)\n")
        zombie = supervisor._linux_pid_record(leader)
        self.assertEqual(supervisor._owned_live({11: zombie}, 10, known), [])

    def test_linux_pid_permission_and_parse_failures_propagate(self):
        entry = self.fake_linux_pid(11, 10, 10, 20)
        count = Mock()
        with patch.object(Path, "iterdir", return_value=iter([entry])), \
                patch.object(os, "open", side_effect=PermissionError(errno.EACCES, "denied")):
            with self.assertRaises(PermissionError):
                supervisor._linux_table(count)
        (entry / "stat").write_text("invalid stat")
        with patch.object(Path, "iterdir", return_value=iter([entry])):
            with self.assertRaisesRegex(supervisor.SupervisorError, "invalid /proc process record"):
                supervisor._linux_table(count)
        count.assert_not_called()

    @unittest.skipUnless(sys.platform == "linux", "live Linux /proc required")
    def test_linux_receipt_counts_pid_records_in_sampling_and_cleanup(self):
        native_iterdir = Path.iterdir
        native_sample = supervisor._default_sample
        gone = self.root / "999999999"

        def with_gone_pid(path):
            return iter([*native_iterdir(path), gone])

        def sample_then_release(pid, *args, **kwargs):
            sample = native_sample(pid, *args, **kwargs)
            (self.root / "release").touch()
            # Observe the exit without consuming the wait status. Supervisor
            # still has to reap it and obtain the two cleanup censuses.
            self.wait_for_fixture(lambda: os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG),
                                  "sampled child did not exit after release")
            return sample

        with (patch.object(Path, "iterdir", with_gone_pid),
              patch.object(supervisor, "_default_sample", side_effect=sample_then_release)):
            result = self.invoke(WAIT_FOR_RELEASE, deadline=time.monotonic() + 2 * FIXTURE_WAIT,
                                 sample_interval=.5)
        self.assertEqual(result["stop_reason"], "EXITED", result)
        self.assertTrue(result["sampler_valid"] and result["reaped"], result)
        self.assertEqual(result["remaining_processes"], [])
        self.assertEqual(result["samples_missed"], 0)
        self.assertGreaterEqual(result["sample_pid_records_skipped"], result["samples_succeeded"])
        self.assertGreaterEqual(result["cleanup_pid_records_skipped"], 2)

    def test_linux_proc_enumeration_esrch_fails_the_whole_sample(self):
        first = True

        def failed_list(_path):
            nonlocal first
            if first:
                first = False
                raise ProcessLookupError(errno.ESRCH, "cannot enumerate proc")
            return iter(())

        with patch.object(supervisor, "sys_platform", return_value="linux"), \
                patch.object(Path, "iterdir", failed_list):
            result = self.invoke("import time; time.sleep(5)")
        self.assertEqual(result["stop_reason"], "SAMPLER_ERROR", result)
        self.assertIn("cannot enumerate proc", result["sampler_error"])
        self.assertEqual(result["samples_missed"], 1)
        self.assertEqual(result["sample_pid_records_skipped"], 0)
        self.assertTrue(result["reaped"], result)

    def test_darwin_valid_absence_and_global_ps_errors(self):
        record = {"pid": 11, "start_id": "Mon Nov 23 10:00:01 2026"}
        sibling = "12 10 10 4096 Ss Mon Nov 23 10:00:01 2026 worker\n"
        with patch.object(supervisor, "sys_platform", return_value="darwin"), \
                patch.object(os, "kill") as kill:
            with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=sibling)):
                self.assertFalse(supervisor._signal_owned(record, signal.SIGTERM))
                self.assertEqual(supervisor._default_sample(10)["rss_kib"], 4096)
            for malformed in ("", "11 10 wrong 4096 Ss Mon Nov 23 10:00:01 2026 worker\n"):
                with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout=malformed)):
                    with self.assertRaisesRegex(supervisor.SupervisorError, "Darwin ps process table"):
                        supervisor._signal_owned(record, signal.SIGTERM)
            for error, expected in ((subprocess.TimeoutExpired("ps", .25), supervisor.DarwinCensusTimeout),
                                    (subprocess.CalledProcessError(1, "ps"), subprocess.CalledProcessError),
                                    (ProcessLookupError(errno.ESRCH, "ps launch failed"), ProcessLookupError)):
                with patch.object(subprocess, "run", side_effect=error), self.assertRaises(expected):
                    supervisor._signal_owned(record, signal.SIGTERM)
            kill.assert_not_called()

    def test_signals_tolerate_esrch_and_preserve_permission_error(self):
        record = {"pid": 11, "start_id": 10}
        for error in (ProcessLookupError(), PlainOSError(errno.ESRCH, "gone"), PermissionError(errno.EPERM, "denied")):
            with self.subTest(error=type(error).__name__), \
                    patch.object(supervisor, "sys_platform", return_value="darwin"), \
                    patch.object(supervisor, "process_table", return_value={11: record}), \
                    patch.object(os, "kill", side_effect=error), patch.object(os, "killpg", side_effect=error):
                for send, target in ((supervisor._signal_group, SimpleNamespace(pid=11)),
                                     (supervisor._signal_owned, record)):
                    if isinstance(error, PermissionError):
                        with self.assertRaises(PermissionError):
                            send(target, signal.SIGTERM)
                    else:
                        self.assertFalse(send(target, signal.SIGTERM))

    def test_linux_pidfd_checks_identity_and_scopes_signal_esrch(self):
        row = {"pid": 11, "start_id": 10}
        current = {11: row}
        reused = {11: row | {"start_id": 20}}
        gone = PlainOSError(errno.ESRCH, "gone")
        for inventories, open_error, send_error, expected in (
            ([reused], None, None, False),
            ([current], gone, None, False),
            ([current, {}], None, None, False),
            ([current, reused], None, None, False),
            ([current, ProcessLookupError(errno.ESRCH, "census failed")], None, None, ProcessLookupError),
            ([current, current], None, gone, False),
            ([current, current], None, PermissionError(), PermissionError),
            ([current, current], None, None, True),
        ):
            with self.subTest(inventories=inventories, open_error=open_error, send_error=send_error), \
                    patch.object(supervisor, "sys_platform", return_value="linux"), \
                    patch.object(supervisor, "process_table", side_effect=inventories), \
                    patch.object(os, "pidfd_open", return_value=42, side_effect=open_error, create=True) as opened, \
                    patch.object(signal, "pidfd_send_signal", side_effect=send_error, create=True) as send, \
                    patch.object(os, "close") as close:
                if isinstance(expected, type):
                    with self.assertRaises(expected):
                        supervisor._signal_owned(row, signal.SIGTERM)
                else:
                    self.assertIs(supervisor._signal_owned(row, signal.SIGTERM), expected)
                if inventories == [reused]:
                    opened.assert_not_called()
                if len(inventories) == 2:
                    close.assert_called_once_with(42)
                else:
                    close.assert_not_called()
                if inventories == [current, current]:
                    send.assert_called_once_with(42, signal.SIGTERM)
                else:
                    send.assert_not_called()

    def test_reused_pid_is_ignored_in_live_sample_and_final_census(self):
        for platform in ("linux", "darwin"):
            starts = (10, 20) if platform == "linux" else (
                "Mon Nov 23 10:00:01 2026", "Mon Nov 23 10:00:02 2026")
            old = {"pid": 11, "ppid": 10, "pgid": 11, "start_id": starts[0], "rss": 10}
            replacement = old | {"ppid": 1, "pgid": 9, "start_id": starts[1], "rss": 1000}
            unrelated_child = replacement | {"pid": 12, "ppid": 11}
            unrelated = {11: replacement, 12: unrelated_child}
            with self.subTest(platform=platform), \
                    patch.object(supervisor, "sys_platform", return_value=platform), \
                    patch.object(supervisor, "process_table", return_value=unrelated), \
                    patch.object(os, "kill") as kill:
                known = {11: old}
                sibling = old | {"pid": 13, "pgid": 10, "rss": 50}
                with patch.object(supervisor, "process_table", return_value=unrelated | {13: sibling}):
                    sample = supervisor._default_sample(10, known)
                self.assertEqual((sample["pids"], sample["rss_kib"], known), ([13], 50, {13: sibling}))
                self.assertFalse(supervisor._signal_owned(old, signal.SIGTERM))
                kill.assert_not_called()

                with patch.object(supervisor, "process_table", side_effect=[{}, unrelated]):
                    result = self.invoke("pass", sampler=lambda pid, pgid: {
                        "rss_kib": 10, "pids": [11], "records": [old],
                    })
                self.assertEqual((result["stop_reason"], result["exit_code"]), ("EXITED", 0), result)
                self.assertTrue(result["sampler_valid"] and result["reaped"], result)
                self.assertEqual(result["remaining_processes"], [])
                self.assertEqual(result["cleanup_errors"], [])

    def test_reused_pid_is_learned_when_the_new_process_belongs_to_the_tree(self):
        root = {"pid": 10, "ppid": 1, "pgid": 10, "start_id": 10}
        old = {"pid": 11, "ppid": 10, "pgid": 10, "start_id": 10}
        for replacement in (old | {"start_id": 20, "ppid": 1},
                            old | {"start_id": 20, "pgid": 11}):
            with self.subTest(replacement=replacement):
                known = {10: root, 11: old}
                table = {10: root, 11: replacement}
                self.assertEqual(supervisor._owned_live(table, 10, known), [root, replacement])
                self.assertEqual(known, table)

    def test_cleanup_ignores_a_recreated_group_after_direct_child_is_reaped(self):
        leader = {"pid": 10, "ppid": 1, "pgid": 10, "start_id": 20}
        member = leader | {"pid": 11, "ppid": 10}
        proc = Mock(pid=10, returncode=0)
        proc.poll.return_value = 0
        with patch.object(supervisor, "process_table", side_effect=[{10: leader, 11: member}, {11: member}]), \
                patch.object(os, "killpg") as kill_group, patch.object(supervisor, "_signal_owned") as kill_owned:
            result = supervisor._shutdown(proc, {}, supervisor.Timeline(), time.monotonic() + 1, .2, .2)
        self.assertEqual(result, (True, [], [], False))
        kill_group.assert_not_called()
        kill_owned.assert_not_called()

    def test_cleanup_ignores_a_recreated_group_with_no_leader_row(self):
        old = {"pid": 11, "ppid": 10, "pgid": 10, "start_id": 10}
        member = old | {"ppid": 1, "start_id": 20}
        proc = Mock(pid=10, returncode=0)
        proc.poll.return_value = 0
        with patch.object(supervisor, "process_table", return_value={11: member}), \
                patch.object(os, "killpg") as kill_group, patch.object(supervisor, "_signal_owned") as kill_owned:
            result = supervisor._shutdown(proc, {11: old}, supervisor.Timeline(), time.monotonic() + 1, .2, .2)
        kill_group.assert_not_called()
        kill_owned.assert_not_called()
        self.assertEqual(result, (True, [], [], False))

    def test_cleanup_signals_and_waits_for_known_group_member_when_poll_reaps_child(self):
        leader = {"pid": 10, "ppid": 1, "pgid": 10, "start_id": 10}
        member = leader | {"pid": 11, "ppid": 10}
        orphan = member | {"ppid": 1}
        unseen = orphan | {"pid": 12, "ppid": 11}
        proc = Mock(pid=10, returncode=None)

        def poll():
            if proc.poll.call_count > 1:
                proc.returncode = 0
            return proc.returncode

        proc.poll.side_effect = poll
        timeline = supervisor.Timeline()
        snapshots = [{10: leader, 11: member}, {11: orphan, 12: unseen}, {12: unseen}, {12: unseen}]
        inventories = iter(snapshots)
        with patch.object(supervisor, "process_table", side_effect=lambda **_: next(inventories, {})) as census, \
                patch.object(os, "killpg") as kill_group, \
                patch.object(supervisor, "_signal_owned", return_value=True) as kill_owned:
            result = supervisor._shutdown(proc, {11: member}, timeline, time.monotonic() + 1, .2, .2)
        kill_group.assert_not_called()
        kill_owned.assert_called_once()
        self.assertEqual(kill_owned.call_args.args[:2], (member, signal.SIGTERM))
        self.assertEqual([entry["event"] for entry in timeline], ["TERM", "TERM_DESCENDANT"])
        self.assertEqual(census.call_count, len(snapshots))
        self.assertEqual(result, (True, [], [], True))

    def test_cleanup_requires_valid_final_census_after_child_exit(self):
        with patch.object(supervisor, "process_table", side_effect=[{}, ProcessLookupError("final census failed")]):
            result = self.invoke("pass", sampler=lambda pid, pgid: {"rss_kib": 20, "pids": [pid]})
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["primary_stop_reason"], "EXITED")
        self.assertEqual(result["stop_reason"], "REAP_UNVERIFIED")
        self.assertFalse(result["reaped"])
        self.assertIsNone(result["remaining_processes"])
        self.assertEqual(result["cleanup_pid_records_skipped"], 0)
        self.assertIn("final census failed", result["cleanup_errors"][0])

    @unittest.skipUnless(sys.platform == "linux", "native Linux /proc descendant census required")
    def test_escaped_descendant_is_killed_by_its_owned_pid(self):
        self.run_descendant(IGNORE_TERM, escaped=True)

    @unittest.skipUnless(sys.platform == "linux", "Linux procfs and subreaper required")
    def test_escaped_descendant_survives_its_thread_leader_until_signalled(self):
        worker = """import ctypes,signal,threading,time
signal.signal(signal.SIGTERM, signal.SIG_DFL)
started = threading.Event()
def wait():
    started.set()
    threading.Event().wait()
threading.Thread(target=wait).start()
started.wait()
""" + PUBLISH_PID + """while not Path('exit-leader').exists():
    time.sleep(.005)
ctypes.CDLL(None).pthread_exit(None)
"""
        for skip_term in (False, True):
            with self.subTest(skip_term=skip_term):
                (self.root / "ready").unlink(missing_ok=True)
                (self.root / "exit-leader").unlink(missing_ok=True)
                self.run_descendant(worker, escaped=True, skip_term=skip_term)

    def test_live_reserve_stops_without_reducing_admitted_rss_twice(self):
        initial = self.memory()
        later = self.memory(available=2_000_000)
        low = self.memory(available=500_000)
        snapshots = iter((initial, later, low))
        def sample(_pid, pgid):
            return {"rss_kib": 3_000_000, "pids": [pgid]}
        result = self.invoke_single_child("import time; time.sleep(5)", sampler=sample,
                                          memory_probe=lambda: next(snapshots, low))
        self.assertEqual(result["stop_reason"], "LIVE_MEMORY_RESERVE", result)
        self.assertEqual(result["effective_cap_kib"], 4_000_000)
        self.assertEqual(result["minimum_available_kib"], 500_000)
        self.assertTrue(result["reaped"], result)

    def test_admission_pressure_and_reserve_do_not_start(self):
        for snapshot, expected in (
            (self.memory(pressure="PRESSURE"), "ADMISSION_MEMORY_PRESSURE"),
            (self.memory(available=500_000), "ADMISSION_RESERVE_UNAVAILABLE"),
        ):
            result = supervisor.run(
                [sys.executable, "-c", "raise SystemExit(98)"], cwd=self.root,
                env=os.environ.copy(), directory=self.root / expected,
                deadline=time.monotonic() + 2, nominal_kib=1_000_000,
                reserve_kib=1_000_000, memory_probe=lambda: snapshot)
            self.assertEqual(result["status"], "NOT_STARTED")
            self.assertEqual(result["stop_reason"], expected)
            self.assertIsNone(result.get("pid"))

    def linux_snapshot(self, avg10, *, available=8_000_000):
        meminfo = f"MemTotal: 16000000 kB\nMemAvailable: {available} kB\n"
        psi = ("some avg10=10.00 avg60=0.00 avg300=0.00 total=42\n"
               f"full avg10={avg10} avg60=0.00 avg300=0.00 total=42\n")
        with patch.object(Path, "read_text", side_effect=[meminfo, psi]):
            return supervisor.memory_snapshot(platform="linux")

    def test_linux_low_psi_allows_admission_and_live_progress(self):
        snapshot = self.linux_snapshot("0.18")
        result = self.invoke_single_child("pass", memory_probe=lambda: snapshot)
        self.assertEqual(result["stop_reason"], "EXITED", result)
        self.assertEqual(result["exit_code"], 0)
        self.assertGreaterEqual(result["samples_succeeded"], 1)
        self.assertEqual(result["admission_memory"]["pressure_avg10"], 0.18)
        self.assertEqual(result["memory"]["pressure_avg10"], 0.18)

    def test_linux_psi_threshold_at_child_admission(self):
        snapshot = self.linux_snapshot("5.00")
        result = self.invoke("raise SystemExit(98)", memory_probe=lambda: snapshot)
        self.assertEqual(result["stop_reason"], "ADMISSION_MEMORY_PRESSURE", result)
        self.assertIsNone(result.get("pid"))

    @unittest.skipUnless(sys.platform == "linux", "Linux PSI cadence with native /proc required")
    def test_linux_live_pressure_requires_consecutive_samples_over_two_seconds(self):
        clear, high = self.linux_snapshot("0.18"), self.linux_snapshot("5.00")
        samples = iter(((0.0, clear),  # Admission
                        (.25, high), (2.25, high), (2.5, clear),
                        (2.75, high), (3.0, high), (3.25, high), (3.5, clear),
                        (3.75, high), (4.75, high), (5.75, high)))
        now = 0.0
        cleanup_started = None
        native_shutdown = supervisor._shutdown

        def probe():
            nonlocal now
            now, snapshot = next(samples)
            return snapshot

        def monotonic():
            return now if cleanup_started is None else now + (time.monotonic() - cleanup_started)

        def shutdown(*args, **kwargs):
            nonlocal cleanup_started
            cleanup_started = time.monotonic()
            return native_shutdown(*args, **kwargs)

        def sleep(seconds):
            if cleanup_started is not None:
                time.sleep(seconds)

        with (patch.object(supervisor, "time", SimpleNamespace(monotonic=monotonic, sleep=sleep)),
              patch.object(supervisor, "_shutdown", side_effect=shutdown)):
            result = self.invoke("import signal; signal.pause()", deadline=10.0, memory_probe=probe)
        self.assertEqual(result["stop_reason"], "LIVE_MEMORY_PRESSURE", result)
        self.assertEqual(result["samples_succeeded"], 10)
        self.assertEqual(result["memory"]["pressure_avg10"], 5.0)
        self.assertEqual(result["memory"]["pressure_high_samples"], 3)
        self.assertEqual(result["memory"]["pressure_high_seconds"], 2.0)
        stopped = next(event for event in result["timeline"] if event["event"] == "LIVE_MEMORY_PRESSURE")
        self.assertEqual(stopped["at"], 5.75)
        self.assertEqual(stopped["memory"], result["memory"])
        self.assertTrue(result["reaped"], result)
        self.assertEqual(result["remaining_processes"], [])
        self.assertIn("TERM", [event["event"] for event in result["timeline"]])

    def test_linux_reserve_and_rss_stop_immediately(self):
        for avg10, available, rss, expected in (
            ("0.00", 500_000, 20, "LIVE_MEMORY_RESERVE"),
            ("5.00", 500_000, 20, "LIVE_MEMORY_RESERVE"),
            ("5.00", 8_000_000, 4_000_001, "RSS_LIMIT"),
        ):
            with self.subTest(avg10=avg10, expected=expected):
                snapshots = iter((self.linux_snapshot("0.18"), self.linux_snapshot(avg10, available=available)))
                result = self.invoke_single_child("import time; time.sleep(5)", memory_probe=snapshots.__next__,
                                                  sampler=lambda _pid, pgid: {"rss_kib": rss, "pids": [pgid]})
                self.assertEqual(result["stop_reason"], expected, result)
                self.assertEqual(result["samples_succeeded"], 1)
                self.assertTrue(result["reaped"], result)

    def test_invalid_linux_psi_is_an_immediate_probe_error(self):
        def invalid_probe():
            return self.linux_snapshot("0.18invalid")

        def unreadable_probe():
            meminfo = "MemTotal: 16000000 kB\nMemAvailable: 8000000 kB\n"
            with patch.object(Path, "read_text", side_effect=[meminfo, OSError("PSI read failed")]):
                return supervisor.memory_snapshot(platform="linux")

        for fail, message in ((invalid_probe, "invalid Linux memory pressure"), (unreadable_probe, "PSI read failed")):
            with self.subTest(message=message):
                result = self.invoke("raise SystemExit(98)", memory_probe=fail)
                self.assertEqual(result["stop_reason"], "SUPERVISOR_ERROR", result)
                self.assertIsNone(result.get("pid"))
                self.assertIn(message, result["supervisor_error"])

                snapshots = iter((self.linux_snapshot("0.18"), self.linux_snapshot("5.00")))
                result = self.invoke_single_child("import time; time.sleep(5)",
                                                  memory_probe=lambda: next(snapshots, None) or fail())
                self.assertEqual(result["stop_reason"], "SAMPLER_ERROR", result)
                self.assertFalse(result["sampler_valid"])
                self.assertEqual(result["samples_succeeded"], 1)
                self.assertIn(message, result["sampler_error"])
                self.assertTrue(result["reaped"], result)

    def darwin_snapshot(self, level, free=35):
        replies = [str(7 * 1024 ** 3), f"System-wide memory free percentage: {free}%", level]
        outputs = [subprocess.CompletedProcess([], 0, stdout=value + "\n") for value in replies]
        with patch.object(supervisor.subprocess, "run", side_effect=outputs) as probes:
            try:
                return supervisor.memory_snapshot(platform="darwin")
            finally:
                self.assertEqual([call.args[0] for call in probes.call_args_list], [
                    ("sysctl", "-n", "hw.memsize"), ("memory_pressure", "-Q"),
                    ("sysctl", "-n", "kern.memorystatus_vm_pressure_level"),
                ])

    def test_darwin_kernel_pressure_blocks_admission_with_sufficient_reserve(self):
        normal = self.darwin_snapshot("1", free=10)
        self.assertEqual(normal["pressure"], "CLEAR")
        self.assertEqual(normal["free_percent"], 10)
        for level, name in (("2", "WARNING"), ("4", "CRITICAL")):
            with self.subTest(level=level):
                snapshot = self.darwin_snapshot(level)
                self.assertGreater(snapshot["available_kib"], 5 * 1024 ** 2 // 4)
                result = self.invoke("raise SystemExit(98)", memory_probe=lambda: snapshot)
                self.assertEqual(result["stop_reason"], "ADMISSION_MEMORY_PRESSURE")
                self.assertEqual(result["status"], "NOT_STARTED")
                self.assertIsNone(result.get("pid"))
                self.assertEqual(result["admission_memory"]["pressure_level"], name)
                self.assertEqual(result["admission_memory"]["free_percent"], 35)

    def test_darwin_live_pressure_stops_with_sufficient_reserve(self):
        normal = self.darwin_snapshot("1")
        for level in ("2", "4"):
            with self.subTest(level=level):
                pressured = self.darwin_snapshot(level)
                snapshots = iter((normal, pressured))
                result = self.invoke_single_child("import time; time.sleep(5)",
                                                  memory_probe=lambda: next(snapshots, pressured))
                self.assertEqual(result["stop_reason"], "LIVE_MEMORY_PRESSURE", result)
                self.assertTrue(result["reaped"], result)
                self.assertEqual(result["admission_memory"]["pressure_level_raw"], 1)
                self.assertEqual(result["memory"]["pressure_level_raw"], int(level))
                self.assertEqual(result["memory"]["free_percent"], 35)
                self.assertGreater(result["minimum_available_kib"], 5 * 1024 ** 2 // 4)

    def test_invalid_darwin_pressure_is_a_probe_error(self):
        for level in ("", "0", "3", "normal"):
            with self.subTest(level=level), self.assertRaisesRegex(supervisor.SupervisorError, "invalid Darwin VM pressure"):
                self.darwin_snapshot(level)
        with patch.object(supervisor.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0, stdout=str(7 * 1024 ** 3)),
            subprocess.CompletedProcess([], 0, stdout="System-wide memory free percentage: 35%"),
            subprocess.CalledProcessError(1, "sysctl"),
        ]):
            result = self.invoke("raise SystemExit(98)", memory_probe=lambda: supervisor.memory_snapshot(platform="darwin"))
        self.assertEqual(result["stop_reason"], "SUPERVISOR_ERROR")
        self.assertEqual(result["status"], "NOT_STARTED")
        self.assertFalse(result["sampler_valid"])
        self.assertIsNone(result.get("pid"))

    def test_phase_transitions_and_bounded_output(self):
        phases = iter(("rustc", "cbmc"))
        def sample(_pid, pgid):
            phase = next(phases, "cbmc")
            if phase == "cbmc":
                (self.root / "release").touch()
            return {"rss_kib": 20, "pids": [pgid], "verifier_count": int(phase == "cbmc"),
                    "images": [phase], "phase": phase}
        result = self.invoke_single_child("print('x'*100000, flush=True)\n" + WAIT_FOR_RELEASE,
                                          deadline=time.monotonic() + 2 * FIXTURE_WAIT, sampler=sample,
                                          stdout_cap_bytes=64)
        self.assertEqual(result["stop_reason"], "EXITED")
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["max_verifier_children"], 1)
        self.assertEqual(result["peak_rss_kib"], 20)
        self.assertEqual(result["last_observed_phase"], "cbmc")
        self.assertEqual((self.root / "out" / "stdout.log").stat().st_size, 64)
        self.assertFalse(result["stdout_complete"])
        self.assertGreaterEqual(result["samples_succeeded"], 2)
        self.assertEqual([e["phase"] for e in result["timeline"] if e["event"] == "PHASE"], ["rustc", "cbmc"])


if __name__ == "__main__":
    unittest.main()
