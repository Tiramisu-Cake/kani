# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Offline CAL2 RSS/PSS probes and publication checks."""
import errno
import os
from pathlib import Path
from queue import Queue
import sys
import tempfile
from threading import Event
import time
import unittest
from unittest.mock import patch

import supervisor
from telemetry import MemoryTelemetry, PssProbe, SERIES_ROWS, read_pss


def sample(group_rss, *rss_per_pid):
    records = [{"pid": 101 + i, "start_id": 300 + i, "rss": rss} for i, rss in enumerate(rss_per_pid)]
    pids = [row["pid"] for row in records]
    return {"rss_kib": group_rss, "records": records, "verifier_pids": pids, "pids": pids,
            "verifier_count": len(pids), "phase": "cbmc" if pids else "kani-compiler"}


class ManualProbe:
    def __init__(self):
        self.reply = None

    def submit(self, pid, start_id):
        self.reply = Queue(maxsize=1)
        return self.reply, None


class TelemetryTests(unittest.TestCase):
    def test_procfs_pss_exact_key_and_pid_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            entry = proc / "101"
            entry.mkdir()
            fields = ["S", *("0" for _ in range(18)), "300"]
            stat = entry / "stat"
            stat.write_text("101 (cbmc) " + " ".join(fields))
            rollup = entry / "smaps_rollup"
            rollup.write_text("Pss_Anon: 999 kB\nPss: 41 kB\nPss_File: 11 kB\n")
            self.assertEqual(read_pss(101, 300, proc), (41, None))
            self.assertEqual(read_pss(101, 299, proc), (None, "PID_IDENTITY_CHANGED"))
            rollup.write_text("Pss_Anon: 999 kB\n")
            self.assertEqual(read_pss(101, 300, proc), (None, "PSS_MISSING_OR_INVALID"))
            rollup.unlink()
            self.assertEqual(read_pss(101, 300, proc), (None, "PROCESS_OR_ROLLUP_GONE"))

    def test_pss_second_identity_read_and_os_errors(self):
        stat = ["S", *("0" for _ in range(18)), "300"]
        newer = [*stat[:-1], "301"]
        with (patch.object(os, "open", return_value=50), patch.object(os, "close") as close,
              patch.object(supervisor, "_linux_stat", side_effect=[stat, newer]),
              patch("builtins.open", unittest.mock.mock_open(read_data="Pss: 41 kB\n"))):
            self.assertEqual(read_pss(101, 300), (None, "PID_IDENTITY_CHANGED"))
            close.assert_called_once_with(50)
        for error, reason in ((errno.ESRCH, "ESRCH"), (errno.EACCES, "ACCESS_DENIED"),
                              (errno.EPERM, "ACCESS_DENIED"), (errno.EIO, "READ_ERROR")):
            with self.subTest(error=error), patch.object(os, "open", side_effect=OSError(error, "synthetic")):
                self.assertEqual(read_pss(101, 300), (None, reason))

    def test_distinct_peaks_nearest_pss_and_bounded_series(self):
        probe = ManualProbe()
        observations = MemoryTelemetry(probe)
        observations.observe(sample(20), 10)
        observations.observe(sample(80, 30, 20), 11)
        probe.reply.put_nowait((11.1, 11.2, 12, None))
        observations.observe(sample(200, 25, 7), 12)
        probe.reply.put_nowait((12.1, 13.1, 25, None))
        observations.observe(sample(180, 70, 30), 13.2)
        probe.reply.put_nowait((13.3, 13.4, 55, None))
        for i in range(SERIES_ROWS + 10):
            observations.observe(sample(3), 14 + i)
        series, compact = observations.publication()
        group, cbmc = compact["group_peak"], compact["cbmc_peak"]
        self.assertEqual((group["group_rss_kib"], group["cbmc_rss_kib"], group["cbmc_count"]), (200, 32, 2))
        self.assertEqual(group["cbmc"], [{"pid": 101, "start_id": 300, "rss_kib": 25},
                                        {"pid": 102, "start_id": 301, "rss_kib": 7}])
        self.assertEqual((cbmc["group_rss_kib"], cbmc["cbmc_rss_kib"], cbmc["monotonic"]), (180, 100, 13.2))
        self.assertEqual(group["pss"]["reason"], "LATE_RESPONSE")
        self.assertIsNone(group["pss"]["pss_kib"])
        self.assertEqual(compact["nearest_pss_to_group_peak"]["sample"], 2)
        self.assertEqual(cbmc["pss"]["pss_kib"], 55)
        self.assertAlmostEqual(cbmc["pss"]["read_latency_seconds"], .1)
        self.assertAlmostEqual(cbmc["pss"]["rss_to_pss_seconds"], .2)
        self.assertEqual(compact["last_rss_sample"]["cbmc_count"], 0)
        self.assertEqual(series[0]["cbmc_count"], 0)
        self.assertEqual(compact["series_rows_omitted"], 14)
        self.assertEqual(len(series), SERIES_ROWS)
        self.assertEqual((compact["pss_attempts"], compact["pss_successes"]), (3, 2))

    def test_pss_error_and_response_after_stop_preserve_rss(self):
        probe = ManualProbe()
        obs = MemoryTelemetry(probe)
        obs.observe(sample(50, 40), 10)
        probe.reply.put_nowait((10.1, 10.2, None, "ACCESS_DENIED"))
        obs.observe(sample(70, 60), 11)
        probe.reply.put_nowait((11.1, 11.3, 50, None))
        obs.finish(11.2)
        series, compact = obs.publication()
        self.assertEqual([row["pss"]["reason"] for row in series], ["ACCESS_DENIED", "AFTER_STOP"])
        self.assertEqual(compact["last_rss_sample"]["cbmc_rss_kib"], 60)
        self.assertEqual(compact["pss_successes"], 0)

    def test_probe_limits_outstanding_reads_and_actual_read_cadence(self):
        started, resume = Event(), Event()

        def blocked(pid, start_id):
            started.set()
            resume.wait(5)
            return 10, None

        probe = PssProbe(blocked)
        self.addCleanup(resume.set)
        reply, reason = probe.submit(101, 300)
        self.assertIsNone(reason)
        self.assertTrue(started.wait(2))
        self.assertEqual(probe.submit(102, 301), (None, "READ_IN_FLIGHT"))
        resume.set()
        began, _, _, _ = reply.get(timeout=2)
        # Check just before the interval ends, independent of scheduling variance.
        with patch("telemetry.time.monotonic", return_value=began + .99):
            self.assertIn(probe.submit(102, 301)[1], {"RATE_LIMIT", "READ_IN_FLIGHT"})

    @unittest.skipUnless(sys.platform == "linux", "Linux /proc and process cleanup")
    def test_blocked_probe_does_not_delay_rss_stop_or_reap(self):
        resume = Event()
        self.addCleanup(resume.set)
        probe = PssProbe(lambda *_: (resume.wait(8), None))
        observations = MemoryTelemetry(probe)
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            child = supervisor.run(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                directory=directory, cwd=directory, env=os.environ, deadline=time.monotonic() + 4,
                nominal_kib=60, reserve_kib=10, term_grace=.2, kill_grace=.2,
                sampler=lambda *_: sample(70, 50), diagnostics=observations,
                memory_probe=lambda: {"physical_kib": 1000, "available_kib": 500, "pressure": "CLEAR"},
            )
        self.assertEqual(child["stop_reason"], "RSS_LIMIT")
        self.assertTrue(child["reaped"])
        self.assertLess(child["wall_seconds"], 4)
        _, summary = observations.publication()
        self.assertEqual(summary["last_rss_sample"]["pss"]["reason"], "PENDING_AT_STOP")
        self.assertEqual(summary["pss_attempts"], 1)


if __name__ == "__main__":
    unittest.main()
