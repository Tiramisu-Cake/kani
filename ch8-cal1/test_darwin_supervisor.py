# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Exercise the real Darwin census and shutdown logic with a simulated clock and OS."""

from contextlib import ExitStack
import io
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import supervisor


CENSUS = ["ps", "-axww", "-o", "pid=,ppid=,pgid=,rss=,stat=,lstart=,comm="]
INIT = "1 0 1 200 Ss Mon Nov 23 10:00:00 2026 launchd\n"
LEADER = "10 1 10 {rss} Ss Mon Nov 23 10:00:01 2026 python\n"
ESCAPED = "11 10 11 75 S Mon Nov 23 10:00:02 2026 python\n"
ORPHAN = "11 1 10 75 S Mon Nov 23 10:00:02 2026 python\n"
REUSED = "11 1 11 1000 S Mon Nov 23 10:00:03 2026 unrelated\n"
CLEAR = {"physical_kib": 1000, "available_kib": 800, "pressure": "CLEAR"}
MISSING_CHILD = (.01, None, "")


class DarwinSimulation:
    def __init__(self, test, live=(), *, cleanup=None, exit_at=float("inf"), ignore_term=False):
        self.test = test
        self.now = 0.0
        self.exit_at = exit_at
        self.ignore_term = ignore_term
        self.live = iter(live)
        self.cleanup = cleanup
        self.cleaning = False
        self.ps_calls = []
        self.signals = []
        self.proc = Mock(pid=10, returncode=None, stdout=io.BytesIO(), stderr=io.BytesIO())
        self.proc.poll.side_effect = self.poll
        self.proc.wait.side_effect = self.wait

    def advance(self, seconds):
        self.now += seconds

    def poll(self):
        if self.now >= self.exit_at and self.proc.returncode is None:
            self.proc.returncode = 0
        return self.proc.returncode

    def wait(self, timeout):
        if self.poll() is not None:
            return self.proc.returncode
        self.now = min(self.now + timeout, self.exit_at)
        if self.poll() is None:
            raise subprocess.TimeoutExpired("child", timeout)
        return self.proc.returncode

    def ps(self, argv, *, timeout, check, env, **kwargs):
        self.test.assertEqual(argv, CENSUS)
        self.test.assertTrue(check)
        self.test.assertEqual(env["LC_ALL"], "C")
        self.test.assertGreater(timeout, 0)
        self.ps_calls.append((self.cleaning, self.now, timeout))
        if self.cleaning and self.cleanup:
            content = self.cleanup(self, timeout)
        else:
            activity = None if self.cleaning else next(self.live, None)
            if activity == "timeout":
                return self.ps_timeout(timeout)
            if isinstance(activity, Exception):
                raise activity
            delay, rss, extra = activity or (.01, 40, "")
            self.advance(delay)
            leader = LEADER.format(rss=rss) if rss is not None and self.now < self.exit_at else ""
            content = INIT + leader + extra
        return subprocess.CompletedProcess(argv, 0, stdout=content)

    def ps_timeout(self, timeout):
        self.advance(timeout)
        raise subprocess.TimeoutExpired(CENSUS, timeout)

    def group_signal(self, pid, sig):
        self.test.assertEqual(pid, self.proc.pid)
        self.test.assertIsNone(self.proc.returncode)
        self.signals.append((self.now, "group", sig))
        if sig == signal.SIGKILL or not self.ignore_term:
            self.exit_at = self.now

    def pid_signal(self, pid, sig):
        self.signals.append((self.now, pid, sig))

    def run(self, *, stop_at=4, term_grace=2, kill_grace=2, memory=None, sampler=None):
        shutdown = supervisor._shutdown

        def cleanup(*args, **kwargs):
            self.cleaning = True
            return shutdown(*args, **kwargs)

        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            clock = stack.enter_context(patch.object(supervisor, "time"))
            clock.monotonic.side_effect = lambda: self.now
            clock.sleep.side_effect = self.advance
            for target, name, options in (
                (supervisor, "sys_platform", {"return_value": "darwin"}),
                (supervisor, "_shutdown", {"side_effect": cleanup}),
                (subprocess, "run", {"side_effect": self.ps}),
                (subprocess, "Popen", {"return_value": self.proc}),
                (os, "kill", {"side_effect": self.pid_signal}),
                (os, "killpg", {"side_effect": self.group_signal}),
            ):
                stack.enter_context(patch.object(target, name, **options))
            return supervisor.run(["child"], cwd=root, env={}, directory=root, nominal_kib=100, reserve_kib=100,
                                  deadline=stop_at + term_grace + kill_grace, term_grace=term_grace,
                                  kill_grace=kill_grace, memory_probe=memory or (lambda: CLEAR), sampler=sampler)

    def live_calls(self):
        return [(at, timeout) for cleaning, at, timeout in self.ps_calls if not cleaning]

    def cleanup_calls(self):
        return [(at, timeout) for cleaning, at, timeout in self.ps_calls if cleaning]


class DarwinSupervisorTests(unittest.TestCase):
    def test_slow_native_command_is_valid_and_normal_stop_stays_timeout(self):
        sim = DarwinSimulation(self, [(1.3, 50, "")])
        result = sim.run(stop_at=1.41)
        self.assertEqual(result["stop_reason"], "TIMEOUT", result)
        self.assertTrue(result["sampler_valid"] and result["reaped"], result)
        self.assertAlmostEqual(sim.live_calls()[0][1], 1.41)
        self.assertEqual(result["rss_peak_kib"], 50)
        self.assertAlmostEqual(result["darwin_census"]["max_gap_seconds"], 1.3)
        self.assertEqual(result["darwin_census"]["ps_timeouts"], 0)

    def test_slow_census_can_hit_the_stop_deadline_after_valid_samples(self):
        for valid_count, timeouts, error in (
            (5, 1, "Darwin census recovery deadline exhausted"),
            (4, 2, "Darwin ps census retry timed out"),
        ):
            with self.subTest(timeouts=timeouts):
                sim = DarwinSimulation(self, [(.7, 50, "")] * valid_count + ["timeout"] * timeouts)
                result = sim.run(stop_at=4.5)
                self.assertEqual(result["stop_reason"], "SAMPLER_ERROR", result)
                self.assertEqual(result["sampler_error"], f"SupervisorError: {error}")
                self.assertFalse(result["sampler_valid"])
                self.assertTrue(result["reaped"])
                self.assertEqual(result["samples_succeeded"], valid_count)
                self.assertEqual(result["rss_peak_kib"], 50)
                census = result["darwin_census"]
                self.assertEqual(census["ps_timeouts"], timeouts)
                self.assertEqual(census["last_timeout"]["reason"], "PS_CENSUS_TIMEOUT")
                self.assertAlmostEqual(census["last_timeout"]["at"], 4.5)
                self.assertAlmostEqual(sim.live_calls()[-1][1], 1 if timeouts == 1 else .2)

    def test_startup_missing_child_retries_immediately_and_checks_fresh_rss(self):
        sim = DarwinSimulation(self, [(.01, None, ORPHAN), (.05, 101, "")])
        result = sim.run()
        self.assertEqual(result["stop_reason"], "RSS_LIMIT", result)
        self.assertTrue(result["sampler_valid"] and result["reaped"], result)
        self.assertEqual(result["samples_attempted"], 2)
        self.assertEqual(result["samples_succeeded"], 1)
        self.assertEqual(result["samples_missed"], 1)
        self.assertEqual(result["rss_peak_kib"], 101)
        self.assertAlmostEqual(sim.live_calls()[1][0], .01)
        census = result["darwin_census"]
        self.assertEqual((census["ps_missing_child"], census["ps_timeouts"], census["recoveries"]), (1, 0, 1))
        self.assertAlmostEqual(census["max_gap_seconds"], .06)

    def test_fresh_retry_checks_rss_even_if_child_exits_after_snapshot(self):
        for miss, exit_at in ((MISSING_CHILD, .07), ("timeout", 1.56)):
            with self.subTest(miss=miss):
                sim = DarwinSimulation(self, [miss, (.05, 101, "")], exit_at=exit_at)
                ps = sim.ps

                def publish_snapshot(*args, **kwargs):
                    snapshot = ps(*args, **kwargs)
                    if not sim.cleaning and len(sim.live_calls()) == 2:
                        sim.advance(.02)
                    return snapshot

                sim.ps = publish_snapshot
                result = sim.run()
                self.assertEqual(result["stop_reason"], "RSS_LIMIT", result)
                self.assertEqual(result["rss_peak_kib"], 101)
                self.assertEqual(result["darwin_census"]["recoveries"], 1)
                self.assertTrue(result["sampler_valid"] and result["reaped"], result)
                self.assertEqual(sim.signals, [])

    def test_live_descendant_snapshot_checks_guards_when_direct_child_exits(self):
        descendant = ORPHAN.replace(" 75 S ", " 175 S ")
        for snapshot, expected in ((CLEAR, "RSS_LIMIT"),
                                   (CLEAR | {"pressure": "PRESSURE"}, "LIVE_MEMORY_PRESSURE"),
                                   (CLEAR | {"available_kib": 99}, "LIVE_MEMORY_RESERVE")):
            with self.subTest(expected=expected):
                sim = DarwinSimulation(self, [(.01, 50, ""), (.01, None, descendant)], exit_at=.305)
                readings = iter([CLEAR, CLEAR, snapshot])
                result = sim.run(memory=lambda: next(readings))
                self.assertEqual(result["stop_reason"], expected, result)
                self.assertEqual(result["rss_peak_kib"], 175)
                self.assertEqual(result["samples_succeeded"], 2)
                self.assertEqual(result["darwin_census"]["ps_missing_child"], 0)
                self.assertEqual(result["exit_code"], 0)
                self.assertTrue(result["sampler_valid"] and result["reaped"], result)
                self.assertEqual(sim.signals, [])

    def test_live_descendant_retry_checks_guards_when_direct_child_exits(self):
        for rss, snapshot, expected in (
            (175, CLEAR, "RSS_LIMIT"),
            (75, CLEAR, "EXITED"),
            (175, CLEAR | {"pressure": "PRESSURE"}, "LIVE_MEMORY_PRESSURE"),
            (175, CLEAR | {"available_kib": 99}, "LIVE_MEMORY_RESERVE"),
        ):
            with self.subTest(expected=expected):
                descendant = ORPHAN.replace(" 75 S ", f" {rss} S ")
                sim = DarwinSimulation(self, [(.01, 50, ""), "timeout", (.05, None, descendant)], exit_at=1.825)
                readings = iter([CLEAR, CLEAR, CLEAR, snapshot])
                result = sim.run(memory=lambda: next(readings))
                self.assertEqual(result["stop_reason"], expected, result)
                self.assertEqual(result["rss_peak_kib"], rss)
                self.assertEqual((result["samples_attempted"], result["samples_succeeded"]), (3, 2))
                census = result["darwin_census"]
                self.assertEqual((census["ps_timeouts"], census["ps_missing_child"], census["recoveries"]), (1, 0, 1))
                self.assertEqual(result["exit_code"], 0)
                self.assertTrue(result["sampler_valid"] and result["reaped"], result)
                self.assertEqual(sim.signals, [])

    def test_retry_budget_expiration_rechecks_direct_child_exit(self):
        remaining_timeout = supervisor._remaining_timeout
        for exit_at, expected in ((.795, "EXITED"), (float("inf"), "SAMPLER_ERROR")):
            with self.subTest(expected=expected):
                sim = DarwinSimulation(self, [(.01, 50, ""), (.49, None, "")], exit_at=exit_at)

                def timeout_after_pause(deadline, maximum):
                    if not sim.cleaning and len(sim.live_calls()) == 2:
                        self.assertAlmostEqual(sim.now, .790)
                        sim.advance(.011)
                    return remaining_timeout(deadline, maximum)

                with patch.object(supervisor, "_remaining_timeout", side_effect=timeout_after_pause):
                    result = sim.run(stop_at=.8)

                self.assertEqual(result["stop_reason"], expected, result)
                self.assertEqual(len(sim.live_calls()), 2)
                self.assertEqual(result["samples_attempted"], 2)
                self.assertEqual(result["samples_succeeded"], 1)
                self.assertEqual(result["rss_peak_kib"], 50)
                self.assertEqual(result["darwin_census"]["ps_missing_child"], 1)
                self.assertEqual(result["darwin_census"]["recoveries"], 0)
                self.assertTrue(result["reaped"], result)
                if expected == "EXITED":
                    self.assertTrue(result["sampler_valid"], result)
                    self.assertEqual(result["exit_code"], 0)
                    self.assertNotIn("sampler_error", result)
                    self.assertEqual(sim.signals, [])
                else:
                    self.assertFalse(result["sampler_valid"], result)
                    self.assertEqual(result["sampler_error"], "SupervisorError: Darwin census deadline exhausted")

    def test_missing_child_can_exit_without_another_valid_sample(self):
        for exit_at, retry, attempts, misses in (
            (.305, MISSING_CHILD, 2, 0),
            (.315, MISSING_CHILD, 3, 1),
            (.315, "timeout", 3, 1),
        ):
            with self.subTest(exit_at=exit_at, retry=retry):
                sim = DarwinSimulation(self, [(.01, 50, ""), MISSING_CHILD, retry], exit_at=exit_at)
                result = sim.run()
                self.assertEqual(result["stop_reason"], "EXITED", result)
                self.assertTrue(result["sampler_valid"] and result["reaped"], result)
                self.assertEqual(result["exit_code"], 0)
                self.assertEqual(result["samples_attempted"], attempts)
                self.assertEqual(result["samples_succeeded"], 1)
                self.assertEqual(result["rss_peak_kib"], 50)
                self.assertEqual(result["darwin_census"]["ps_missing_child"], misses)
                self.assertEqual(result["darwin_census"]["ps_timeouts"], int(retry == "timeout"))
                self.assertEqual(result["darwin_census"]["recoveries"], 0)
                self.assertEqual(sim.signals, [])

    def test_two_misses_in_one_series_fail_and_do_not_count_as_samples(self):
        for live, attempts, succeeded, peak, misses, timeouts, error in (
            ([MISSING_CHILD] * 2, 2, 0, None, 2, 0, "did not observe the live direct child"),
            ([(.05, 50, ""), MISSING_CHILD, MISSING_CHILD], 3, 1, 50, 2, 0, "did not observe the live direct child"),
            (["timeout", MISSING_CHILD], 2, 0, None, 1, 1, "did not observe the live direct child"),
            ([MISSING_CHILD, "timeout"], 2, 0, None, 1, 1, "retry timed out"),
        ):
            with self.subTest(live=live):
                sim = DarwinSimulation(self, live)
                result = sim.run()
                self.assertEqual(result["stop_reason"], "SAMPLER_ERROR", result)
                self.assertIn(error, result["sampler_error"])
                self.assertFalse(result["sampler_valid"])
                self.assertTrue(result["reaped"])
                self.assertEqual(result["samples_attempted"], attempts)
                self.assertEqual(result["samples_succeeded"], succeeded)
                self.assertEqual(result["rss_peak_kib"], peak)
                self.assertEqual(result["peak_rss_kib"], peak)
                census = result["darwin_census"]
                self.assertEqual((census["ps_missing_child"], census["ps_timeouts"], census["recoveries"]),
                                 (misses, timeouts, 0))

    def test_missing_child_retry_keeps_stop_and_rss_gap_limits(self):
        for live, stop_at, pause, retry_at, boundary, gap, peak in (
            ([(.1, None, ""), "timeout"], .8, 0, .1, .8, .8, None),
            ([(.05, 50, ""), (.8, None, ""), "timeout"], 6, 3.25, 4.1, 5.05, 5, 50),
        ):
            with self.subTest(stop_at=stop_at, gap=gap):
                sim = DarwinSimulation(self, live)

                def memory():
                    # Model a scheduling pause after the first valid RSS sample.
                    if len(sim.live_calls()) == 1:
                        sim.advance(pause)
                    return CLEAR

                result = sim.run(stop_at=stop_at, memory=memory)
                self.assertEqual(result["stop_reason"], "SAMPLER_ERROR", result)
                self.assertFalse(result["sampler_valid"])
                self.assertTrue(result["reaped"], result)
                self.assertEqual(result["rss_peak_kib"], peak)
                self.assertEqual(result["samples_attempted"], len(live))
                at, timeout = sim.live_calls()[-1]
                self.assertAlmostEqual(at, retry_at)
                self.assertAlmostEqual(timeout, boundary - retry_at)
                self.assertAlmostEqual(result["darwin_census"]["max_gap_seconds"], gap)
                self.assertLessEqual(result["monotonic_end"], stop_at + 4)

    def test_retry_is_immediate_and_a_fresh_sample_checks_rss_cap(self):
        sim = DarwinSimulation(self, [(.05, 50, ""), "timeout", (.35, 101, "")])
        memory_times = []

        def memory():
            memory_times.append(sim.now)
            sim.advance(.1 if len(memory_times) == 3 else 0)
            return CLEAR

        result = sim.run(memory=memory)
        self.assertEqual(result["stop_reason"], "RSS_LIMIT", result)
        self.assertTrue(result["sampler_valid"] and result["reaped"], result)
        self.assertEqual(result["rss_peak_kib"], 101)
        self.assertEqual((result["samples_attempted"], result["samples_succeeded"], result["samples_missed"]), (3, 2, 6))
        self.assertEqual(result["samples_expected"], 8)
        self.assertAlmostEqual(sim.live_calls()[2][0], 1.9)
        self.assertAlmostEqual(sim.live_calls()[2][1], 1.5)
        self.assertAlmostEqual(memory_times[2], 1.8)
        self.assertAlmostEqual(memory_times[3], 2.25)
        self.assertAlmostEqual(result["sampling_cadence_seconds"], 2.2)
        census = result["darwin_census"]
        self.assertEqual((census["ps_timeouts"], census["recoveries"]), (1, 1))
        self.assertEqual(census["last_timeout"]["reason"], "PS_CENSUS_TIMEOUT")
        self.assertAlmostEqual(census["max_gap_seconds"], 2.2)

    def test_full_ps_timeout_leaves_budget_to_recover_rss(self):
        sim = DarwinSimulation(self, [(.05, 50, ""), "timeout", (1.4, 75, ""), (.05, None, "")], exit_at=3.225)
        result = sim.run(stop_at=6)

        self.assertEqual(result["stop_reason"], "EXITED", result)
        self.assertTrue(result["sampler_valid"] and result["reaped"], result)
        self.assertEqual(result["samples_succeeded"], 2)
        self.assertEqual(result["rss_peak_kib"], 75)
        self.assertAlmostEqual(sim.live_calls()[2][0], 1.8)
        self.assertEqual(sim.live_calls()[2][1], 1.5)
        census = result["darwin_census"]
        self.assertEqual(census["ps_timeout_seconds"], 1.5)
        self.assertEqual(census["rss_gap_limit_seconds"], 5.0)
        self.assertEqual((census["ps_timeouts"], census["recoveries"]), (1, 1))
        self.assertEqual(census["last_timeout"]["timeout_seconds"], 1.5)
        self.assertAlmostEqual(census["max_gap_seconds"], 3.15)

    def test_two_separate_series_recover_and_resume_cadence(self):
        sim = DarwinSimulation(self, ["timeout", (.2, 50, ""), "timeout", (.2, 60, "")])
        result = sim.run(stop_at=4.1)
        self.assertEqual(result["stop_reason"], "TIMEOUT", result)
        self.assertTrue(result["sampler_valid"] and result["reaped"], result)
        self.assertEqual(result["rss_peak_kib"], 60)
        self.assertEqual(result["darwin_census"]["ps_timeouts"], 2)
        self.assertEqual(result["darwin_census"]["recoveries"], 2)
        self.assertAlmostEqual(sim.live_calls()[2][0], 1.8)
        self.assertAlmostEqual(sim.live_calls()[4][0], 3.6)
        self.assertAlmostEqual(result["wall_seconds"], 4.1, delta=.1)

    def test_unrecovered_census_fails_closed_and_keeps_previous_peak(self):
        for live, stop_at, exit_at, error, peak, attempts, gap in (
            ([(.05, 50, ""), "timeout", "timeout"], 6, float("inf"), "retry timed out", 50, 3, 3.25),
            (["timeout", "timeout"], 6, float("inf"), "retry timed out", None, 2, 3),
            (["timeout"], .8, float("inf"), "recovery deadline", None, 1, .8),
            (["timeout", "timeout"], 1.9, float("inf"), "retry timed out", None, 2, 1.9),
            (["timeout", (3.51, 111, "")], 6, float("inf"), "recovery deadline", None, 2, 5.01),
            (["timeout"], 4, .5, "child exited", None, 1, 1.5),
            ([(.05, 50, ""), "timeout", (.4, 111, "")], 4, 2.1, "child exited", 50, 3, 2.15),
        ):
            with self.subTest(live=live, stop_at=stop_at, exit_at=exit_at):
                sim = DarwinSimulation(self, live, exit_at=exit_at)
                result = sim.run(stop_at=stop_at)
                self.assertEqual(result["stop_reason"], "SAMPLER_ERROR", result)
                self.assertIn(error, result["sampler_error"])
                self.assertFalse(result["sampler_valid"])
                self.assertTrue(result["reaped"], result)
                self.assertEqual(result["rss_peak_kib"], peak)
                self.assertEqual(result["samples_attempted"], attempts)
                self.assertEqual(result["darwin_census"]["recoveries"], 0)
                self.assertAlmostEqual(result["darwin_census"]["max_gap_seconds"], gap)
                self.assertLessEqual(result["monotonic_end"], stop_at + 4)
                if stop_at == 1.9:
                    self.assertAlmostEqual(sim.live_calls()[1][1], .4)

    def test_first_sample_or_retry_cannot_arrive_after_its_budget(self):
        sim = DarwinSimulation(self, [(.81, 111, "")])
        result = sim.run(stop_at=.8)
        self.assertEqual(result["stop_reason"], "SAMPLER_ERROR", result)
        self.assertIn("before first Darwin RSS sample", result["sampler_error"])
        self.assertIsNone(result["rss_peak_kib"])
        self.assertTrue(result["reaped"])

        sim = DarwinSimulation(self, ["timeout"])

        def slow_memory():
            if sim.now > 0:
                sim.advance(3.5)
            return CLEAR

        result = sim.run(stop_at=6, memory=slow_memory)
        self.assertEqual(result["stop_reason"], "SAMPLER_ERROR", result)
        self.assertIn("recovery deadline", result["sampler_error"])
        self.assertEqual(result["samples_attempted"], 1)
        self.assertTrue(result["reaped"])
        self.assertEqual(result["darwin_census"]["max_gap_seconds"], 5)

    def test_memory_guards_stop_during_the_gap_and_after_recovery(self):
        for snapshot, expected in ((CLEAR | {"pressure": "PRESSURE"}, "LIVE_MEMORY_PRESSURE"),
                                   (CLEAR | {"available_kib": 99}, "LIVE_MEMORY_RESERVE")):
            for recovered in (False, True):
                with self.subTest(expected=expected, recovered=recovered):
                    sim = DarwinSimulation(self, [(.05, 50, ""), "timeout", (.1, 101, "")])
                    readings = iter([CLEAR, CLEAR] + ([CLEAR] if recovered else []) + [snapshot])
                    result = sim.run(memory=lambda: next(readings))
                    self.assertEqual(result["stop_reason"], expected, result)
                    self.assertTrue(result["reaped"], result)
                    self.assertEqual(result["sampler_valid"], recovered)
                    self.assertEqual(result["samples_attempted"], 3 if recovered else 2)
                    self.assertEqual(result["rss_peak_kib"], 101 if recovered else 50)
                    self.assertEqual(result["darwin_census"]["recoveries"], int(recovered))

    def test_non_census_errors_fail_immediately(self):
        for error in (subprocess.CalledProcessError(1, CENSUS), OSError("ps launch failed"), "bad snapshot", ""):
            with self.subTest(error=error):
                if isinstance(error, str):
                    sim = DarwinSimulation(self)
                    native_ps = sim.ps

                    def ps(*args, **kwargs):
                        result = native_ps(*args, **kwargs)
                        if not sim.cleaning:
                            result.stdout = error
                        return result

                    sim.ps = ps
                else:
                    sim = DarwinSimulation(self, [error])
                result = sim.run()
                self.assertEqual(result["stop_reason"], "SAMPLER_ERROR", result)
                self.assertEqual(result["samples_attempted"], 1)
                self.assertEqual(result["darwin_census"]["ps_timeouts"], 0)
                self.assertFalse(result["sampler_valid"])
                self.assertTrue(result["reaped"], result)

        for live in ([], ["timeout"]):
            with self.subTest(live=live):
                memory = Mock(side_effect=[CLEAR, subprocess.TimeoutExpired("memory_pressure", .5)])
                result = DarwinSimulation(self, live).run(memory=memory)
                self.assertEqual(result["stop_reason"], "SAMPLER_ERROR", result)
                self.assertIn("memory_pressure", result["sampler_error"])
                self.assertEqual(result["samples_attempted"], 1)
                self.assertEqual(result["darwin_census"]["ps_timeouts"], len(live))
                self.assertEqual(result["darwin_census"]["recoveries"], 0)
                self.assertFalse(result["sampler_valid"])
                self.assertTrue(result["reaped"], result)

    def test_cleanup_timeout_does_not_block_anchored_term_or_final_reap(self):
        def cleanup(sim, timeout):
            if len(sim.cleanup_calls()) == 1:
                sim.ps_timeout(timeout)
            sim.advance(.6)
            return INIT

        sim = DarwinSimulation(self, [(.05, 101, "")], cleanup=cleanup)
        result = sim.run()
        self.assertEqual(result["stop_reason"], "RSS_LIMIT", result)
        self.assertTrue(result["reaped"], result)
        self.assertEqual(sim.signals, [(.3, "group", signal.SIGTERM)])
        self.assertEqual([budget for _, budget in sim.cleanup_calls()], [.25, 1, 1])
        self.assertEqual(len(result["cleanup_errors"]), 1)
        self.assertEqual(result["darwin_census"]["ps_timeouts"], 0)

    def test_cleanup_timeout_requires_final_group_check_after_child_reap(self):
        def cleanup(sim, timeout):
            if len(sim.cleanup_calls()) == 1:
                sim.ps_timeout(timeout)
            self.assertIsNotNone(sim.proc.returncode)
            return INIT + ORPHAN

        sim = DarwinSimulation(self, [(.05, 101, "")], cleanup=cleanup)
        result = sim.run()
        self.assertEqual(result["stop_reason"], "REAP_UNVERIFIED", result)
        self.assertEqual(result["primary_stop_reason"], "RSS_LIMIT")
        self.assertFalse(result["reaped"])
        self.assertEqual(result["remaining_processes"], [11])
        self.assertEqual(sim.signals, [(.3, "group", signal.SIGTERM)])
        self.assertEqual([budget for _, budget in sim.cleanup_calls()], [.25, 1, 1])

    def test_cleanup_rejects_late_observation_and_reserves_kill_and_final(self):
        def cleanup(sim, timeout):
            call = len(sim.cleanup_calls())
            if call == 1:
                return INIT + LEADER.format(rss=101)
            if call == 5:
                sim.advance(timeout + .001)
                return INIT
            sim.ps_timeout(timeout)

        sim = DarwinSimulation(self, [(.05, 101, "")], cleanup=cleanup, ignore_term=True)
        result = sim.run(stop_at=.5, term_grace=1.5, kill_grace=2)
        self.assertEqual(result["stop_reason"], "REAP_UNVERIFIED", result)
        self.assertEqual(result["primary_stop_reason"], "RSS_LIMIT")
        self.assertFalse(result["reaped"])
        self.assertIsNone(result["remaining_processes"])
        (term_at, _, term), (kill_at, _, kill) = sim.signals
        self.assertEqual((term, kill), (signal.SIGTERM, signal.SIGKILL))
        self.assertAlmostEqual(term_at, .05)
        self.assertAlmostEqual(kill_at, 1.55)
        first, term1, term2, kill1, kill2, final = sim.cleanup_calls()
        self.assertAlmostEqual(first[1], .25)
        self.assertAlmostEqual(term1[1], 1)
        self.assertAlmostEqual(sum(term2), kill_at)
        self.assertAlmostEqual(kill1[1], 1)
        self.assertAlmostEqual(sum(kill2), 2.95)
        self.assertLessEqual(sum(final), 4)
        self.assertAlmostEqual(final[1], 1)

    def test_cleanup_does_not_signal_unconfirmed_or_reused_pid(self):
        for identity in ("reuse", "timeout", "late"):
            with self.subTest(identity=identity):
                def cleanup(sim, timeout):
                    call = len(sim.cleanup_calls())
                    if call == 1:
                        return INIT + LEADER.format(rss=50) + ESCAPED
                    if call == 2:
                        if identity == "timeout":
                            sim.ps_timeout(timeout)
                        if identity == "late":
                            sim.advance(timeout + .01)
                            return INIT + ESCAPED
                        return INIT + REUSED
                    return INIT + REUSED

                sim = DarwinSimulation(self, [(.05, 50, ESCAPED)], cleanup=cleanup)
                result = sim.run(term_grace=.5)
                self.assertEqual(result["stop_reason"], "RSS_LIMIT", result)
                self.assertTrue(result["reaped"], result)
                self.assertEqual(sim.signals, [(.05, "group", signal.SIGTERM)])
                self.assertAlmostEqual(sim.cleanup_calls()[1][1], .5)
                self.assertEqual(bool(result["cleanup_errors"]), identity != "reuse")
