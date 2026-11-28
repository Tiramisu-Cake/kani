# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Bounded, advisory Linux RSS and CBMC PSS observations for CAL2."""
from collections import Counter, deque
import errno
from functools import partial
import os
from pathlib import Path
from queue import Empty, Queue
import re
from threading import BoundedSemaphore, Thread
import time


PSS_INTERVAL = 1.0
PSS_MAX_AGE = 1.0
SERIES_ROWS = 128
FIRST_ROWS = 16
PID_ROWS = 64
CENSUS_ROWS = 64
CENSUS_SCOPE = ("Each key sample keeps up to 64 processes of the same group census, largest RSS first. "
                "Linux VmRSS counts shared pages in every process and a sampled TID turnover can report zero. "
                "Omitted or skipped rows make that sample's attribution incomplete.")
RELAY_PHASES = {"STARTED": "before_wait_done", "CBMC_RUNNING": "before_wait_done", "WAIT_DONE": "replay",
                "REPLAYING": "replay", "REPLAY_DONE": "after_replay"}


def read_pss(pid, start_id, proc=Path("/proc")):
    # Open relative to the procfs PID directory so PID reuse cannot redirect
    # the smaps read. Check the census identity both before and after the read.
    from supervisor import _linux_stat

    try:
        fd = os.open(proc / str(pid), os.O_RDONLY | os.O_DIRECTORY)
        try:
            opener = partial(os.open, dir_fd=fd)
            if int(_linux_stat(opener)[19]) != start_id:
                return None, "PID_IDENTITY_CHANGED"
            with open("smaps_rollup", opener=opener) as stream:
                data = stream.read(16385)
            if int(_linux_stat(opener)[19]) != start_id:
                return None, "PID_IDENTITY_CHANGED"
        finally:
            os.close(fd)
    except OSError as exc:
        if exc.errno == errno.ESRCH:
            return None, "ESRCH"
        if exc.errno in (errno.EACCES, errno.EPERM):
            return None, "ACCESS_DENIED"
        if exc.errno == errno.ENOENT:
            return None, "PROCESS_OR_ROLLUP_GONE"
        return None, "READ_ERROR"
    except (IndexError, ValueError):
        return None, "INVALID_PROC_DATA"
    matches = re.findall(r"^Pss:[ \t]+([0-9]+)[ \t]+kB[ \t]*$", data, re.M)
    if len(data) > 16384:
        return None, "ROLLUP_TOO_LARGE"
    if len(matches) != 1 or len(matches[0]) > 20:
        return None, "PSS_MISSING_OR_INVALID"
    return int(matches[0]), None


class PssProbe:
    """One daemon reader per job, at most one outstanding procfs read."""

    def __init__(self, read=read_pss):
        self._read = read
        self._inbox = Queue(maxsize=1)
        self._available = BoundedSemaphore(1)
        self._next_read = 0.0
        Thread(target=self._worker, daemon=True, name="cal2-pss").start()

    def _worker(self):
        while True:
            pid, start_id, reply = self._inbox.get()
            started_at = time.monotonic()
            try:
                pss, reason = self._read(pid, start_id)
            except Exception:
                pss, reason = None, "PROBE_ERROR"
            finished_at = time.monotonic()
            reply.put_nowait((started_at, finished_at, pss, reason))
            self._next_read = started_at + PSS_INTERVAL
            self._available.release()

    def submit(self, pid, start_id):
        if not self._available.acquire(blocking=False):
            return None, "READ_IN_FLIGHT"
        if time.monotonic() < self._next_read:
            self._available.release()
            return None, "RATE_LIMIT"
        reply = Queue(maxsize=1)
        self._inbox.put_nowait((pid, start_id, reply))
        return reply, None


class MemoryTelemetry:
    """Keep peaks and nearest valid PSS online, plus a bounded sample series."""

    def __init__(self, probe, *, pss_unavailable=None, relay_phase=None):
        self.probe = probe
        self.pss_unavailable = pss_unavailable
        self.relay_phase = relay_phase
        self.census = {}
        self.relay_phase_errors = 0
        self.samples = 0
        self.attempts = 0
        self.successes = 0
        self.reasons = Counter()
        self.first = []
        self.tail = deque(maxlen=SERIES_ROWS - FIRST_ROWS)
        self.group_peak = self.cbmc_peak = self.last = None
        self.group_nearest = self.cbmc_nearest = self.last_pss = None
        self.pending = None

    @staticmethod
    def _nearest(peak, nearest, observation):
        if peak is None:
            return None
        at = peak["monotonic"]
        if nearest is None or abs(at - observation["monotonic"]) < abs(at - nearest["monotonic"]):
            return observation
        return nearest

    def _collect(self, stop_at=None):
        if self.pending is None:
            return
        reply, sample, pid = self.pending
        try:
            started, ended, value, reason = reply.get_nowait()
        except Empty:
            if stop_at is None:
                return
            started = ended = value = None
            reason = "PENDING_AT_STOP"
        self.pending = None
        age = None if ended is None else ended - sample["monotonic"]
        if age is not None and age > PSS_MAX_AGE:
            value, reason = None, "LATE_RESPONSE"
        elif ended is not None and stop_at is not None and ended > stop_at:
            value, reason = None, "AFTER_STOP"
        observation = {
            "sample": sample["sample"], "monotonic": sample["monotonic"], "phase": sample["phase"],
            "group_rss_kib": sample["group_rss_kib"], "cbmc_count": sample["cbmc_count"],
            "cbmc_rss_kib": sample["cbmc_rss_kib"], **pid,
            "pss_kib": value, "reason": reason, "read_started_monotonic": started,
            "read_finished_monotonic": ended, "read_latency_seconds": None if ended is None else ended - started,
            "rss_to_pss_seconds": age,
        }
        sample["pss"] = observation
        if value is None:
            self.reasons[reason] += 1
        else:
            self.successes += 1
            self.last_pss = observation
            self.group_nearest = self._nearest(self.group_peak, self.group_nearest, observation)
            self.cbmc_nearest = self._nearest(self.cbmc_peak, self.cbmc_nearest, observation)

    def observe(self, sample, at):
        self._collect()
        pids = set(sample["verifier_pids"])
        backend = sorted(
            ({"pid": row["pid"], "start_id": row["start_id"], "rss_kib": row["rss"]}
             for row in sample["records"] if row["pid"] in pids),
            key=lambda row: row["pid"],
        )
        self.samples += 1
        row = {
            "sample": self.samples, "monotonic": at, "phase": sample["phase"], "group_rss_kib": sample["rss_kib"],
            "cbmc_count": len(backend), "cbmc_rss_kib": sum(pid["rss_kib"] for pid in backend),
            "cbmc": backend[:PID_ROWS], "cbmc_pid_rows_omitted": max(0, len(backend) - PID_ROWS),
            "pss": {"pss_kib": None, "reason": self.pss_unavailable or "NO_CBMC"},
        }
        self.last = row
        self._census(sample, row, pids)
        if self.group_peak is None or row["group_rss_kib"] > self.group_peak["group_rss_kib"]:
            self.group_peak, self.group_nearest = row, self.last_pss
        if backend and (self.cbmc_peak is None or row["cbmc_rss_kib"] > self.cbmc_peak["cbmc_rss_kib"]):
            self.cbmc_peak, self.cbmc_nearest = row, self.last_pss
        if len(self.first) < FIRST_ROWS:
            self.first.append(row)
        else:
            self.tail.append(row)
        if not backend or self.probe is None:
            return
        # One PID per eligible sample. Rotate if the census sees several CBMCs.
        pid = backend[self.attempts % len(backend)]
        reply, reason = (None, "READ_IN_FLIGHT") if self.pending else self.probe.submit(pid["pid"], pid["start_id"])
        row["pss"] = {"pss_kib": None, "reason": reason or "PENDING"}
        if reply is not None:
            self.attempts += 1
            self.pending = (reply, row, pid)
        else:
            self.reasons[reason] += 1

    def _census(self, sample, row, verifier_pids):
        """Keep bounded whole-group attributions for the peak, last and relay-phase peaks."""
        phase = None
        if self.relay_phase is not None:
            try:
                phase = self.relay_phase()
            except Exception:
                self.relay_phase_errors += 1
                phase = "UNKNOWN"
        records = sorted(sample["records"], key=lambda item: (-item["rss"], item["pid"]))
        processes = [{"pid": item["pid"], "ppid": item.get("ppid"), "start_id": item["start_id"],
                      "image": item.get("image", "UNKNOWN"), "rss_kib": item["rss"],
                      "cbmc": item["pid"] in verifier_pids} for item in records[:CENSUS_ROWS]]
        skipped = sample.get("pid_records_skipped", 0)
        entry = {"row": row, "relay_phase": phase, "processes": processes,
                 "processes_omitted": len(records) - len(processes), "pid_records_skipped": skipped,
                 "attribution_complete": len(records) <= CENSUS_ROWS and skipped == 0}
        keys = ["group_peak", "last"]
        segment = RELAY_PHASES.get(phase) if phase is not None else None
        if segment:
            keys.append(f"group_peak_{segment}")
        for key in keys:
            current = self.census.get(key)
            if key == "last" or current is None or row["group_rss_kib"] > current["row"]["group_rss_kib"]:
                self.census[key] = entry

    def census_publication(self):
        published = {}
        for key, entry in self.census.items():
            row = entry["row"]
            published[key] = {
                "sample": row["sample"], "monotonic": row["monotonic"], "phase": row["phase"],
                "group_rss_kib": row["group_rss_kib"], "cbmc_rss_kib": row["cbmc_rss_kib"],
                "cbmc_count": row["cbmc_count"], "cbmc_pss": row["pss"], "relay_phase": entry["relay_phase"],
                "processes": entry["processes"], "processes_omitted": entry["processes_omitted"],
                "pid_records_skipped": entry["pid_records_skipped"],
                "attribution_complete": entry["attribution_complete"],
            }
        return {"scope": CENSUS_SCOPE, "rows_per_sample_limit": CENSUS_ROWS, "relay_phase_probe":
                self.relay_phase is not None, "relay_phase_errors": self.relay_phase_errors,
                "samples": published}

    def finish(self, stop_at):
        self._collect(stop_at)

    def publication(self):
        retained = self.first + list(self.tail)
        compact = {
            "rss_samples": self.samples, "series_rows_omitted": self.samples - len(retained),
            "group_peak": self.group_peak, "cbmc_peak": self.cbmc_peak, "last_rss_sample": self.last,
            "nearest_pss_to_group_peak": self.group_nearest, "nearest_pss_to_cbmc_peak": self.cbmc_nearest,
            "pss_attempts": self.attempts, "pss_successes": self.successes, "pss_reasons": dict(self.reasons),
            "pss_min_interval_seconds": PSS_INTERVAL, "pss_max_rss_age_seconds": PSS_MAX_AGE,
            "pss_scope": "Selected CBMC PID from RSS census, one PID per probe. Group PSS is unknown.",
            "group_census": self.census_publication(),
        }
        return retained, compact
