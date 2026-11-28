"""Portable, fail-closed resource supervisor for one CAL2 invocation.

The resource sample is a polled sum over the dedicated process group and its
observed descendants. It is not an atomic/kernel peak; shared pages can be
counted more than once. A monotonic absolute deadline includes shutdown.
"""
from __future__ import annotations

import errno
from functools import partial
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import threading
import time


TIMELINE_LIMIT = 128
SAMPLE_INTERVAL = 0.3
TERM_GRACE = 5.0
KILL_GRACE = 5.0
DARWIN_CLEANUP_PS_TIMEOUT = 1.0
DARWIN_PS_TIMEOUT = 1.5
DARWIN_RSS_MAX_GAP = 5.0
LINUX_PRESSURE_THRESHOLD = 5.0  # PSI full avg10, in percent
LINUX_PRESSURE_MIN_SAMPLES = 3
LINUX_PRESSURE_MIN_SECONDS = 2.0
STDOUT_CAP_BYTES = 16 * 1024 * 1024
STDERR_CAP_BYTES = 4 * 1024 * 1024
DEAD_STATES = ("Z", "X", "x")
RSS_CAVEAT = ("On Linux, worker TID turnover after the main thread exits can give a live process zero RSS "
              "in a sample. The observed peak RSS may be underestimated. Confirming compliance with the RSS cap "
              "requires evidence beyond the absence of RSS_LIMIT.")
REAP_SCOPE = ("After the direct child is reaped, cleanup signals only previously observed descendants "
              "individually by PID and start identity. On Darwin, if the initial cleanup census fails, "
              "final confirmation also checks for live members of the original process group. "
              "On Darwin, an empty census after direct child exit can yield EXITED without checking live pressure or reserve.")


class SupervisorError(RuntimeError):
    pass


class DarwinCensusTimeout(SupervisorError):
    pass


class Timeline(list):
    def __init__(self):
        super().__init__()
        self.omitted = 0


def _positive_int(value, label):
    if type(value) is not int or value <= 0:
        raise SupervisorError(f"{label} must be a positive integer")
    return value


def _nonnegative_int(value, label):
    if type(value) is not int or value < 0:
        raise SupervisorError(f"{label} must be a non-negative integer")
    return value


def parse_linux_status_rss(text: str) -> int:
    """Parse Linux VmRSS (KiB), rejecting missing, duplicate, or malformed data."""
    matches = re.findall(r"^VmRSS:\s+(\d+)\s+kB\s*$", text, re.MULTILINE)
    if len(matches) != 1:
        raise SupervisorError("Linux status has no unique valid VmRSS")
    return int(matches[0])


def _linux_status_rss(text: str) -> int:
    matches = re.findall(r"^VmRSS:\s+(\d+)\s+kB\s*$", text, re.MULTILINE)
    if len(matches) == 1:
        return int(matches[0])
    # Kernel threads have no userspace address space and legitimately omit all
    # Vm* size fields. Missing VmRSS for a userspace process remains an error.
    if not matches and not re.search(r"^Vm(?:Size|Peak):", text, re.MULTILINE):
        return 0
    raise SupervisorError("Linux status has no unique valid VmRSS")


def parse_darwin_ps_rss(text: str) -> int:
    """Parse one `ps -o rss=` value (KiB), rejecting non-numeric/ambiguous data."""
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != 1 or not re.fullmatch(r"\d+", lines[0]):
        raise SupervisorError("Darwin ps RSS is not one non-negative integer")
    return int(lines[0])


def _process_gone(exc):
    return isinstance(exc, ProcessLookupError) or exc.errno == errno.ESRCH


def _proc_entry_gone(exc):
    return isinstance(exc, FileNotFoundError) or _process_gone(exc)


def _linux_stat(opener):
    with open("stat", opener=opener) as stream:
        stat = stream.read()
    return stat[stat.rfind(")") + 2:].split()


def _linux_details(opener):
    with open("cmdline", "rb", opener=opener) as stream:
        cmd = stream.read().replace(b"\0", b" ").decode(errors="replace").strip()
    with open("status", opener=opener) as stream:
        rss = _linux_status_rss(stream.read())
    return rss, cmd.split()[0].rsplit("/", 1)[-1] if cmd else "UNKNOWN"


def _linux_thread_details(pid_fd, leader):
    try:
        tasks_fd = os.open("task", os.O_RDONLY | os.O_DIRECTORY, dir_fd=pid_fd)
        try:
            for tid in os.listdir(tasks_fd):
                if tid == leader or not tid.isdigit():
                    continue
                try:
                    thread_fd = os.open(tid, os.O_RDONLY | os.O_DIRECTORY, dir_fd=tasks_fd)
                    try:
                        opener = partial(os.open, dir_fd=thread_fd)
                        if _linux_stat(opener)[0] not in DEAD_STATES:
                            return _linux_details(opener)
                    finally:
                        os.close(thread_fd)
                except OSError as exc:
                    if not _proc_entry_gone(exc):
                        raise
        finally:
            os.close(tasks_fd)
    except OSError as exc:
        if not _proc_entry_gone(exc):
            raise
    return None


def _linux_pid_record(entry):
    # Relative opens stay attached to this procfs PID directory if its number
    # is recycled during the reads.
    fd = os.open(entry, os.O_RDONLY | os.O_DIRECTORY)
    try:
        opener = partial(os.open, dir_fd=fd)
        tail = _linux_stat(opener)
        other_threads = tail[0] in DEAD_STATES and int(tail[17]) > 1
        if other_threads:
            # The zombie leader has lost its mm. Read the shared RSS once
            # from a worker. If threads race the walk, keep the group in the
            # census until a subsequent stat confirms the workers are gone.
            rss, image = _linux_thread_details(fd, entry.name) or (0, "UNKNOWN")
        else:
            rss, image = _linux_details(opener)
    finally:
        os.close(fd)
    pid = int(entry.name)
    return {"pid": pid, "ppid": int(tail[1]), "pgid": int(tail[2]),
            "state": tail[0], "has_other_threads": other_threads,
            "start_id": int(tail[19]), "rss": rss, "image": image}


def _linux_table(on_pid_skip=None):
    table = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            row = _linux_pid_record(entry)
        except OSError as exc:
            if not _proc_entry_gone(exc):
                raise
            if on_pid_skip is not None:
                on_pid_skip()
        except (IndexError, ValueError) as exc:
            raise SupervisorError(f"invalid /proc process record: {entry.name}") from exc
        else:
            table[row["pid"]] = row
    return table


def _darwin_table(timeout=.5):
    try:
        proc = subprocess.run(["ps", "-axww", "-o", "pid=,ppid=,pgid=,rss=,stat=,lstart=,comm="],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                              check=True, timeout=timeout, env=os.environ | {"LC_ALL": "C"})
    except subprocess.TimeoutExpired as exc:
        raise DarwinCensusTimeout(f"Darwin ps census timed out after {timeout:.3f} s") from exc
    return _parse_darwin_table(proc.stdout)


def _parse_darwin_table(text):
    table = {}
    for line in text.splitlines():
        fields = line.split(maxsplit=10)
        if len(fields) != 11 or any(not re.fullmatch(r"\d+", x) for x in fields[:4]):
            raise SupervisorError("invalid Darwin ps process table")
        pid, ppid, pgid, rss = map(int, fields[:4])
        table[pid] = {"pid": pid, "ppid": ppid, "pgid": pgid, "rss": rss,
                      "state": fields[4][0], "image": fields[10].rsplit("/", 1)[-1],
                      "start_id": " ".join(fields[5:10])}
    if not table:
        raise SupervisorError("empty Darwin ps process table")
    return table


def process_table(platform=None, timeout=.5, *, on_pid_skip=None):
    platform = platform or sys_platform()
    if platform == "linux":
        return _linux_table(on_pid_skip)
    if platform == "darwin":
        return _darwin_table(timeout)
    raise SupervisorError(f"unsupported platform: {platform}")


def sys_platform():
    import sys
    return sys.platform


def _is_live(row):
    return row.get("state") not in DEAD_STATES or row.get("has_other_threads", False)


def _tree(table, pgid, seeds=()):
    found = {pid for pid, row in table.items() if row["pgid"] == pgid}
    found.update(seeds)
    changed = True
    while changed:
        added = {pid for pid, row in table.items() if row["ppid"] in found}
        changed = not added.issubset(found)
        found.update(added)
    return [table[pid] for pid in sorted(found) if _is_live(table[pid])]


def _linux_memory():
    values = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        m = re.fullmatch(r"(MemTotal|MemAvailable):\s+(\d+)\s+kB", line)
        if m:
            values[m.group(1)] = int(m.group(2))
    if set(values) != {"MemTotal", "MemAvailable"} or values["MemTotal"] <= 0:
        raise SupervisorError("Linux memory inventory unavailable")
    pressure = Path("/proc/pressure/memory").read_text()
    full = re.findall(r"^full[ \t]+avg10=(\S+)", pressure, re.MULTILINE)
    if len(full) != 1:
        raise SupervisorError("Linux memory pressure inventory unavailable")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", full[0]):
        raise SupervisorError("invalid Linux memory pressure")
    avg10 = float(full[0])
    if not math.isfinite(avg10):
        raise SupervisorError("invalid Linux memory pressure")
    # CAL1 uses this diagnostic threshold for Linux admission and live sampling.
    level = "PRESSURE" if avg10 >= LINUX_PRESSURE_THRESHOLD else "CLEAR"
    return {"physical_kib": values["MemTotal"], "available_kib": values["MemAvailable"],
            "pressure": level, "pressure_avg10": avg10}


def _darwin_memory(timeout=.5):
    deadline = time.monotonic() + timeout

    def probe(*argv):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SupervisorError("Darwin memory probe deadline exhausted")
        return subprocess.run(argv, capture_output=True, text=True, check=True,
                              timeout=remaining, env=os.environ | {"LC_ALL": "C"}).stdout.strip()

    total = probe("sysctl", "-n", "hw.memsize")
    if not re.fullmatch(r"\d+", total) or int(total) <= 0:
        raise SupervisorError("invalid Darwin physical memory")
    match = re.search(r"System-wide memory free percentage:\s*(\d+)%", probe("memory_pressure", "-Q"))
    if not match:
        raise SupervisorError("Darwin memory pressure result is unrecognized")
    pct = int(match.group(1))
    if pct > 100:
        raise SupervisorError("invalid Darwin free memory percentage")
    # XNU reports the dispatch level, a single NOTE_MEMORYSTATUS_PRESSURE_* value.
    pressure_levels = {"1": "NORMAL", "2": "WARNING", "4": "CRITICAL"}
    raw_level = probe("sysctl", "-n", "kern.memorystatus_vm_pressure_level")
    if raw_level not in pressure_levels:
        raise SupervisorError(f"invalid Darwin VM pressure level: {raw_level[:80]!r}")
    total_kib = int(total) // 1024
    return {"physical_kib": total_kib, "available_kib": total_kib * pct // 100,
            "pressure": "CLEAR" if raw_level == "1" else "PRESSURE", "free_percent": pct,
            "pressure_level": pressure_levels[raw_level], "pressure_level_raw": int(raw_level)}


def memory_snapshot(platform=None, timeout=.5):
    platform = platform or sys_platform()
    if platform == "linux":
        return _linux_memory()
    if platform == "darwin":
        return _darwin_memory(timeout)
    raise SupervisorError(f"unsupported platform: {platform}")


def _event(timeline, event, **fields):
    timeline.append({"at": time.monotonic(), "event": event, **fields})
    if len(timeline) > TIMELINE_LIMIT:
        del timeline[0]
        timeline.omitted += 1


def _send_signal(send, *args):
    try:
        send(*args)
        return True
    except OSError as exc:
        if _process_gone(exc):
            return False
        raise


def _signal_group(proc, sig):
    return _send_signal(os.killpg, proc.pid, sig)


def _remaining_timeout(deadline, maximum):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SupervisorError("Darwin census deadline exhausted")
    return min(maximum, remaining)


def _signal_owned(record, sig, timeout=.25, *, deadline=None, on_pid_skip=None):
    """Signal only a PID whose current start identity matches our observation."""
    pid = record["pid"]

    def still_owned():
        budget = timeout if deadline is None else _remaining_timeout(deadline, timeout)
        current = process_table(timeout=budget, on_pid_skip=on_pid_skip).get(pid)
        if deadline is not None and time.monotonic() >= deadline:
            raise SupervisorError("Darwin PID identity check exceeded phase deadline")
        return current is not None and current["start_id"] == record["start_id"] and _is_live(current)

    if not still_owned():
        return False
    if sys_platform() != "linux" or not (hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")):
        return _send_signal(os.kill, pid, sig)
    try:
        fd = os.pidfd_open(pid)
    except OSError as exc:
        if _process_gone(exc):
            return False
        raise
    try:
        return still_owned() and _send_signal(signal.pidfd_send_signal, fd, sig)
    finally:
        os.close(fd)


def _owned_live(table, pgid, known):
    """Return live owned processes, discovering descendants while the PGID is anchored."""
    seeds = []
    for pid, old in list(known.items()):
        current = table.get(pid)
        if current is None:
            continue
        if current["start_id"] != old["start_id"]:
            del known[pid]
        elif _is_live(current):
            seeds.append(pid)
    if pgid is None:
        return [table[pid] for pid in sorted(seeds)]
    records = _tree(table, pgid, seeds)
    known.update((row["pid"], row) for row in records)
    return records


def _shutdown(proc, known, timeline, deadline, term_grace, kill_grace, *, on_pid_skip=None):
    """Signal the group until the direct child is reaped, then use known identities."""
    errors = []
    darwin = sys_platform() == "darwin"
    if darwin:
        end_term = min(deadline - kill_grace, time.monotonic() + term_grace)
        # Leave part of KILL for collecting the child, then an independent final ps.
        reap_until = deadline - min(DARWIN_CLEANUP_PS_TIMEOUT, kill_grace / 2)
        end_kill = reap_until - min(.05, kill_grace / 4)
    else:
        reap_until, end_kill = deadline, deadline - .05

    def census(until, maximum, *, confirm_group):
        pgid = proc.pid if proc.poll() is None else None
        if pgid is None:
            known.pop(proc.pid, None)
        timeout = (_remaining_timeout(until, maximum) if darwin else
                   min(.25, max(.01, deadline - time.monotonic())))
        table = process_table(timeout=timeout, on_pid_skip=on_pid_skip)
        if darwin and time.monotonic() >= until:
            raise SupervisorError("Darwin census exceeded phase deadline")
        records = _owned_live(table, pgid, known)
        if confirm_group and pgid is None:
            # Possible group survivors can block final confirmation but are never signal targets.
            owned_pids = {row["pid"] for row in records}
            records.extend(row for row in table.values()
                           if row["pgid"] == proc.pid and row["pid"] not in owned_pids and _is_live(row))
        return records

    def observe(until, maximum=DARWIN_CLEANUP_PS_TIMEOUT, *, confirm_group=False):
        try:
            return census(until, maximum, confirm_group=confirm_group)
        except (OSError, ValueError, SupervisorError, subprocess.SubprocessError) as exc:
            if len(errors) < 8:
                errors.append(f"{type(exc).__name__}: {exc}"[:300])
            return None

    def stop(sig, label, records, until):
        if darwin and time.monotonic() >= until:
            return
        _event(timeline, label, pgid=proc.pid)
        group_signal_allowed = proc.poll() is None
        if group_signal_allowed:
            try:
                _signal_group(proc, sig)
            except OSError as exc:
                errors.append(f"group signal: {exc}"[:300])
        candidates = records if records is not None else list(known.values())
        for row in candidates:
            if (row["pid"] == proc.pid or (group_signal_allowed and row["pgid"] == proc.pid)
                    or time.monotonic() >= until):
                continue
            try:
                if darwin:
                    sent = _signal_owned(row, sig, DARWIN_CLEANUP_PS_TIMEOUT, deadline=until, on_pid_skip=on_pid_skip)
                else:
                    sent = _signal_owned(row, sig, min(.25, max(.01, deadline - time.monotonic())),
                                         on_pid_skip=on_pid_skip)
                if sent:
                    _event(timeline, f"{label}_DESCENDANT", pid=row["pid"])
            except (OSError, ValueError, SupervisorError, subprocess.SubprocessError) as exc:
                if len(errors) < 8:
                    errors.append(f"{type(exc).__name__}: {exc}"[:300])

    def wait_until(until):
        remaining = observe(until) if not darwin or time.monotonic() < until else None
        while (remaining is None or remaining or proc.returncode is None) and time.monotonic() < until:
            time.sleep(min(.04, max(0, until - time.monotonic())))
            if not darwin or time.monotonic() < until:
                remaining = observe(until)
        return remaining

    live = observe(end_term if darwin else deadline, .25)
    confirm_group = darwin and live is None
    had_live_descendant = bool(live and any(row["pid"] != proc.pid for row in live))
    if proc.returncode is None or live is None or live:
        stop(signal.SIGTERM, "TERM", live, end_term if darwin else deadline)
        if not darwin:
            end_term = min(deadline - kill_grace, time.monotonic() + term_grace)
        live = wait_until(end_term)
        if proc.returncode is None or live is None or live:
            stop(signal.SIGKILL, "KILL", live, end_kill if darwin else deadline)
            live = wait_until(end_kill)
    try:
        proc.wait(timeout=max(0, reap_until - time.monotonic()))
    except subprocess.TimeoutExpired:
        errors.append("direct child did not reap by slot deadline")
    live = observe(deadline, confirm_group=confirm_group)
    remaining = sorted(row["pid"] for row in live) if live is not None else None
    return proc.returncode is not None and remaining == [], remaining, errors, had_live_descendant


def run(argv, *, cwd, env, directory, deadline, nominal_kib, reserve_kib,
        sample_interval=SAMPLE_INTERVAL, term_grace=TERM_GRACE,
        kill_grace=KILL_GRACE, sampler=None, pressure_probe=None,
        memory_probe=None, stdout_cap_bytes=STDOUT_CAP_BYTES,
        stderr_cap_bytes=STDERR_CAP_BYTES, diagnostics=None):
    """Run exactly one command with deadline, group RSS, and fail-closed admission.

    `deadline` is an absolute `time.monotonic()` timestamp. Test seams accept
    sampler(pid, pgid) -> {"rss_kib": int, "pids": [...], "verifier_count": int}
    and memory_probe() -> physical_kib/available_kib/pressure (plus pressure_avg10
    for Linux snapshots, which require sustained live pressure). `pressure_probe`
    may return CLEAR/PRESSURE and overrides the snapshot's pressure field.
    """
    nominal_kib = _positive_int(nominal_kib, "nominal_kib")
    reserve_kib = _positive_int(reserve_kib, "reserve_kib")
    if not isinstance(argv, (list, tuple)) or not argv or any(not isinstance(x, str) for x in argv):
        raise SupervisorError("argv must be a non-empty string sequence")
    if not math.isfinite(deadline) or deadline <= time.monotonic():
        raise SupervisorError("deadline must be a future monotonic timestamp")
    if not math.isfinite(sample_interval) or sample_interval <= 0:
        raise SupervisorError("sample_interval must be positive")
    stdout_cap_bytes = _positive_int(stdout_cap_bytes, "stdout_cap_bytes")
    stderr_cap_bytes = _positive_int(stderr_cap_bytes, "stderr_cap_bytes")
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    darwin = sys_platform() == "darwin"
    result = {"status": "NOT_STARTED", "argv": list(argv), "monotonic_start": started,
              "monotonic_end": None, "wall_seconds": None, "exit_code": None,
              "signal": None, "reaped": False, "rss_peak_kib": None,
              "rss_scope": "DEDICATED_PROCESS_GROUP_PLUS_OBSERVED_DESCENDANTS; POLLED_NONATOMIC_SUM; shared-page double-counting possible",
              "rss_caveat": RSS_CAVEAT, "reap_scope": REAP_SCOPE,
              "sampler_valid": False, "pressure": "UNKNOWN", "memory": None,
              "nominal_cap_kib": nominal_kib, "reserve_kib": reserve_kib,
              "effective_cap_kib": None, "stop_reason": None, "timeline": [],
              "rss_method": "Linux /proc VmRSS KiB" if sys_platform() == "linux" else "Darwin ps rss KiB",
              "timeline_omitted": 0, "max_simultaneous_verifier_processes": 0,
              "max_verifier_children": 0, "peak_rss_kib": None,
              "samples_attempted": 0, "samples_succeeded": 0, "samples_missed": 0,
              "sample_pid_records_skipped": 0, "cleanup_pid_records_skipped": 0,
              "samples_expected": None, "missed_sample_fraction": None,
              "sampling_cadence_seconds": None, "sampling_interval_target_seconds": sample_interval,
              "cbmc_pid_transitions": [], "cbmc_pid_transitions_omitted": 0,
              "owned_process_count": 0,
              "stdout_bytes": 0, "stderr_bytes": 0,
              "stdout_complete": True, "stderr_complete": True,
              "last_observed_phase": "UNKNOWN", "last_phase_monotonic": None,
              "observed_process_images": []}
    timeline = Timeline()
    result["timeline"] = timeline
    proc = None
    capture = {"stdout_bytes": 0, "stderr_bytes": 0,
               "stdout_truncated": False, "stderr_truncated": False}
    readers = []
    known = {}
    pending_exception = None
    previous_cbmc = None
    previous_cbmc_count = None
    sample_timestamps = []
    high_pressure_started = None
    high_pressure_samples = 0
    stop_at = max(time.monotonic(), deadline - term_grace - kill_grace)
    recovering = False
    missing_child_in_gap = False
    census = None
    if darwin:
        census = {"ps_timeout_seconds": DARWIN_PS_TIMEOUT, "rss_gap_limit_seconds": DARWIN_RSS_MAX_GAP,
                  "ps_timeouts": 0, "ps_missing_child": 0, "recoveries": 0,
                  "max_gap_seconds": None, "last_timeout": None}
        result["darwin_census"] = census

    def count_sample_pid_skip():
        result["sample_pid_records_skipped"] += 1

    def count_cleanup_pid_skip():
        result["cleanup_pid_records_skipped"] += 1

    def memory_call(timeout=None):
        if memory_probe:
            return memory_probe()
        if timeout is None:
            timeout = min(.5, max(.01, stop_at - time.monotonic()))
        return memory_snapshot(timeout=timeout)

    def live_memory(timeout=None):
        snapshot = memory_call(timeout)
        if (not isinstance(snapshot, dict) or
                type(snapshot.get("physical_kib")) is not int or
                type(snapshot.get("available_kib")) is not int or
                snapshot["physical_kib"] <= 0 or snapshot["available_kib"] < 0 or
                snapshot["available_kib"] > snapshot["physical_kib"]):
            raise SupervisorError("live memory sampler returned invalid record")
        pressure = pressure_probe() if pressure_probe else snapshot.get("pressure")
        if pressure not in ("CLEAR", "PRESSURE"):
            raise SupervisorError("live memory pressure is unknown or invalid")
        result["memory"] = snapshot | {"pressure": pressure}
        result["minimum_available_kib"] = min(result["minimum_available_kib"], snapshot["available_kib"])
        result["pressure"] = pressure
        return snapshot, pressure

    def stop_for_memory(snapshot, pressure_confirmed):
        if pressure_confirmed:
            result["stop_reason"] = "LIVE_MEMORY_PRESSURE"
            _event(timeline, "LIVE_MEMORY_PRESSURE", memory=result["memory"])
        elif snapshot["available_kib"] < reserve_kib:
            result["stop_reason"] = "LIVE_MEMORY_RESERVE"
        return result["stop_reason"] is not None

    def record_census_exit():
        result["stop_reason"] = "EXITED"
        result["sampler_valid"] = bool(sample_timestamps)

    def census_timeout(until, maximum):
        try:
            return _remaining_timeout(until, maximum)
        except SupervisorError:
            if proc.poll() is None:
                raise
            record_census_exit()
            return None

    def census_child_exited(*, keep_sample=False):
        if proc.poll() is None:
            return False
        if recovering and not missing_child_in_gap and not keep_sample:
            raise SupervisorError("child exited before Darwin census recovery")
        if not keep_sample:
            record_census_exit()
        return True

    def check_recovery(until, *, fresh_sample=False):
        expired = time.monotonic() >= until
        # An in-budget recovery sample goes through the guards before the exit check.
        if (expired or not fresh_sample) and census_child_exited():
            return False
        if expired:
            raise SupervisorError("Darwin census recovery deadline exhausted")
        return True

    try:
        snapshot = memory_call()
        if not isinstance(snapshot, dict):
            raise SupervisorError("memory sampler returned invalid record")
        physical = _positive_int(snapshot.get("physical_kib"), "physical_kib")
        available = _nonnegative_int(snapshot.get("available_kib"), "available_kib")
        if available > physical:
            raise SupervisorError("available memory exceeds physical memory")
        pressure = (pressure_probe() if pressure_probe else snapshot.get("pressure"))
        if pressure not in ("CLEAR", "PRESSURE"):
            raise SupervisorError("memory pressure is unknown or invalid")
        result["memory"] = snapshot | {"pressure": pressure}
        result["admission_memory"] = result["memory"]
        result["minimum_available_kib"] = available
        result["pressure"] = pressure
        if pressure != "CLEAR":
            result["stop_reason"] = "ADMISSION_MEMORY_PRESSURE"
            _event(timeline, "ADMISSION_REJECTED", reason=result["stop_reason"])
            return _finish(result)
        effective = min(nominal_kib, available - reserve_kib)
        if effective <= 0:
            result["stop_reason"] = "ADMISSION_RESERVE_UNAVAILABLE"
            _event(timeline, "ADMISSION_REJECTED", reason=result["stop_reason"])
            return _finish(result)
        result["effective_cap_kib"] = effective
        if time.monotonic() >= stop_at:
            result["stop_reason"] = "DEADLINE_BEFORE_START"
            _event(timeline, "ADMISSION_REJECTED", reason=result["stop_reason"])
            return _finish(result)
        stdout_path, stderr_path = directory / "stdout.log", directory / "stderr.log"
        child_started = last_rss_at = time.monotonic()
        proc = subprocess.Popen(list(argv), cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        result.update(status="RUNNING", pid=proc.pid, pgid=proc.pid)

        def drain(stream, path, key, cap):
            used = 0
            try:
                with path.open("wb") as output:
                    while True:
                        chunk = stream.read(65536)
                        if not chunk:
                            break
                        keep = max(0, min(len(chunk), cap - used))
                        if keep:
                            output.write(chunk[:keep])
                            used += keep
                        if keep < len(chunk):
                            capture[key + "_truncated"] = True
            except OSError as exc:
                capture[key + "_error"] = f"{type(exc).__name__}: {exc}"[:300]
            finally:
                capture[key + "_bytes"] = used
                stream.close()
        readers = [threading.Thread(target=drain, args=(proc.stdout, stdout_path, "stdout", stdout_cap_bytes), daemon=True),
                   threading.Thread(target=drain, args=(proc.stderr, stderr_path, "stderr", stderr_cap_bytes), daemon=True)]
        for reader in readers:
            reader.start()
        _event(timeline, "START", pid=proc.pid, pgid=proc.pid)
        # Preserve the requested cleanup window inside the absolute slot deadline.
        while True:
            now = time.monotonic()
            try:
                if now >= stop_at and not recovering:
                    if darwin and not sample_timestamps:
                        raise SupervisorError("stop deadline reached before first Darwin RSS sample")
                    result["stop_reason"] = "TIMEOUT"
                    break
                if darwin:
                    census_until = min(stop_at, last_rss_at + DARWIN_RSS_MAX_GAP)
                    if recovering and not check_recovery(census_until):
                        break
                    timeout = census_timeout(census_until, DARWIN_PS_TIMEOUT)
                    if timeout is None:
                        break
                else:
                    timeout = min(.5, max(.01, stop_at - time.monotonic()))
                result["samples_attempted"] += 1
                retry_error = None
                skipped_before = result["sample_pid_records_skipped"]
                try:
                    sample = (sampler(proc.pid, proc.pid) if sampler else
                              _default_sample(proc.pid, known, timeout=timeout, on_pid_skip=count_sample_pid_skip))
                except DarwinCensusTimeout:
                    if not darwin or sampler:
                        raise
                    census["ps_timeouts"] += 1
                    census["last_timeout"] = {"at": time.monotonic(), "timeout_seconds": timeout,
                                              "reason": "PS_CENSUS_TIMEOUT"}
                    _event(timeline, "PS_CENSUS_TIMEOUT", retry=recovering, timeout_seconds=timeout)
                    retry_error = "Darwin ps census retry timed out"
                else:
                    sampled_at = time.monotonic()
                    if (not isinstance(sample, dict) or type(sample.get("rss_kib")) is not int
                            or sample["rss_kib"] < 0 or not isinstance(sample.get("pids"), list)):
                        raise SupervisorError("RSS sampler returned invalid sample")
                    sample.setdefault("pid_records_skipped", result["sample_pid_records_skipped"] - skipped_before)
                    if darwin and not sampler and proc.pid not in sample["pids"]:
                        # A reaped child can leave live descendants in the snapshot.
                        keep_sample = bool(sample["pids"])
                        if not census_child_exited(keep_sample=keep_sample):
                            census["ps_missing_child"] += 1
                            _event(timeline, "PS_CENSUS_MISSING_CHILD", retry=recovering)
                            missing_child_in_gap = True
                            retry_error = "Darwin census retry did not observe the live direct child"
                        elif not keep_sample:
                            break
                if retry_error is not None:
                    if recovering:
                        if missing_child_in_gap and census_child_exited():
                            break
                        raise SupervisorError(retry_error)
                    recovering = True
                    result["sampler_valid"] = False
                    if not check_recovery(census_until):
                        break
                    memory_timeout = None
                    if not memory_probe:
                        memory_timeout = census_timeout(census_until, .5)
                        if memory_timeout is None:
                            break
                    live_snapshot, current_pressure = live_memory(memory_timeout)
                    if not check_recovery(census_until):
                        break
                    if stop_for_memory(live_snapshot, current_pressure == "PRESSURE"):
                        break
                    continue
                if darwin:
                    if recovering:
                        if not check_recovery(census_until, fresh_sample=True):
                            break
                    elif sampled_at >= last_rss_at + DARWIN_RSS_MAX_GAP:
                        raise SupervisorError("Darwin RSS observation budget exhausted")
                    elif sampled_at >= stop_at:
                        if not sample_timestamps:
                            raise SupervisorError("stop deadline reached before first Darwin RSS sample")
                        result["stop_reason"] = "TIMEOUT"
                        break
                records = sample.get("records", [])
                if not isinstance(records, list):
                    raise SupervisorError("RSS sampler returned invalid process records")
                for record in records:
                    if (not isinstance(record, dict) or type(record.get("pid")) is not int
                            or type(record.get("start_id")) not in (str, int)):
                        raise SupervisorError("RSS sampler returned process without stable identity")
                    known[record["pid"]] = record
                result["owned_process_count"] = len(known)
                count = sample.get("verifier_count", 0)
                if type(count) is not int or count < 0:
                    raise SupervisorError("invalid verifier process count")
                result["rss_peak_kib"] = max(result["rss_peak_kib"] or 0, sample["rss_kib"])
                result["peak_rss_kib"] = result["rss_peak_kib"]
                result["max_simultaneous_verifier_processes"] = max(
                    result["max_simultaneous_verifier_processes"], count)
                result["max_verifier_children"] = result["max_simultaneous_verifier_processes"]
                images = sample.get("images", [])
                if not isinstance(images, list) or any(not isinstance(x, str) for x in images):
                    raise SupervisorError("invalid process image list")
                result["observed_process_images"] = sorted(set(result["observed_process_images"]) | set(images))
                phase = sample.get("phase", "UNKNOWN")
                if not isinstance(phase, str):
                    raise SupervisorError("invalid observed phase")
                if phase != "UNKNOWN":
                    if phase != result["last_observed_phase"]:
                        _event(timeline, "PHASE", phase=phase)
                    result["last_observed_phase"] = phase
                    result["last_phase_monotonic"] = now
                verifier_pids = sample.get("verifier_pids")
                if verifier_pids is not None:
                    if (not isinstance(verifier_pids, list) or
                            any(type(pid) is not int or pid <= 0 for pid in verifier_pids)):
                        raise SupervisorError("invalid CBMC PID set")
                    verifier_pids = sorted(set(verifier_pids))
                    if verifier_pids != previous_cbmc:
                        transitions = result["cbmc_pid_transitions"]
                        if len(transitions) >= 64:
                            del transitions[0]
                            result["cbmc_pid_transitions_omitted"] += 1
                        transitions.append({"at": now, "pids": verifier_pids})
                        _event(timeline, "CBMC_CHILDREN", pids=verifier_pids)
                        previous_cbmc = verifier_pids
                elif count != previous_cbmc_count:
                    _event(timeline, "CBMC_COUNT", count=count, pids="UNKNOWN")
                previous_cbmc_count = count
                if darwin:
                    census["max_gap_seconds"] = max(census["max_gap_seconds"] or 0, sampled_at - last_rss_at)
                    last_rss_at = sampled_at
                    if recovering:
                        census["recoveries"] += 1
                        _event(timeline, "PS_CENSUS_RECOVERED")
                        recovering = False
                        missing_child_in_gap = False
                if diagnostics is not None and "diagnostic_error" not in result:
                    try:
                        diagnostics.observe(sample, sampled_at)
                    except Exception as exc:
                        result["diagnostic_error"] = f"{type(exc).__name__}: {exc}"[:300]
                live_snapshot, current_pressure = live_memory()
                result["sampler_valid"] = True
                result["samples_succeeded"] += 1
                sample_timestamps.append(sampled_at if darwin else now)
                pressure_confirmed = current_pressure == "PRESSURE"
                if "pressure_avg10" in live_snapshot:
                    if pressure_confirmed:
                        observed_at = time.monotonic()
                        if high_pressure_started is None:
                            high_pressure_started = observed_at
                        high_pressure_samples += 1
                        high_pressure_seconds = observed_at - high_pressure_started
                        pressure_confirmed = (high_pressure_samples >= LINUX_PRESSURE_MIN_SAMPLES
                                              and high_pressure_seconds >= LINUX_PRESSURE_MIN_SECONDS)
                        if pressure_confirmed:
                            result["memory"].update(pressure_high_samples=high_pressure_samples,
                                                    pressure_high_seconds=high_pressure_seconds)
                    else:
                        high_pressure_started = None
                        high_pressure_samples = 0
                if stop_for_memory(live_snapshot, pressure_confirmed):
                    break
                if sample["rss_kib"] > effective:
                    result["stop_reason"] = "RSS_LIMIT"
                    break
                result["stdout_bytes"] = capture["stdout_bytes"]
                result["stderr_bytes"] = capture["stderr_bytes"]
                if capture.get("stdout_error") or capture.get("stderr_error"):
                    result["stop_reason"] = "CAPTURE_ERROR"
                    break
            except Exception as exc:
                result["sampler_valid"] = False
                result["samples_missed"] += 1
                result["stop_reason"] = "SAMPLER_ERROR"
                result["sampler_error"] = f"{type(exc).__name__}: {str(exc)[:512]}"
                _event(timeline, "SAMPLER_ERROR", detail=result["sampler_error"])
                break
            rc = proc.poll()
            if rc is not None:
                result["exit_code"] = rc
                result["signal"] = -rc if rc < 0 else None
                result["stop_reason"] = "EXITED"
                break
            next_sample = min(now + sample_interval, stop_at)
            if darwin:
                next_sample = min(next_sample, last_rss_at + DARWIN_RSS_MAX_GAP)
            time.sleep(max(0, next_sample - time.monotonic()))
    except BaseException as exc:
        result["stop_reason"] = result["stop_reason"] or "SUPERVISOR_ERROR"
        result["supervisor_error"] = f"{type(exc).__name__}: {str(exc)[:512]}"
        if not isinstance(exc, Exception):
            pending_exception = exc
    finally:
        if proc is not None:
            observation_end = time.monotonic()
            result["monotonic_observation_end"] = observation_end
            if darwin:
                census["max_gap_seconds"] = max(census["max_gap_seconds"] or 0, observation_end - last_rss_at)
            reaped, remaining, errors, surviving = _shutdown(
                proc, known, timeline, deadline, term_grace, kill_grace, on_pid_skip=count_cleanup_pid_skip)
            result["reaped"], result["remaining_processes"], result["cleanup_errors"] = reaped, remaining, errors
            result["exit_code"] = proc.returncode
            result["signal"] = -proc.returncode if proc.returncode is not None and proc.returncode < 0 else None
            if not reaped or surviving and result["stop_reason"] == "EXITED":
                result["primary_stop_reason"] = result["stop_reason"]
                result["stop_reason"] = "SURVIVING_DESCENDANT" if reaped else "REAP_UNVERIFIED"
            for reader in readers:
                reader.join(timeout=max(0.0, deadline - time.monotonic()))
            drained = not any(reader.is_alive() for reader in readers)
            for stream in ("stdout", "stderr"):
                result[stream + "_bytes"] = capture[stream + "_bytes"]
                result[stream + "_truncated"] = capture[stream + "_truncated"]
                result[stream + "_capture_error"] = capture.get(stream + "_error")
                result[stream + "_drained"] = drained
                result[stream + "_complete"] = drained and not (capture[stream + "_truncated"] or capture.get(stream + "_error"))
            if diagnostics is not None:
                try:
                    diagnostics.finish(observation_end)
                except Exception as exc:
                    result.setdefault("diagnostic_error", f"{type(exc).__name__}: {exc}"[:300])
            _event(timeline, "REAP", reaped=reaped, remaining_count=len(remaining) if remaining is not None else None)
    if pending_exception is not None:
        raise pending_exception
    if darwin and proc is not None:
        # Count attempted and scheduled samples on the same scale. A lost ps
        # can already occupy a scheduled slot, so don't add the two counts.
        expected = max(result["samples_attempted"], math.ceil((observation_end - child_started) / sample_interval))
        success = result["samples_succeeded"]
        result["samples_expected"] = expected
        result["samples_missed"] = expected - success
        result["missed_sample_fraction"] = (expected - success) / expected if expected else None
        if success > 1:
            result["sampling_cadence_seconds"] = (sample_timestamps[-1] - sample_timestamps[0]) / (success - 1)
    elif sample_timestamps:
        span = sample_timestamps[-1] - sample_timestamps[0]
        expected = max(result["samples_attempted"], 1 + math.floor(span / sample_interval))
        success = result["samples_succeeded"]
        result["samples_expected"] = expected
        result["samples_missed"] = expected - success
        result["missed_sample_fraction"] = (expected - success) / expected
        result["sampling_cadence_seconds"] = span / (success - 1) if success > 1 else None
    elif result["samples_attempted"]:
        result["samples_expected"] = result["samples_attempted"]
        result["missed_sample_fraction"] = 1.0
    return _finish(result)


def _default_sample(pgid, known=None, *, timeout=.5, on_pid_skip=None):
    table = process_table(timeout=timeout, on_pid_skip=on_pid_skip)
    records = _owned_live(table, pgid, {} if known is None else known)
    rss = sum(row["rss"] for row in records)
    images = sorted({row.get("image", "UNKNOWN") for row in records})
    verifier_pids = sorted(row["pid"] for row in records
                           if row.get("image", "").lower() in ("cbmc", "cbmc.exe"))
    verifiers = len(verifier_pids)
    phase_names = ("rustc", "kani-compiler", "goto-instrument", "goto-cc", "cbmc")
    phase = next((name for name in reversed(phase_names)
                  if any(name in row.get("image", "").lower() for row in records)), "UNKNOWN")
    return {"rss_kib": rss, "pids": [row["pid"] for row in records],
            "verifier_count": verifiers, "verifier_pids": verifier_pids,
            "records": records, "images": images, "phase": phase}


def _finish(result):
    end = time.monotonic()
    result["monotonic_end"] = end
    result["wall_seconds"] = max(0.0, end - result["monotonic_start"])
    if result.get("status") == "RUNNING":
        result["status"] = "COMPLETED" if result.get("reaped") else "INCOMPLETE"
    if result.get("status") == "NOT_STARTED" and result.get("stop_reason") is None:
        result["stop_reason"] = "NOT_STARTED"
    result["timeline_omitted"] = getattr(result.get("timeline"), "omitted", 0)
    return result
