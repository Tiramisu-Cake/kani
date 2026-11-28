# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Local native CAL1 checks. Run this script outside unittest discovery."""
import argparse
import json
import mmap
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

import supervisor


DURATION = 182
LEAVES_PER_WORKER = 320
HOLDER_KIB = 24 * 1024
RSS_STOP_KIB = 48 * 1024
RESERVE_KIB = 64 * 1024
SCRIPT = str(Path(__file__).resolve())


def hold_memory(size_kib, seconds):
    size = size_kib * 1024
    with mmap.mmap(-1, size) as memory:
        for offset in range(0, size, mmap.PAGESIZE):
            memory[offset] = 1
        if sys.platform == "linux":
            rss = supervisor.parse_linux_status_rss(Path("/proc/self/status").read_text())
        else:
            output = subprocess.check_output(["ps", "-o", "rss=", "-p", str(os.getpid())], text=True)
            rss = supervisor.parse_darwin_ps_rss(output)
        print(json.dumps({"touched_kib": size_kib, "holder_rss_kib": rss}), flush=True)
        time.sleep(seconds)


def wait_ok(pid):
    _, status = os.waitpid(pid, 0)
    if status != 0:
        raise RuntimeError(f"child {pid} failed with wait status {status}")


def churn():
    start = time.monotonic()
    holder = os.fork()
    if holder == 0:
        hold_memory(HOLDER_KIB, 4)
        os._exit(0)
    workers = []
    for worker in range(2):
        pid = os.fork()
        if pid == 0:
            for leaf in range(LEAVES_PER_WORKER):
                target = start + (leaf + worker * .5) * DURATION / LEAVES_PER_WORKER
                time.sleep(max(0, target - time.monotonic()))
                if (pid := os.fork()) == 0:
                    time.sleep(.015 + (leaf % 9) * .005)
                    os._exit(0)
                wait_ok(pid)
            print(json.dumps({"worker": worker, "leaves_reaped": LEAVES_PER_WORKER}), flush=True)
            os._exit(0)
        workers.append(pid)
    for pid in workers:
        wait_ok(pid)
    wait_ok(holder)
    time.sleep(max(0, start + DURATION - time.monotonic()))
    print(json.dumps({"descendants_created": len(workers) * (1 + LEAVES_PER_WORKER) + 1}), flush=True)


def measure(directory, scenario, cap_kib, timeout):
    result = supervisor.run([sys.executable, "-B", SCRIPT, "--workload", scenario],
                            cwd=directory, env=os.environ.copy(), directory=directory,
                            deadline=time.monotonic() + timeout, nominal_kib=cap_kib,
                            reserve_kib=RESERVE_KIB, term_grace=.5, kill_grace=.5)
    print(json.dumps(result, sort_keys=True), flush=True)
    assert result["sampler_valid"] and result["samples_succeeded"] > 0, result
    assert result["reaped"] and result["remaining_processes"] == [] and not result["cleanup_errors"], result
    assert result["effective_cap_kib"] == cap_kib and result["minimum_available_kib"] >= RESERVE_KIB, result
    return result


def check_churn(directory):
    result = measure(directory, "churn", 160 * 1024, DURATION + 12)
    assert result["stop_reason"] == "EXITED" and result["exit_code"] == 0, result
    rows = [json.loads(line) for line in (directory / "stdout.log").read_text().splitlines()]
    print(json.dumps(rows, sort_keys=True), flush=True)
    holder = next(row for row in rows if "touched_kib" in row)
    counts = [row for row in rows if "leaves_reaped" in row]
    total = sum(row["leaves_reaped"] for row in counts) + len(counts) + 1
    assert {row["worker"] for row in counts} == {0, 1}, rows
    assert total >= 603 and {"descendants_created": total} in rows, rows
    assert result["wall_seconds"] >= 180 and result["samples_succeeded"] > 10, result
    assert max(HOLDER_KIB, holder["holder_rss_kib"]) <= result["rss_peak_kib"] < result["effective_cap_kib"], result


def check_rss_stop(directory):
    result = measure(directory, "rss-stop", 24 * 1024, 10)
    assert result["rss_peak_kib"] > result["effective_cap_kib"], result
    assert result["stop_reason"] == "RSS_LIMIT" and result["signal"] == signal.SIGTERM, result


def check_pid_race(directory):
    from unittest.mock import patch

    assert sys.platform == "linux"
    original = Path.iterdir
    triggered = False
    with subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(10)"]) as victim:
        def iterdir(path):
            nonlocal triggered
            entries = list(original(path))
            if path == Path("/proc") and not triggered:
                assert path / str(victim.pid) in entries, entries
                victim.terminate()
                victim.wait(timeout=2)
                assert not (path / str(victim.pid)).exists()
                triggered = True
            return iter(entries)

        try:
            with patch.object(Path, "iterdir", iterdir):
                result = measure(directory, "pid-race", 96 * 1024, 5)
            assert triggered and result["sample_pid_records_skipped"] >= 1, result
            assert result["stop_reason"] == "EXITED" and result["exit_code"] == 0, result
        finally:
            if victim.poll() is None:
                victim.kill()


def main():
    checks = {"churn": check_churn, "rss-stop": check_rss_stop, "pid-race": check_pid_race}
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=checks)
    parser.add_argument("--workload", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.workload:
        workloads = {"churn": churn, "rss-stop": lambda: hold_memory(RSS_STOP_KIB, 6),
                     "pid-race": lambda: time.sleep(.35)}
        workloads[args.scenario]()
    else:
        with tempfile.TemporaryDirectory(prefix="cal1-stress-") as directory:
            checks[args.scenario](Path(directory))


if __name__ == "__main__":
    main()
