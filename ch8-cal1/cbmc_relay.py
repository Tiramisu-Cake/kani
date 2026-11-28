# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Deferred stdout relay for one CBMC JSON-UI verification call.

The runner installs this file as ``cbmc`` first in PATH for one slot only. A
``--version`` call is replaced by the real binary. A ``--json-ui`` call starts
the real CBMC with the original argv tail, cwd, environment, stdin and stderr.
Its stdout goes in small blocks to a private spill file. After the real CBMC is
reaped, every spilled byte is replayed in order to the inherited stdout and the
original exit status is returned. The relay writes only bounded JSON journals.
"""
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import time

CONFIG_NAME = "cbmc-relay.json"
SCHEMA = "smallsort-cbmc-stdout-relay-v1"
EXIT_RELAY_FAILURE = 125
MAX_ARGS = 64
MAX_ARG_BYTES = 4096


class Cancelled(BaseException):
    """A termination signal reached the relay."""

    def __init__(self, signum):
        super().__init__(signum)
        self.signum = signum


class RelayFailure(Exception):
    def __init__(self, outcome, detail):
        super().__init__(detail)
        self.outcome = outcome


def monotonic():
    return time.monotonic()


def start_id(pid):
    """Read the procfs start time used by the supervisor as PID identity."""
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8") as stream:
            data = stream.read()
        fields = data[data.rfind(")") + 2:].split()
        return {"start_id": int(fields[19]), "pgid": int(fields[2]), "sid": int(fields[3])}
    except (OSError, IndexError, ValueError):
        return {"start_id": None, "pgid": None, "sid": None}


def peak_rss_kib():
    try:
        with open("/proc/self/status", encoding="utf-8") as stream:
            for line in stream:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1])
    except (OSError, IndexError, ValueError):
        pass
    return None


def original_environment(path="/proc/self/environ"):
    """Return the environment block received at exec, before any interpreter adjustment."""
    with open(path, "rb") as stream:
        block = stream.read()
    env = {}
    for item in block.split(b"\0"):
        if item:
            key, sep, value = item.partition(b"=")
            if sep and key:
                env[key] = value
    return env, hashlib.sha256(block).hexdigest()


def argv_digest(args):
    return hashlib.sha256(b"\0".join(os.fsencode(arg) for arg in args)).hexdigest()


def bounded_args(args):
    kept = [arg for arg in args[:MAX_ARGS] if len(os.fsencode(arg)) <= MAX_ARG_BYTES]
    return {"argv": kept, "argv_count": len(args), "argv_complete": len(kept) == len(args)}


class Journal:
    """Exclusive per-invocation journal, replaced atomically at each phase."""

    def __init__(self, directory, pid):
        self.path = Path(directory) / f"invocation-{pid}.json"
        self.record = {}
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        os.close(fd)

    def write(self, **fields):
        self.record.update(fields)
        temp = self.path.with_name(self.path.name + ".tmp")
        data = json.dumps(self.record, allow_nan=False, sort_keys=True).encode()
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            write_all(fd, data)
        finally:
            os.close(fd)
        os.replace(temp, self.path)


def write_all(fd, data, write=os.write):
    """Write every byte, retrying short writes. Return the number of calls."""
    view = memoryview(data)
    calls = 0
    while view:
        written = write(fd, view)
        calls += 1
        if written <= 0:
            raise OSError(errno.EIO, "write made no progress")
        view = view[written:]
    return calls


def load_config(script):
    path = Path(script).with_name(CONFIG_NAME)
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 65536:
        raise RelayFailure("CONFIG_INVALID", "relay config is not a private regular file")
    with open(path, encoding="utf-8") as stream:
        config = json.load(stream)
    if config.get("schema") != SCHEMA:
        raise RelayFailure("CONFIG_INVALID", "relay config schema mismatch")
    return config


def check_real(config):
    real = Path(config["real_cbmc"])
    info = os.stat(real)
    identity = [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns]
    if not real.is_absolute() or identity != config["real_cbmc_identity"]:
        raise RelayFailure("REAL_CBMC_CHANGED", "real CBMC path or file identity changed")
    return str(real)


TERMINATION_SIGNALS = ("SIGTERM", "SIGINT", "SIGHUP")


def ignore_termination():
    """A later group signal must not interrupt the relay's own stop and reap of the real CBMC."""
    for name in TERMINATION_SIGNALS:
        signal.signal(getattr(signal, name), signal.SIG_IGN)


def stop_child(proc, grace):
    """Terminate the real CBMC if it is alive and confirm its reap."""
    if proc.poll() is None:
        for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, None)):
            try:
                proc.send_signal(sig)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=wait)
                break
            except subprocess.TimeoutExpired:
                continue
    proc.wait()
    return proc.returncode


def relay(args, config, journal, env, *, stdout_fd=1, spawn=subprocess.Popen, spill_write=os.write,
          replay_write=os.write, clock=monotonic):
    """Run one JSON-UI call with deferred stdout. Return the exit status to mirror."""
    chunk = int(config["chunk_bytes"])
    cap = int(config["spill_cap_bytes"])
    reserve = int(config["disk_reserve_bytes"])
    spill_dir = Path(config["spill_dir"])
    real = check_real(config)
    usage = os.statvfs(spill_dir)
    free = usage.f_bavail * usage.f_frsize
    journal.write(spill_free_bytes_before=free)
    if free < cap + reserve:
        raise RelayFailure("SPILL_DISK_UNAVAILABLE", f"{free} bytes free, {cap + reserve} required")
    spill = spill_dir / f"spill-{os.getpid()}.bin"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    spill_fd = os.open(spill, flags, 0o600)
    journal.write(spill_path=str(spill), spill_mode=oct(stat.S_IMODE(os.fstat(spill_fd).st_mode)))
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    proc = None
    spilled = 0
    spilled_digest = hashlib.sha256()
    try:
        proc = spawn(["cbmc", *args], executable=real, stdout=write_fd, close_fds=True, env=env)
        os.close(write_fd)
        write_fd = None
        child = start_id(proc.pid)
        journal.write(phase="CBMC_RUNNING", cbmc_pid=proc.pid, cbmc_start_id=child["start_id"],
                      cbmc_pgid=child["pgid"], cbmc_sid=child["sid"], cbmc_start_monotonic=clock())
        while True:
            block = os.read(read_fd, chunk)
            if not block:
                break
            if spilled + len(block) > cap:
                journal.write(spill_limit_reached_monotonic=clock())
                raise RelayFailure("SPILL_LIMIT", f"CBMC stdout exceeded {cap} spill bytes")
            try:
                write_all(spill_fd, block, spill_write)
            except OSError as exc:
                raise RelayFailure("SPILL_WRITE_ERROR", f"{type(exc).__name__}: {exc}") from exc
            spilled += len(block)
            spilled_digest.update(block)
        status = proc.wait()
        journal.write(phase="WAIT_DONE", wait_done_monotonic=clock(), cbmc_returncode=status,
                      spill_bytes=spilled, spill_sha256=spilled_digest.hexdigest())
    except BaseException:
        if proc is not None:
            ignore_termination()
            returncode = stop_child(proc, float(config["term_grace_seconds"]))
            journal.write(cbmc_returncode=returncode, cbmc_reaped_monotonic=clock(),
                          spill_bytes=spilled, spill_sha256=spilled_digest.hexdigest())
        raise
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        os.close(spill_fd)
    # The real CBMC is reaped here. Only now does any byte reach the inherited stdout.
    replayed = 0
    replay_digest = hashlib.sha256()
    first = None
    journal.write(phase="REPLAYING", replay_start_monotonic=clock())
    source = os.open(spill, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        while True:
            block = os.read(source, chunk)
            if not block:
                break
            try:
                write_all(stdout_fd, block, replay_write)
            except OSError as exc:
                journal.write(replay_bytes=replayed, replay_sha256=replay_digest.hexdigest())
                raise RelayFailure("REPLAY_INCOMPLETE", f"{type(exc).__name__}: {exc}") from exc
            if first is None:
                first = clock()
                journal.write(replay_first_byte_monotonic=first)
            replayed += len(block)
            replay_digest.update(block)
    finally:
        os.close(source)
    end = clock()
    os.close(stdout_fd)
    complete = replayed == spilled and replay_digest.hexdigest() == spilled_digest.hexdigest()
    if not complete:
        journal.write(replay_bytes=replayed, replay_sha256=replay_digest.hexdigest(), replay_end_monotonic=end)
        raise RelayFailure("REPLAY_INCOMPLETE", "replayed bytes differ from spilled bytes")
    os.unlink(spill)
    journal.write(phase="REPLAY_DONE", replay_bytes=replayed, replay_sha256=replay_digest.hexdigest(),
                  replay_end_monotonic=end, spill_removed=True, replay_complete=True)
    return status


def mirror(status):
    """Leave with the real CBMC status: the same exit code or the same signal."""
    if status < 0:
        try:
            signal.signal(-status, signal.SIG_DFL)
            signal.pthread_sigmask(signal.SIG_UNBLOCK, [-status])
        except (OSError, ValueError):
            pass
        os.kill(os.getpid(), -status)
        os._exit(128 - status)
    os._exit(status)


def main(argv=None, environ=None):
    argv = sys.argv if argv is None else argv
    args = list(argv[1:])
    config = load_config(argv[0])
    journal = Journal(config["journal_dir"], os.getpid())
    own = start_id(os.getpid())
    env, env_digest = original_environment(environ or "/proc/self/environ")
    journal.write(schema=SCHEMA, relay_pid=os.getpid(), relay_start_id=own["start_id"], relay_pgid=own["pgid"],
                  relay_sid=own["sid"], relay_start_monotonic=monotonic(), argv_sha256=argv_digest(args),
                  environment_sha256=env_digest, environment_entries=len(env), cwd=os.getcwd(),
                  **bounded_args(args))
    if "--json-ui" not in args:
        real = check_real(config)
        mode = "VERSION_PASSTHROUGH" if args == ["--version"] else "OTHER_PASSTHROUGH"
        journal.write(mode=mode, phase="EXEC")
        os.execve(real, ["cbmc", *args], env)
    journal.write(mode="SPILL_THEN_REPLAY", phase="STARTED", outcome="RUNNING")

    def cancel(signum, _frame):
        ignore_termination()
        raise Cancelled(signum)

    for name in TERMINATION_SIGNALS:
        signal.signal(getattr(signal, name), cancel)
    try:
        status = relay(args, config, journal, env)
    except Cancelled as exc:
        journal.write(outcome="CANCELLED", signal=exc.signum, replay_complete=False, spill_removed=False,
                      relay_peak_rss_kib=peak_rss_kib(), relay_end_monotonic=monotonic())
        mirror(-exc.signum)
    except RelayFailure as exc:
        ignore_termination()
        journal.write(outcome=exc.outcome, error=str(exc)[:512], replay_complete=False,
                      relay_peak_rss_kib=peak_rss_kib(), relay_end_monotonic=monotonic())
        os._exit(EXIT_RELAY_FAILURE)
    except Exception as exc:
        ignore_termination()
        journal.write(outcome="RELAY_ERROR", error=f"{type(exc).__name__}: {exc}"[:512], replay_complete=False,
                      relay_peak_rss_kib=peak_rss_kib(), relay_end_monotonic=monotonic())
        os._exit(EXIT_RELAY_FAILURE)
    outcome = "COMPLETE" if status >= 0 else "CBMC_SIGNALED"
    journal.write(outcome=outcome, signal=-status if status < 0 else None,
                  relay_peak_rss_kib=peak_rss_kib(), relay_end_monotonic=monotonic())
    mirror(status)


if __name__ == "__main__":
    main()
