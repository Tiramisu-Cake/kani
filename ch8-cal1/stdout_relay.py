# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Install, observe and judge the deferred CBMC stdout relay for the single relay slot."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys

import native_metrics
import request as spec

JOURNAL_LIMIT = 8
JOURNAL_BYTES = 65536
COMMAND_LIMIT = 16 * 1024 * 1024
# One C-level scan over the bounded prefix. A string cut by the prefix end has no closing quote and never matches.
MESSAGE_KEY = b'"messageText":'
# Only native size and phase messages match. Ordinary messages such as "Unwinding loop ..." fail at their
# first byte, so they cost no budget and a CNF anywhere in the 16 MiB prefix is still found.
_TEXT = rb'[^"\\\n]'
NATIVE_MESSAGE = re.compile(
    rb'"messageText":[ \t]*"('
    rb'[0-9]{1,20} variables, [0-9]{1,20} clauses'
    rb'|Starting Bounded Model Checking'
    rb'|Runtime (?:Symex|Convert SSA|Solver|decision procedure): [0-9][0-9.eE+-]{0,40}s'
    rb'|size of program expression: [0-9]{1,20} steps'
    rb'|Generated [0-9]{1,20} VCC\(s\), [0-9]{1,20} remaining after simplification'
    rb'|converting SSA' + _TEXT + rb'{0,400}'
    rb'|Solving with ' + _TEXT + rb'{1,400}'
    rb'|Running (?:propositional reduction|cover|reachability|' + _TEXT + rb'{0,200}CaDiCaL)' + _TEXT + rb'{0,200}'
    rb'|Passing problem to propositional reduction' + _TEXT + rb'{0,200}'
    rb'|(?:Covering goals|Starting (?:coverage|cover|reachability)|Checking (?:cover|reachability))'
    + _TEXT + rb'{0,400}'
    rb'|VERIFICATION:- (?:SUCCESSFUL|FAILED)' + _TEXT + rb'{0,200}'
    rb')"')
MARKER_SCAN_LIMIT = 4096
PHASE_ORDER = ("STARTED", "CBMC_RUNNING", "WAIT_DONE", "REPLAYING", "REPLAY_DONE")


class RelayError(RuntimeError):
    pass


def require(condition, reason):
    if not condition:
        raise RelayError(reason)


def file_sha256(path):
    with Path(path).open("rb") as source:
        return spec.digest(source)


def resolve_real(setup_tool, base_path):
    """Bind the CBMC that PATH resolves before substitution to the attested binary."""
    record = (setup_tool or {}).get("binaries", {}).get("cbmc") or {}
    found = shutil.which("cbmc", path=base_path)
    require(found is not None, "real CBMC is not on the stock PATH")
    resolved = Path(found).resolve(strict=True)
    require(str(resolved) == record.get("path"), "stock PATH CBMC differs from the attested path")
    info = resolved.stat()
    digest = file_sha256(resolved)
    require(digest == record.get("sha256") and info.st_size == record.get("bytes"),
            "stock PATH CBMC differs from the attested SHA-256")
    require(spec.CBMC_VERSION in (record.get("version") or "").split("\n", 1)[0],
            "attested CBMC is not the pinned release")
    return {"path": str(resolved), "sha256": digest, "bytes": info.st_size,
            "identity": [info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns],
            "attested_version_first_line": (record.get("version") or "").split("\n", 1)[0]}


MEMORY_FILESYSTEMS = frozenset(("tmpfs", "ramfs"))


def filesystem_type(path, mounts="/proc/self/mounts"):
    """Return the type of the longest mount point that contains `path`."""
    target = str(Path(path).resolve(strict=True))
    best, kind = "", None
    with open(mounts, encoding="utf-8") as stream:
        for line in stream:
            fields = line.split()
            if len(fields) < 3:
                continue
            point = re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[1])
            inside = target == point or target.startswith(point.rstrip("/") + "/")
            if inside and len(point) >= len(best):
                best, kind = point, fields[2]
    require(kind is not None, "spill directory has no mount record")
    return kind


def free_bytes(path):
    usage = os.statvfs(path)
    return usage.f_bavail * usage.f_frsize


def install(directory, real, *, interpreter=None, config=spec.STDOUT_RELAY):
    """Write the slot-private relay as `cbmc` and return its PATH prefix and receipt."""
    interpreter = str(Path(interpreter or sys.executable).resolve(strict=True))
    source = spec.HERE / "cbmc_relay.py"
    body = source.read_bytes()
    require(hashlib.sha256(body).hexdigest() == config["source_sha256"], "relay source differs from the frozen hash")
    root = Path(directory) / "relay"
    bin_dir, spill_dir, journal_dir = root / "bin", root / "spill", root / "journal"
    for path in (root, bin_dir, spill_dir, journal_dir):
        path.mkdir(mode=0o700)
    kind = filesystem_type(spill_dir)
    require(kind not in MEMORY_FILESYSTEMS, f"spill directory is on memory-backed {kind}")
    free = free_bytes(spill_dir)
    required = config["spill_cap_bytes"] + config["disk_reserve_bytes"]
    require(free >= required, f"spill disk has {free} bytes, {required} required")
    script = bin_dir / "cbmc"
    content = f"#!{interpreter} -I\n".encode() + body
    fd = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, "wb") as stream:
        stream.write(content)
    settings = {"schema": config["schema"], "real_cbmc": real["path"], "real_cbmc_identity": real["identity"],
                "spill_dir": str(spill_dir), "journal_dir": str(journal_dir), "chunk_bytes": config["chunk_bytes"],
                "spill_cap_bytes": config["spill_cap_bytes"], "disk_reserve_bytes": config["disk_reserve_bytes"],
                "term_grace_seconds": config["term_grace_seconds"]}
    fd = os.open(bin_dir / "cbmc-relay.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(settings, stream, sort_keys=True)
    return {"path_prefix": str(bin_dir), "journal_dir": str(journal_dir), "spill_dir": str(spill_dir),
            "receipt": {"mode": config["mode"], "slot": config["slot"], "source_sha256": config["source_sha256"],
                        "installed_sha256": hashlib.sha256(content).hexdigest(), "interpreter": interpreter,
                        "interpreter_sha256": file_sha256(interpreter), "path_prefix": str(bin_dir),
                        "real_cbmc": real, "spill_filesystem": kind, "spill_free_bytes_before": free, "spill_required_bytes": required,
                        "chunk_bytes": config["chunk_bytes"], "spill_cap_bytes": config["spill_cap_bytes"]}}


def read_journals(journal_dir):
    """Read at most a few bounded invocation journals, ignoring nothing silently."""
    names = sorted(os.listdir(journal_dir))
    records, problems = [], []
    for name in names:
        if name.endswith(".tmp"):
            problems.append(f"partial journal {name}")
            continue
        if len(records) >= JOURNAL_LIMIT:
            problems.append("journal count limit reached")
            break
        path = Path(journal_dir) / name
        info = os.lstat(path)
        if not re.fullmatch(r"invocation-[0-9]+\.json", name) or not path.is_file() or path.is_symlink() \
                or info.st_size > JOURNAL_BYTES:
            problems.append(f"unexpected journal member {name}")
            continue
        try:
            records.append(json.loads(path.read_text(encoding="utf-8")))
        except (OSError, ValueError) as exc:
            problems.append(f"unreadable journal {name}: {type(exc).__name__}")
    return records, problems, len(names)


def phase_probe(journal_dir):
    """Return the current phase of the one relay-mode invocation, for the RSS census."""
    def probe():
        phase = None
        for name in os.listdir(journal_dir):
            if not name.endswith(".json"):
                continue
            path = Path(journal_dir) / name
            if path.stat().st_size > JOURNAL_BYTES:
                continue
            record = json.loads(path.read_text(encoding="utf-8"))
            if record.get("mode") == "SPILL_THEN_REPLAY":
                phase = record.get("phase")
        return phase or "NO_RELAY_CALL"
    return probe


def kani_command(stdout_path):
    """Parse the stock verbose `[Kani] Running: `cbmc ...`` line, if exactly one exists."""
    try:
        with Path(stdout_path).open("rb") as stream:
            data = stream.read(COMMAND_LIMIT + 1)
    except OSError:
        return None, "stdout unreadable"
    lines = [line.removesuffix(b"\r") for line in data[:COMMAND_LIMIT].split(b"\n")
             if line.startswith(native_metrics.CBMC_COMMAND)]
    if len(lines) != 1:
        return None, f"{len(lines)} verbose CBMC command lines"
    line = lines[0]
    if not line.endswith(b"`") or len(line) > 65536:
        return None, "verbose CBMC command is truncated"
    rendered = line[len(b"[Kani] Running: `"):-1]
    tokens = native_metrics.COMMAND_ARG.findall(rendered)
    if b" ".join(tokens) != rendered:
        return None, "verbose CBMC command has an unsupported rendering"
    return [token.strip(b'"').decode("utf-8", errors="strict") for token in tokens], None


def profile_mismatch(argv, directory, template):
    """Compare the CBMC argv tail with the frozen stock profile; only the goto path varies."""
    if len(argv) != len(template):
        return f"CBMC argv has {len(argv)} entries, profile has {len(template)}"
    for observed, expected in zip(argv, template):
        if expected == "{goto}":
            path = Path(observed)
            inside = path.is_absolute() and ".." not in path.parts and str(path).startswith(str(directory) + "/")
            if not inside or not observed.endswith(".out"):
                return "CBMC goto binary is outside the slot directory"
        elif observed != expected:
            return f"CBMC argv differs at {expected!r}"
    return None


def spill_prefix_markers(spill, limit):
    """Recover native CBMC size and phase markers from a bounded JSON-UI prefix after reap, in bounded time."""
    size = spill.stat().st_size
    with spill.open("rb") as stream:
        data = stream.read(limit)
    # A string cut by the prefix end has no closing quote and never matches.
    lines = []
    limit_reached = False
    for match in NATIVE_MESSAGE.finditer(data):
        if len(lines) >= MARKER_SCAN_LIMIT:
            limit_reached = True
            break
        lines.append(match[1])
    text = b"".join(line + b"\n" for line in lines)
    metrics = native_metrics.stream_metrics(text, "relay_spill_prefix", size <= limit and not limit_reached)
    keep = {key: metrics[key] for key in ("first_cnf", "subsequent_cnf", "cnf_status", "cnf_omitted",
                                          "markers", "markers_omitted", "last_terminal")}
    return keep | {"spill_bytes": size, "prefix_bytes_read": len(data), "prefix_complete": size <= limit,
                   "messages": data.count(MESSAGE_KEY), "native_messages": len(lines),
                   "marker_scan_limit": MARKER_SCAN_LIMIT, "marker_scan_limit_reached": limit_reached,
                   "native_marker_found": bool(metrics["first_cnf"] or metrics["markers"])}


def prefix_reason(prefixes):
    """Explain a missing first CNF without hiding a scan bound behind a generic reason."""
    if any(item["first_cnf"] for item in prefixes.values()):
        return None
    if any(item["marker_scan_limit_reached"] for item in prefixes.values()):
        return "CNF_NOT_FOUND_BEFORE_MARKER_SCAN_LIMIT"
    if not any(item["native_marker_found"] for item in prefixes.values()):
        return "NO_RECOGNIZED_NATIVE_MARKER_IN_PREFIX"
    return "NO_CNF_IN_PREFIX"


def drain_spill(relay_state, config=spec.STDOUT_RELAY):
    """After a confirmed reap, read each leftover spill prefix and remove the spill."""
    spill_dir = Path(relay_state["spill_dir"])
    leftovers = sorted(os.listdir(spill_dir)) if spill_dir.is_dir() else []
    prefixes = {}
    result = {"spill_prefix": None}
    for name in leftovers:
        path = spill_dir / name
        if len(prefixes) < JOURNAL_LIMIT and not path.is_symlink() and path.is_file():
            prefixes[name] = spill_prefix_markers(path, config["spill_prefix_read_bytes"])
        path.unlink()
    if leftovers:
        result["spill_prefix"] = prefixes
        reason = prefix_reason(prefixes)
        if reason:
            result["spill_prefix_reason"] = reason
    result["spill_removed_after_reap"] = not os.listdir(spill_dir)
    return result


def remove_spill(relay_state):
    """Remove spill left by a prefix read that ran out of its window. Called only after a confirmed reap."""
    spill_dir = Path(relay_state["spill_dir"])
    for name in os.listdir(spill_dir) if spill_dir.is_dir() else ():
        (spill_dir / name).unlink()


def collect(relay_state, directory, child, *, config=spec.STDOUT_RELAY):
    """Judge relay delivery after the supervisor finished. Never upgrades a verdict."""
    journal_dir, spill_dir = Path(relay_state["journal_dir"]), Path(relay_state["spill_dir"])
    reasons = []
    result = {"status": "INCOMPLETE", "reasons": reasons}
    try:
        journals, problems, members = read_journals(journal_dir)
    except OSError as exc:
        journals, problems, members = [], [f"journal directory unreadable: {type(exc).__name__}"], 0
    reasons.extend(problems)
    result["journal_members"] = members
    calls = [record for record in journals if record.get("mode") == "SPILL_THEN_REPLAY"]
    others = [record for record in journals if record.get("mode") != "SPILL_THEN_REPLAY"]
    result["passthrough_calls"] = [{key: record.get(key) for key in ("mode", "argv", "relay_pid")} for record in others]
    if any(record.get("mode") != "VERSION_PASSTHROUGH" or record.get("argv") != ["--version"] for record in others):
        reasons.append("relay saw a non-version passthrough call")
    if len(calls) != 1:
        reasons.append(f"{len(calls)} JSON-UI relay calls")
    call = calls[0] if len(calls) == 1 else {}
    fields = ("outcome", "phase", "error", "signal", "relay_pid", "relay_start_id", "relay_pgid", "relay_sid",
              "cbmc_pid", "cbmc_start_id", "cbmc_pgid", "cbmc_sid", "cbmc_returncode", "argv", "argv_count",
              "argv_complete", "argv_sha256", "environment_sha256", "environment_entries", "cwd",
              "spill_free_bytes_before", "spill_mode", "spill_bytes", "spill_sha256", "replay_bytes",
              "replay_sha256", "replay_complete", "spill_removed", "relay_start_monotonic",
              "cbmc_start_monotonic", "wait_done_monotonic", "replay_start_monotonic",
              "replay_first_byte_monotonic", "replay_end_monotonic", "relay_end_monotonic",
              "relay_peak_rss_kib", "spill_limit_reached_monotonic", "cbmc_reaped_monotonic")
    result["call"] = {key: call.get(key) for key in fields}
    if call:
        argv = call.get("argv") or []
        if call.get("outcome") != "COMPLETE" or call.get("replay_complete") is not True:
            reasons.append(f"relay outcome {call.get('outcome')}")
        if call.get("argv_complete") is not True or call.get("argv_sha256") != hashlib.sha256(
                b"\0".join(os.fsencode(arg) for arg in argv)).hexdigest():
            reasons.append("relay argv record is incomplete or its hash differs")
        mismatch = profile_mismatch(argv, directory, config["expected_cbmc_argv"])
        if mismatch:
            reasons.append(mismatch)
        command, problem = kani_command(Path(directory) / "stdout.log")
        result["kani_command_matches"] = command == ["cbmc", *argv] if command else False
        if not result["kani_command_matches"]:
            reasons.append(problem or "relay argv differs from the Kani verbose CBMC command")
        if call.get("cwd") != str(directory):
            reasons.append("relay cwd differs from the slot directory")
        pgid = child.get("pgid")
        if not (pgid and call.get("relay_pgid") == call.get("cbmc_pgid") == pgid
                and call.get("relay_sid") == call.get("cbmc_sid") == pgid):
            reasons.append("relay or CBMC left the supervised session or process group")
        if (call.get("spill_bytes") != call.get("replay_bytes") or not call.get("spill_sha256")
                or call.get("spill_sha256") != call.get("replay_sha256")):
            reasons.append("replayed bytes or SHA-256 differ from the spilled stdout")
        if type(call.get("cbmc_returncode")) is not int or call["cbmc_returncode"] < 0:
            reasons.append("real CBMC did not exit normally")
        if type(call.get("spill_bytes")) is int and call["spill_bytes"] > config["spill_cap_bytes"]:
            reasons.append("spill exceeded its cap")
        marks = [call.get(key) for key in ("relay_start_monotonic", "cbmc_start_monotonic", "wait_done_monotonic",
                                           "replay_start_monotonic", "replay_first_byte_monotonic",
                                           "replay_end_monotonic", "relay_end_monotonic")]
        if call.get("spill_bytes") == 0:
            marks[4] = marks[3]
        start, end = child.get("monotonic_start"), child.get("monotonic_observation_end")
        ordered = (all(type(mark) in (int, float) for mark in marks) and type(start) in (int, float)
                   and type(end) in (int, float) and start <= marks[0]
                   and all(a <= b for a, b in zip(marks, marks[1:])) and marks[2] < marks[4] and marks[-1] <= end)
        if not ordered:
            reasons.append("relay phase marks are missing or out of order")
        transitions = child.get("cbmc_pid_transitions") or []
        seen = {pid for item in transitions for pid in item.get("pids", ())}
        if call.get("relay_pid") in seen:
            reasons.append("the relay was counted as a real CBMC process")
        if call.get("cbmc_pid") not in seen:
            reasons.append("the real CBMC PID was not observed by the census")
        result["real_cbmc_observed_by_census"] = call.get("cbmc_pid") in seen
        result["relay_counted_as_cbmc"] = call.get("relay_pid") in seen
    # Judgement only. The spill prefix is read later by drain_spill, outside the projection window.
    leftovers = sorted(os.listdir(spill_dir)) if spill_dir.is_dir() else []
    result["spill_members_after_child"] = len(leftovers)
    if child.get("reaped") is True:
        if leftovers:
            reasons.append("spill was not removed by a complete replay")
    elif leftovers:
        result["spill_prefix_reason"] = "REAP_UNCONFIRMED_SPILL_KEPT"
        reasons.append("spill left with unconfirmed reap")
    if not reasons:
        result["status"] = "COMPLETE"
    elif not leftovers:
        result["spill_prefix_reason"] = "NO_SPILL_LEFT_AFTER_CHILD"
    return result
