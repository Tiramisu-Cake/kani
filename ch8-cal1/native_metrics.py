# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Read bounded native prefixes with stream-local line and byte coordinates."""
from io import BytesIO
import re


CNF_LIMIT = 8  # First marker and up to seven subsequent markers per stream.
MARKER_LIMIT = 32
STAMP = re.compile(rb"^(?:\[(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\]|(\d{2}:\d{2}:\d{2}(?:\.\d+)?))[ \t]+")
CNF = re.compile(rb"([0-9]{1,20}) variables, ([0-9]{1,20}) clauses")
OBJECT_BITS = re.compile(rb"too many addressed objects\b", re.I)
HARNESS = re.compile(rb"Checking harness (.+)\.\.\.")
CBMC_COMMAND = b"[Kani] Running: `cbmc "
COMMAND_ARG = re.compile(rb'[^ \t\r"`]+|"[^"\r`]+"')
NUMBER = rb"([0-9]{1,16}(?:\.[0-9]{1,16})?(?:[eE][+-]?[0-9]{1,3})?)"
MARKERS = {
    "symex_start": (rb"Starting Bounded Model Checking", "SYMEX"),
    "symex_seconds": (rb"Runtime Symex: " + NUMBER + rb"s", "SYMEX"),
    "symex_steps": (rb"size of program expression: ([0-9]{1,20}) steps", "SYMEX"),
    "vcc": (rb"Generated ([0-9]{1,20}) VCC\(s\), ([0-9]{1,20}) remaining after simplification", "SYMEX"),
    "ssa_start": (rb"converting SSA.*", "SSA"),
    "ssa_seconds": (rb"Runtime Convert SSA: " + NUMBER + rb"s", "SSA"),
    "sat_start": (rb"(?:Solving with .+|Running (?:propositional reduction|.*CaDiCaL).*|"
                  rb"Passing problem to propositional reduction.*)", "SAT"),
    "sat_seconds": (rb"Runtime Solver: " + NUMBER + rb"s", "SAT"),
    "decision_seconds": (rb"Runtime decision procedure: " + NUMBER + rb"s", "SAT"),
    "cover_pass": (rb"(?:Covering goals|Starting (?:coverage|cover|reachability)|"
                   rb"Checking (?:cover|reachability)|Running (?:cover|reachability)).*", "COVER_OR_REACHABILITY"),
    "terminal": (rb"VERIFICATION:- (?:SUCCESSFUL|FAILED)(?: .*)?", "TERMINAL"),
    "verification_time": (rb"Verification Time: " + NUMBER + rb"s", "TERMINAL"),
}
MARKERS = {name: (re.compile(pattern, re.I if name == "cover_pass" else 0), phase)
           for name, (pattern, phase) in MARKERS.items()}


def _command_unwind(line):
    if not line.endswith(b"`") or len(line) > 4096:
        return None
    rendered = line[len(CBMC_COMMAND):-1]
    args = COMMAND_ARG.findall(rendered)
    # The stock renderer wraps args containing spaces in double quotes.
    if b" ".join(args) != rendered or b"--" in args:
        return None
    indices = [i for i, arg in enumerate(args) if arg == b"--unwind" or arg.startswith(b"--unwind=")]
    if len(indices) != 1:
        return None
    i = indices[0]
    if args[i] != b"--unwind" or i + 1 == len(args) or not re.fullmatch(rb"[0-9]{1,10}", args[i + 1]):
        return None
    unwind = int(args[i + 1])
    return unwind if unwind <= 2**32 - 1 else None


def sequential_cbmc_unwinds(stdout, selectors):
    """Bind a complete stock verbose command to its preceding exact selector."""
    expected = {selector.encode(): selector for selector in selectors}
    seen = set()
    observations = {}
    selected = None
    # A truncated final line cannot supply a command or select a harness.
    for number, raw in enumerate(BytesIO(stdout), 1):
        if not raw.endswith(b"\n"):
            break
        line = raw[:-1].removesuffix(b"\r")
        harness = HARNESS.fullmatch(line)
        if harness:
            selected = expected.get(harness[1])
            if selected is None or selected in seen:
                return {}
            seen.add(selected)
        elif line.startswith(CBMC_COMMAND):
            if selected is None:
                return {}
            unwind = None if selected in observations else _command_unwind(line)
            observations[selected] = (unwind, number)
    return {selector: {"resolved_unwind": unwind,
                       "resolved_unwind_source": {"kind": "NATIVE_CBMC_COMMAND", "stream": "stdout", "line": line}}
            for selector, (unwind, line) in observations.items() if unwind is not None}


def stream_metrics(data, name, capture_complete, *, truncated=False, error=None):
    phase, solve, scoped = "UNKNOWN", "UNATTRIBUTED", False
    cnf, markers, object_bits = [], [], None
    cnf_count, marker_count, oversized_lines = 0, 0, 0
    first_by_kind = {}
    last_terminal = None
    tail = data.rsplit(b"\n", 1)[-1]
    offset, line_number, complete_end = 0, 0, len(data) - len(tail)
    while offset < complete_end:
        end = data.index(b"\n", offset, complete_end)
        line_number += 1
        raw = data[offset:end].removesuffix(b"\r")
        origin = {"stream": name, "line": line_number, "byte_start": offset, "byte_end": offset + len(raw)}
        offset = end + 1
        if len(raw) > 4096:
            oversized_lines += 1
            continue
        text = raw.strip()
        stamp = STAMP.match(text)
        if stamp:
            origin["native_timestamp"] = (stamp[1] or stamp[2]).decode("ascii")
            text = text[stamp.end():]
        match = CNF.fullmatch(text)
        if match:
            cnf_count += 1
            if len(cnf) < CNF_LIMIT:
                cnf.append(origin | {"variables": int(match[1]), "clauses": int(match[2]),
                                     "phase": "SAT" if phase != "COVER_OR_REACHABILITY" else phase,
                                     "preceding_phase": phase, "solve_context": solve, "ordinal": cnf_count})
            if solve == "INITIAL_SOLVE":
                solve = "SUBSEQUENT_OR_UNATTRIBUTED"
            continue
        if object_bits is None and OBJECT_BITS.search(text):
            object_bits = origin | {"text": text[:400].decode("utf-8", errors="replace")}
        for kind, (pattern, new_phase) in MARKERS.items():
            match = pattern.fullmatch(text)
            if match is None:
                continue
            if kind == "cover_pass":
                solve = "COVER_OR_REACHABILITY"
            elif phase != "COVER_OR_REACHABILITY":
                if kind == "symex_start" and cnf_count == 0:
                    scoped = True
                if scoped and kind in {"ssa_start", "sat_start"} and cnf_count == 0:
                    solve = "INITIAL_SOLVE"
            if phase != "COVER_OR_REACHABILITY" or new_phase == "TERMINAL":
                phase = new_phase
            marker_count += 1
            marker = origin | {"kind": kind, "phase": phase, "text": text[:400].decode("utf-8", errors="replace")}
            if kind == "vcc":
                marker |= {"generated": int(match[1]), "after_simplification": int(match[2])}
            first_by_kind.setdefault(kind, marker)
            if kind == "terminal":
                last_terminal = marker
            if len(markers) < MARKER_LIMIT:
                markers.append(marker)
            break
    primary = next((item for item in cnf if item["solve_context"] == "INITIAL_SOLVE"), None)
    # A tail without LF never contributes an exact marker, even when capture reached EOF.
    incomplete_tail = ({"line": line_number + 1, "byte_start": complete_end, "bytes": len(tail)}
                       if tail else None)
    return {
        "capture_complete": capture_complete, "capture_truncated": truncated, "capture_error": error,
        "captured_bytes": len(data), "incomplete_tail": incomplete_tail, "oversized_lines_skipped": oversized_lines,
        "first_cnf": cnf[0] if cnf else None, "subsequent_cnf": cnf[1:],
        "cnf_omitted": cnf_count - len(cnf), "initial_solve_cnf": primary,
        "cnf_status": ("OBSERVED" if cnf else "UNOBSERVED_IN_PREFIX" if not capture_complete or tail
                       else "ABSENT_IN_COMPLETE_CAPTURE"),
        "markers": markers, "markers_omitted": marker_count - len(markers),
        "first_marker_by_kind": first_by_kind, "last_terminal": last_terminal, "addressed_objects": object_bits,
    }


def collect(captures, child):
    streams = {}
    for name, (data, read_complete, error) in captures.items():
        streams[name] = stream_metrics(
            data, name, read_complete and child.get(name + "_complete") is True,
            truncated=child.get(name + "_truncated", False) or bool(error and " exceeds " in error),
            error=child.get(name + "_capture_error") or error,
        )
    candidates = [record["initial_solve_cnf"] for record in streams.values() if record["initial_solve_cnf"]]
    return {
        "streams": streams, "cross_stream_order": None,
        "order_source": "Stream-local byte and line coordinates. Native timestamps are retained when emitted.",
        "initial_solve_cnf": candidates[0] if len(candidates) == 1 else None,
        "initial_solve_cnf_status": ("OBSERVED_IN_ONE_STREAM" if len(candidates) == 1 else
                                     "AMBIGUOUS_STREAMS" if candidates else "UNATTRIBUTED_OR_UNOBSERVED"),
    }
