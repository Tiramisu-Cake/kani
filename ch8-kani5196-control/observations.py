# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT

"""Record selected native messages, evidence joins, and narrowly scoped blockers."""
from collections import Counter
from pathlib import Path
import re

UNINIT = re.compile(r"Undefined Behavior: Reading from an uninitialized pointer of type `(.+)`")
NUMBER = r"(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)"
MARKERS = {
    "symex_start": r"Starting Bounded Model Checking",
    "symex_seconds": rf"Runtime Symex: {NUMBER}s",
    "symex_steps": r"size of program expression: (\d+) steps",
    "vccs": r"Generated (\d+) VCC\(s\), (\d+) remaining after simplification",
    "ssa_start": r"converting SSA",
    "ssa_seconds": rf"Runtime Convert SSA: {NUMBER}s",
    "first_cnf": r"(\d+) variables, (\d+) clauses",
    "verification_seconds": rf"Verification Time: {NUMBER}s",
    "compile_seconds": rf"\s*Finished .+ profile .+ in {NUMBER}s",
    "harness_terminal": r"VERIFICATION:- (SUCCESSFUL|FAILED)(?: .*)?",
    "run_terminal": r"Complete - (\d+) successfully verified harnesses?, (\d+) failures?, (\d+) total\.",
    "harness_marker": r"Checking harness (.+)\.\.\.",
    "cargo_build": r"\[Kani\] Running: `.{0,4000}\bcargo\b.+\bbuild-std=panic_abort,core,std\b.*`",
    "backend_command": r"\[Kani\] Running: `(?:.*[ /])?cbmc[ \"].*--json-ui.*`",
    "compiler_command": r"\[Kani\] Running: `.*kani-compiler.*`",
}
COMPILED_MARKERS = {name: re.compile(pattern) for name, pattern in MARKERS.items()}
CONFIRMED_COMPILER_CODES = {"E0046", "E0432", "E0433", "E0463", "E0557", "E0635",
                            "E0658", "E0718", "E0773", "E0789"}


def lines(data, capture, stream, edge_bytes=None):
    """Yield complete lines at their source coordinates, even with a missing middle."""
    if data is None:
        return
    cap = capture["cap_bytes"]
    reported = capture["observed_bytes"]
    if capture["truncated"] and reported is not None and reported > len(data):
        segments = ((0, 1, data[:cap // 2], True, False),
                    (reported - len(data[cap // 2:]), None, data[cap // 2:], False, True))
    elif capture["truncated"] is None and len(data) > cap // 2:
        # Without the original byte count the positional meaning of the tail is unknown.
        segments = ((0, 1, data[:cap // 2], True, False),)
    else:
        segments = ((0, 1, data, True, capture["truncated"] is False),)
    if edge_bytes:
        limited = []
        for offset, number, chunk, left_exact, right_exact in segments:
            if len(chunk) <= 2 * edge_bytes:
                limited.append((offset, number, chunk, left_exact, right_exact))
            else:
                limited.append((offset, number, chunk[:edge_bytes], left_exact, False))
                limited.append((offset + len(chunk) - edge_bytes, None, chunk[-edge_bytes:], False, right_exact))
        segments = limited
    for offset, number, chunk, left_exact, right_exact in segments:
        if not left_exact:
            start = chunk.find(b"\n") + 1
            if not start:
                continue
            offset += start
            chunk = chunk[start:]
        if not right_exact:
            chunk = chunk[:chunk.rfind(b"\n") + 1]
        for raw in re.findall(rb"[^\n]*\n|[^\n]+$", chunk):
            line = raw.removesuffix(b"\n").removesuffix(b"\r")
            here = {"stream": stream, "byte_start": offset, "byte_end": offset + len(line), "line": number}
            offset += len(raw)
            if number is not None:
                number += 1
            yield line.decode("utf-8", errors="backslashreplace"), here


def native(captures, edge_bytes=None):
    found = {name: {"state": "INCOMPLETE", "reason": "NATIVE_MARKER_UNOBSERVED"} for name in MARKERS}
    diagnostics = []
    for stream in ("stdout", "stderr"):
        pending = None
        for text, coordinate in lines(*captures[stream], stream, edge_bytes):
            if len(text) > 4096:
                continue
            item = {"text": text, "source_coordinate": coordinate}
            for name, pattern in COMPILED_MARKERS.items():
                match = pattern.fullmatch(text)
                if match and found[name]["state"] != "OBSERVED":
                    found[name] = {"state": "OBSERVED", **item, "native_values": list(match.groups())}
            code = re.match(r"^error(?:\[(E\d+)\])?: (.+)", text, re.IGNORECASE)
            launch = re.match(r"^(error: Could not find kani-driver binary\.|error: (?:Failed to invoke (?:cargo|.*kani-compiler)|Failed to run cbmc))",
                              text, re.IGNORECASE)
            flag = re.match(r"^error: (unexpected argument|invalid value|unrecognized option)", text)
            cargo = re.match(r"^(?:error: )?(?:Failed to execute cargo \(.+\)\. Found [1-9][0-9]* compilation errors\.|could not compile `(?:core|std|alloc|compiler_builtins|panic_abort)` .+)",
                             text, re.IGNORECASE)
            if code or launch or flag or cargo:
                # Prefer specific matches over the generic Rust diagnostic header.
                kind = "launch" if launch else "flag" if flag else "cargo_failure" if cargo else "compiler"
                pending = {"kind": kind, "code": code.group(1) if code else None, **item}
                if len(diagnostics) < 12:
                    diagnostics.append(pending)
                elif kind in ("launch", "flag", "cargo_failure") and not any(d["kind"] == kind for d in diagnostics):
                    diagnostics.append(pending)
            elif pending and re.match(r"^\s*-->\s+.+:\d+:\d+$", text):
                pending["location"] = item
                pending = None
    return {"state": "OBSERVED" if any(v["state"] == "OBSERVED" for v in found.values()) or diagnostics
            else "INCOMPLETE", "markers": found, "diagnostics": diagnostics}


def blocker(root, evidence, child, std):
    """A nonzero status alone cannot confirm a shared compile or launch fault."""
    if (child.get("original_exit_code") in (None, 0) or child.get("signal")
            or child.get("termination_reason") or evidence["markers"]["harness_marker"]["state"] == "OBSERVED"):
        return None
    notes = evidence["diagnostics"]
    if any(note["kind"] == "launch" for note in notes):
        return {"scope": "all", "reason": "SHARED_TOOL_LAUNCH_FAILURE",
                "diagnostic": next(note for note in notes if note["kind"] == "launch")}
    # Attribute CLI rejection only when it names a flag shared across both entry points.
    flags = ("'--harness'", "'--exact'", "'--jobs'", "'--harness-timeout'", "'--output-format'",
             "'--verbose'", "'--export-json'", "'export-json'", "'unstable-options'")
    for note in notes:
        if note["kind"] == "flag" and any(flag in note["text"] for flag in flags):
            return {"scope": "all", "reason": "SHARED_FLAG_FAILURE", "diagnostic": note}
    if not std or root["uninit"] or not any(note["kind"] == "cargo_failure" for note in notes):
        return None
    # The OFF invocation builds the same library tree for every selector, before
    # Kani chooses the harness. Require a deterministic compiler error at that tree.
    for note in notes:
        location = note.get("location", {}).get("text", "").strip().removeprefix("--> ")
        parts = location.rsplit(":", 2)
        if len(parts) != 3:
            continue
        path = Path(parts[0])
        if not path.is_absolute() and path.parts[:1] == ("library",):
            path = std / path
        if (path.is_absolute() and path.resolve().is_relative_to(std / "library") and path.is_file()
                and note["code"] in CONFIRMED_COMPILER_CODES):
            return {"scope": root["pin"], "reason": "STD_TREE_COMPILER_INCOMPATIBILITY",
                    "diagnostic": note}
    link = next((note for note in notes if re.match(r"^error: linking with .* failed:", note["text"])), None)
    if (link and evidence["markers"]["cargo_build"]["state"] == "OBSERVED"
            and any(re.match(r"^error: could not compile `(?:core|std|alloc|panic_abort)`", note["text"])
                    for note in notes)):
        return {"scope": root["pin"], "reason": "STD_TREE_LINK_INCOMPATIBILITY", "diagnostic": link}
    return None


def reconcile(regular, stock, root, request, attested_release, exit_code):
    """Cross-check stock buckets and renderer counts without assigning proof credit."""
    if regular["state"] != "COMPLETE" or stock["state"] != "COMPLETE":
        return {"state": "INCOMPLETE", "reason": "REGULAR_OR_STOCK_INCOMPLETE"}
    properties = regular["observations"]
    projected, = stock["observations"]
    meta, fields = stock["metadata"], projected["fields"]
    totals, buckets = projected["totals"], projected["property_buckets"]
    problems = []
    if (meta["schema_version"] != "0.1.0" or meta["run_state"] != "COMPLETE"
            or meta["kani_commit"] != request["pins"]["tool"]["sha"]
            or meta["kani_commit_dirty"] is not False or meta["tools"]["rustc"] != attested_release
            or (meta["tools"]["cbmc"] or "").split()[:1] != [request["dependency_versions"]["cbmc"]]):
        problems.append("STOCK_TOOL_OR_RUN_IDENTITY_MISMATCH")
    expected_features = {request[key][i + 1] for key in
                         (["standalone_argv"] if root["pin"] == "tool" else ["std_argv"])
                         for i, arg in enumerate(request[key]) if arg == "-Z"}
    if root["uninit"]:
        expected_features.add("uninit-checks")
    if (set(meta["enabled_unstable_features"]) != expected_features
            or meta["configuration"]["cbmc_args"] != ["--object-bits", "12"]
            or meta["harness_timeout_s"] != root["harness_seconds"]
            or fields["resolved_solver"] != request["solver"] or fields["resolved_unwind"] != root["unwind"]):
        problems.append("STOCK_EFFECTIVE_SETTINGS_MISMATCH")
    checks = meta["configuration_checks"]
    if (not all(checks[k] for k in ("memory_safety", "overflow", "unwinding", "assertion_reach_checks"))
            or (root["pin"] != "tool" and checks["assert_contracts"])
            or meta["configuration"]["coverage_enabled"]):
        problems.append("STOCK_CHECK_SETTINGS_MISMATCH")
    if fields["outcome.kind"] != "COMPLETED":
        problems.append("NATIVE_OUTCOME_INCOMPLETE")
    terminal = regular["terminal"]["verification"]
    verdict = fields["outcome.verdict"]
    if (verdict not in {"SUCCESS", "FAILURE"} or exit_code != int(verdict == "FAILURE")
            or not terminal.startswith("VERIFICATION:- " + ("SUCCESSFUL" if verdict == "SUCCESS" else "FAILED"))):
        problems.append("STOCK_REGULAR_EXIT_DISAGREEMENT")

    ids = Counter()
    status_counts = Counter()
    for prop in properties:
        bucket = "covers" if prop["class"] == "cover" else "checks"
        status = prop["status"].lower()
        ids[bucket, status, prop["stock_export_id"]] += 1
        status_counts[bucket, status] += 1
    # bcdc's Display intentionally renders both UNKNOWN and UNDETERMINED as
    # UNDETERMINED. The stock buckets preserve the distinction.
    for name, values in buckets.items():
        bucket, status = name.split(".")
        if status == "unknown":
            continue
        if status == "undetermined":
            values = values + buckets.get(f"{bucket}.unknown", [])
        if status == "other":
            observed = Counter({(key_status.upper(), prop_id): count
                                for (group, key_status, prop_id), count in ids.items()
                                if group == bucket and f"{bucket}.{key_status}" not in buckets
                                and (bucket, key_status) != ("checks", "success")})
            expected = Counter((v["status"], v["id"]) for v in values)
        else:
            observed = Counter({prop_id: count for (group, key_status, prop_id), count in ids.items()
                                if group == bucket and status == key_status})
            expected = Counter(values)
        if expected != observed:
            problems.append(f"REGULAR_BUCKET_MISMATCH:{name}")
    for bucket in ("checks", "covers"):
        if totals[f"{bucket}.total"] != sum(n for (group, _), n in status_counts.items() if group == bucket):
            problems.append(f"REGULAR_TOTAL_MISMATCH:{bucket}")
    if totals.get("checks.success") != status_counts["checks", "success"]:
        problems.append("REGULAR_CHECK_SUCCESS_COUNT_MISMATCH")
    terminal_counts = {"checks": (totals.get("n_failed"), totals.get("checks.total")),
                       "covers": (status_counts["covers", "satisfied"], totals.get("covers.total"))}
    for kind, (num, total) in terminal_counts.items():
        phrase = "failed" if kind == "checks" else "cover properties satisfied"
        expected = f" ** {num} of {total} {phrase}"
        observed = [item["text"] for item in regular["terminal"]["summary_lines"] if
                    re.fullmatch(r" \*\* \d+ of \d+ " + phrase + r"(?: \(.*\))?", item["text"])]
        if (kind == "checks" or total or observed) and (
                len(observed) != 1 or observed[0].split(" (", 1)[0] != expected):
            problems.append(f"REGULAR_SUMMARY_MISMATCH:{kind}")
    for key, pick in (("failed_properties", lambda p: p["status"] == "FAILURE" and p["class"] != "cover"),
                      ("unsupported_constructs", lambda p: p["class"] == "unsupported_construct")):
        native = Counter((p["stock_export_id"], p["class"], p["status"], p["description"])
                         for p in properties if pick(p))
        exported = Counter((p["id"], p["class"], "UNDETERMINED" if p["status"] == "UNKNOWN" else p["status"],
                            p["description"]) for p in fields[key])
        if native != exported:
            problems.append(f"REGULAR_PROPERTY_DETAIL_MISMATCH:{key}")

    calibration = None
    if root["pin"] == "tool":
        failures = [p for p in properties if p["status"] == "FAILURE"]
        unsupported = fields["unsupported_constructs"]
        reads = []
        for prop in failures:
            # IDs can recur after demangling. Each canary read still needs an exact association.
            match = UNINIT.fullmatch(prop["description"])
            matches = [p for p in fields["failed_properties"]
                       if p["id"] == prop["stock_export_id"] and p["description"] == prop["description"]]
            if len(matches) == 1 and match:
                item = matches[0]
                site = re.match(r"(?:.*/)?main\.rs:(\d+)(?::\d+)?(?: in function .+)?$", prop["location"] or "")
                if (item["class"] == "safety_check" and Path(item["file"] or "").name == "main.rs"
                        and item["line"] == str(root["read_line"]) and site and int(site[1]) == root["read_line"]):
                    reads.append({"id": item["id"], "type": match[1], "line": item["line"]})
        expected = Counter(("*const u32", "u32")) if root["expected_verdict"] == "FAILURE" else Counter()
        matched = (not unsupported and verdict == root["expected_verdict"] and len(failures) == len(reads)
                   and Counter(r["type"] for r in reads) == expected
                   and len({r["id"] for r in reads}) == len(reads) and not problems)
        calibration = {"state": "MATCH" if matched else "INCOMPLETE", "matched_reads": reads,
                       "failure_count": len(failures), "unsupported_count": len(unsupported)}
    covers = {label: [p for p in properties if p["class"] == "cover" and p["description"] == label]
              for label in root.get("required_covers", [])}
    return {
        "state": "INCOMPLETE" if problems else "CONSISTENT", "issues": problems, "verdict": verdict,
        "required_covers": {label: {"state": "OBSERVED" if items else "INCOMPLETE", "properties": items}
                            for label, items in covers.items()},
        "calibration": calibration, "verification_seconds": fields["resources"]["verification_time_s"],
        "unsupported": [p for p in properties if p["class"] == "unsupported_construct"],
        "uninit_reads": [p for p in properties if UNINIT.fullmatch(p["description"])],
        "native_property_counts": {f"{bucket}.{status}": n for (bucket, status), n in status_counts.items()},
    }
