#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Exact per-invocation regression gate, with deterministic PASS/FAIL results.

JSON schema validation is shared with the existing export tests. This consumer
adds selection, complete inventories, counters and selected regular evidence.
It does not establish source -> GOTO causality or independent proof credit.
REGRESSION_BOUND manifests pin reviewed source and property expectations.
"""

import hashlib
import importlib.util
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "validate_json_export", ROOT / "scripts/validate_json_export.py"
)
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
SCHEMA = VALIDATOR.load_schema_template()
FIELDS = ("id", "description", "class", "file", "line", "status")
FLAGS = {"uninit-checks", "function-contracts", "export-json", "unstable-options"}
REACHED_UNSUPPORTED = {"FAILURE", "UNDETERMINED", "UNKNOWN"}


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def normalize(value, prefix):
    # Only the explicitly known checkout prefix. Keep all lines, types,
    # functions, generated names and rust library paths intact.
    return value.replace(prefix.rstrip("/") + "/", "") if isinstance(value, str) else value


def identity(prop, prefix):
    return tuple(normalize(prop[key], prefix) for key in FIELDS)


def load_export(path):
    # Reject duplicate JSON keys, which ordinary json.load silently overwrites.
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value):
        raise Rejected(f"non-JSON numeric constant: {value}")

    return json.loads(Path(path).read_text(), object_pairs_hook=unique,
                      parse_constant=invalid_constant)


def regular_properties(text):
    """Parse the existing regular renderer, failing closed on partial records."""
    require(text.count("\nRESULTS:\n") == 1, "missing/duplicate regular RESULTS")
    require(text.count("\nSUMMARY:") == 1, "missing/duplicate regular SUMMARY")
    section = text.split("\nRESULTS:\n", 1)[1].split("\nSUMMARY:", 1)[0]
    records = []
    for block in section.strip().split("\n\n"):
        match = re.fullmatch(
            r'Check ([1-9][0-9]*): (.+)\n\t - Status: ([A-Z]+)\n'
            r'\t - Description: "(.*)"(?:\n\t - Location: (.+))?', block
        )
        require(match is not None, "malformed/truncated regular property")
        index, pid, status, description, location = match.groups()
        require(int(index) == len(records) + 1, "regular property sequence gap")
        records.append({"id": pid, "status": status, "description": description,
                        "location": location})
    return records


def validate(data, case, receipt, regular, root=ROOT):
    problems = VALIDATOR.validate_document(data, SCHEMA)
    require(not problems, f"export schema/presence: {problems}")
    source = root / case["input"]
    require(sha256(source) == case["sha256"] == receipt["input_sha256"], "input hash mismatch")
    require(receipt["input"] == case["input"] and receipt["root"] == case["root"],
            "receipt input/root mismatch")
    require(receipt["timed_out"] is False and receipt["error"] is None, "timeout/process error")
    expected_exit = 0 if case["verdict"] == "SUCCESS" else 1
    require(type(receipt["original_exit"]) is int and receipt["original_exit"] == expected_exit,
            "signal/nonverification exit or wrong verdict exit")
    # Kani stores whole seconds. Allow rounding within the actual process window.
    started = datetime.strptime(data["started_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc).timestamp()
    require(receipt["started_epoch"] - 1 <= started <= receipt["finished_epoch"], "stale export")
    require(data["run_state"] == "COMPLETE" and data["outcome"] == {"kind": "COMPLETED"},
            "incomplete run")
    require(data["harness_selection"] == {
        "requested_filters": [case["root"]], "exact": True,
        "unmatched_filters": [], "matched_count": 1,
    }, "wrong harness selection")
    require(set(data["enabled_unstable_features"]) == FLAGS, "wrong unstable features")
    config = data["configuration"]
    require(config["cbmc_args"] == ["--object-bits", "12"], "wrong backend flags")
    require(config["coverage_enabled"] is False, "unexpected coverage")
    for flag in ("memory_safety", "overflow", "unwinding", "undefined_function",
                 "assertion_reach_checks", "assert_contracts"):
        require(config["checks"][flag] is True, f"disabled check: {flag}")
    for flag in ("ignore_global_asm", "prove_safety_only"):
        require(config["checks"][flag] is False, f"unexpected check mode: {flag}")
    require(len(data["harnesses"]) == 1, "missing/duplicate root")
    h = data["harnesses"][0]
    prefix = receipt["build_prefix"]
    require(Path(prefix).is_absolute(), "build prefix must be absolute")
    require(receipt.get("cwd") == prefix, "invocation cwd must be checkout root")
    require(h["name"] == case["root"] and normalize(h["file"], prefix) == case["input"],
            "same root in wrong input or wrong root")
    require(h["line"] == case["root_line"], "wrong harness source line")
    require(h["attributes"]["should_panic"] is False, "unexpected should_panic")
    require(h["attributes"]["stubs"] == [] and h["attributes"]["verified_stubs"] == [],
            "unexpected stubs")
    require(h["outcome"] == {"kind": "COMPLETED", "verdict": case["verdict"]}, "wrong outcome")
    require(h["failure_kind"] == ("NONE" if expected_exit == 0 else "OTHER"), "wrong failure kind")
    # Unsupported properties assert(false): SUCCESS proves that path was not
    # executed. Neither SUCCESS nor UNREACHABLE is a reached Unsupported.
    require(all(p["status"] in {"SUCCESS", "UNREACHABLE"}
                for p in h["unsupported_constructs"]), "reached/nonterminal Unsupported")
    require(len({p["id"] for p in h["unsupported_constructs"]}) == len(h["unsupported_constructs"]),
            "duplicate Unsupported IDs")
    checks, covers = h["checks"], h["covers"]
    for bucket in (checks, covers):
        for name in ("undetermined", "error", "unknown", "other"):
            require(bucket[name] == [], f"nonterminal/unknown property: {name}")
    for name in ("n_properties", "n_failed"):
        require(type(h[name]) is int and h[name] >= 0, f"bad counter {name}")
    for value in (checks["total"], checks["success"], covers["total"]):
        require(type(value) is int and value >= 0, "bad checks/covers counter")
    require(covers["total"] == 0 and all(not covers[k] for k in covers if k != "total"),
            "unexpected cover properties")
    ids = checks["failure"] + checks["unreachable"]
    require(len(ids) == len(set(ids)), "duplicate/overlapping check IDs")
    require(h["n_properties"] == checks["total"] + covers["total"], "n_properties partition mismatch")
    require(checks["total"] == checks["success"] + len(ids), "checks partition mismatch")
    failed = h["failed_properties"]
    fids = [p["id"] for p in failed]
    require(len(fids) == len(set(fids)), "duplicate failed IDs")
    require(h["n_failed"] == len(failed) == len(checks["failure"]), "failure counter mismatch")
    require(set(fids) == set(checks["failure"]), "failed_properties/checks.failure mismatch")
    require(all(p["status"] == "FAILURE" for p in failed), "wrong failed status")
    require(bool(failed) == bool(expected_exit), "verdict/failures mismatch")
    summary = {"total": 1, "successful": int(expected_exit == 0), "failed": int(expected_exit != 0),
               "checks_total": checks["total"], "checks_success": checks["success"],
               "covers_total": 0, "covers_satisfied": 0}
    require(data["summary"] == summary, "summary mismatch")

    # The full regular inventory is from this process, alongside the export.
    props = regular_properties(regular)
    require(len(props) == h["n_properties"], "partial regular inventory")
    require(len({p["id"] for p in props}) == len(props), "duplicate regular IDs")
    require(Counter(p["status"] for p in props) == +Counter({
        "SUCCESS": checks["success"], "FAILURE": len(failed),
        "UNREACHABLE": len(checks["unreachable"]),
    }), "regular/JSON status inventory mismatch")
    require({p["id"] for p in props if p["status"] == "FAILURE"} == set(fids),
            "regular/JSON failure IDs mismatch")
    require({p["id"] for p in props if p["status"] == "UNREACHABLE"} == set(checks["unreachable"]),
            "regular/JSON unreachable IDs mismatch")
    by_id = {p["id"]: p for p in props}
    for p in h["unsupported_constructs"]:
        require(p["id"] in by_id and by_id[p["id"]]["status"] == p["status"] and
                by_id[p["id"]]["description"] == p["description"],
                "Unsupported regular/JSON inventory mismatch")
    for p in failed:
        require(by_id[p["id"]]["description"] == p["description"], "failure description mismatch")
    marker = "SUCCESSFUL" if expected_exit == 0 else "FAILED"
    require(regular.count(f"VERIFICATION:- {marker}") == 1, "missing regular verdict")
    require(regular.count(f"Checking harness {case['root']}...") == 1, "regular root mismatch")

    binding = case["binding"]
    require(binding["status"] == "REGRESSION_BOUND",
            "BINDING_PENDING: regression expectations must be reviewed and committed")
    expected = binding["failures"]
    require(isinstance(expected, list), "missing exact failure inventory")
    expected = list(expected)
    normalized = {p["id"]: {k: normalize(v, prefix) for k, v in p.items()} for p in props}
    consequences = binding.get("allowed_consequences", [])
    consequence_ids = [p["failure"]["id"] for p in consequences]
    require(len(consequence_ids) == len(set(consequence_ids)) and
            not set(consequence_ids).intersection(p["id"] for p in expected),
            "duplicate/overlapping consequence IDs")
    consequence_failures = 0
    for consequence in consequences:
        failure, record = consequence["failure"], consequence["regular"]
        require(failure["class"] == "assertion" and failure["status"] == "FAILURE" and
                record["id"] == failure["id"] and record["status"] == "FAILURE" and
                record["description"] == failure["description"], "bad consequence binding")
        actual = normalized.get(failure["id"])
        require(actual is not None and actual["status"] in {"FAILURE", "UNREACHABLE"},
                "outer ensures must be FAILURE or UNREACHABLE")
        require(actual == dict(record, status=actual["status"]),
                "outer ensures identity/location mismatch")
        if actual["status"] == "FAILURE":
            expected.append(failure)
            consequence_failures += 1
    require(type(case["failure_count"]) is int and
            case["failure_count"] == len(binding["failures"]) and
            len(failed) == case["failure_count"] + consequence_failures, "missing/extra failure")
    require(Counter(identity(p, prefix) for p in failed) ==
            Counter(identity(p, prefix) for p in expected), "exact failure inventory mismatch")
    require(set(binding["operations"]) == set(case["required_operations"]), "incomplete operation map")
    require(all(binding["operations"].values()), "empty operation binding")
    successes = binding["required_successes"]
    require(isinstance(successes, list) and (successes or expected_exit != 0),
            "positive useful assertions not bound")
    for p in successes:
        require(p["status"] == "SUCCESS" and normalized.get(p["id"]) == p,
                "useful assertion missing/unreachable/wrong source or function")
    for p in binding.get("required_regular", []):
        require(normalized.get(p["id"]) == p, "required regular identity/location mismatch")
    return "PASS"


def check_directory(directory, case, receipt):
    """Check current output against its in-memory invocation identity."""
    require(sha256(directory / "export.json") == receipt["export_sha256"], "export hash mismatch")
    require(sha256(directory / "regular.out") == receipt["regular_sha256"], "regular hash mismatch")
    require(receipt["input_sha256_after"] == receipt["input_sha256"], "source changed during run")
    return validate(load_export(directory / "export.json"), case, receipt,
                    (directory / "regular.out").read_text())
