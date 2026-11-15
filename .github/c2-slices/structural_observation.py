#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""CI-only full-inventory validators extracted from accepted C2-S4; no bound snapshots."""
import importlib.util
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
import sys
ROOT = Path(os.environ.get("SEL1_C2_SOURCE_DIR", Path(__file__).resolve().parents[2])).resolve()
SPEC = importlib.util.spec_from_file_location("validate_json_export", ROOT / "scripts/validate_json_export.py")
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
SCHEMA = VALIDATOR.load_schema_template()
class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def normalize(value, prefix):
    """Remove installation roots, retaining complete source/property identities.

    Rust source is outside the checkout: the regular renderer relativizes it
    against cwd, while JSON uses an absolute path. Keep its toolchain identity
    and full library suffix in a separate namespace. Do not collapse arbitrary
    external paths or strip basename-only suffixes.
    """
    if not isinstance(value, str):
        return value
    value = re.sub(r"(?<![\w./-])" + re.escape(prefix.rstrip("/") + "/"), "", value)
    return re.sub(
        r"(?<![\w./-])(?:/(?:[\w.+-]+/)*|(?:\.\./)+(?:[\w.+-]+/)*)"
        r"toolchains/([^/\s:]+)/lib/rustlib/src/rust/library/",
        r"rust-toolchain:\1/library/", value)


def normalize_property(prop, prefix):
    # Source paths also occur inside closure IDs, function names and diagnostics.
    return {key: normalize(value, prefix) for key, value in prop.items()}


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


CHECKER = sys.modules[__name__]

def observation(data, regular, selectors, case_by_name, receipt):
    problems = CHECKER.VALIDATOR.validate_document(data, CHECKER.SCHEMA)
    require(not problems, f"shared JSON schema/presence validation failed: {problems}")
    require(data.get("run_state") == "COMPLETE" and data.get("outcome") == {"kind": "COMPLETED"},
            "run did not complete")
    selection = data["harness_selection"]
    require(selection["requested_filters"] == selectors and selection["exact"] is True
            and selection["matched_count"] == len(selectors)
            and selection["unmatched_filters"] == [], "wrong/incomplete harness selection")
    started = datetime.strptime(data["started_at"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc).timestamp()
    require(type(receipt.get("started_epoch")) in (int, float)
            and type(receipt.get("finished_epoch")) in (int, float)
            and receipt["started_epoch"] - 1 <= started <= receipt["finished_epoch"],
            "stale export timestamp")
    require(set(data["enabled_unstable_features"]) ==
            {"uninit-checks", "function-contracts", "export-json", "unstable-options"},
            "unstable feature drift")
    config = data["configuration"]
    require(config["cbmc_args"] == ["--object-bits", "12"], "backend profile drift")
    require(config["coverage_enabled"] is False, "unexpected coverage configuration")
    for check_name in ("memory_safety", "overflow", "unwinding", "undefined_function",
                       "assertion_reach_checks", "assert_contracts"):
        require(config["checks"][check_name] is True, f"disabled check: {check_name}")
    for check_name in ("ignore_global_asm", "prove_safety_only"):
        require(config["checks"][check_name] is False, f"unexpected check mode: {check_name}")
    harnesses = data["harnesses"]
    require(len(harnesses) == len(selectors), "harness inventory incomplete")
    expected_summary = {"total": len(selectors),
                        "successful": sum(h["outcome"].get("verdict") == "SUCCESS" for h in harnesses),
                        "failed": sum(h["outcome"].get("verdict") == "FAILURE" for h in harnesses),
                        "checks_total": sum(h["checks"]["total"] for h in harnesses),
                        "checks_success": sum(h["checks"]["success"] for h in harnesses),
                        "covers_total": sum(h["covers"]["total"] for h in harnesses),
                        "covers_satisfied": sum(len(h["covers"]["satisfied"]) for h in harnesses)}
    require(data["summary"] == expected_summary, "aggregate summary counter drift")
    roots = []
    for harness in harnesses:
        name = harness["name"]
        require(name in selectors and name in case_by_name, "wrong selected root")
        case = case_by_name[name]
        require(CHECKER.normalize(harness["file"], receipt["build_prefix"]) ==
                ".github/c2-slices/structural-mixed.rs",
                f"selected root came from wrong input: {name}")
        require(harness["line"] == case["root_line"], f"root line drift: {name}")
        require(harness["outcome"].get("kind") == "COMPLETED", f"root incomplete: {name}")
        verdict = harness["outcome"].get("verdict")
        require(verdict in ("SUCCESS", "FAILURE"), f"unexpected root outcome: {name}")
        checks = harness["checks"]
        failure_ids = checks["failure"]
        unreachable_ids = checks["unreachable"]
        require(len(failure_ids) == len(set(failure_ids)),
                f"duplicate JSON failure ID: {name}")
        require(len(unreachable_ids) == len(set(unreachable_ids)),
                f"duplicate JSON unreachable ID: {name}")
        check_ids = set(failure_ids) | set(unreachable_ids)
        for bucket in (checks, harness["covers"]):
            require(all(bucket[key] == [] for key in
                        ("undetermined", "error", "unknown", "other")),
                    f"nonterminal property status: {name}")
        require(checks["total"] == checks["success"] + len(checks["failure"])
                + len(checks["unreachable"]), f"incomplete JSON check partition: {name}")
        covers = harness["covers"]
        cover_status = {}
        for bucket, status in (("satisfied", "SATISFIED"), ("unsatisfiable", "UNSATISFIABLE"),
                               ("unreachable", "UNREACHABLE")):
            for identifier in covers[bucket]:
                require(identifier not in cover_status, f"duplicate JSON cover ID: {name}")
                cover_status[identifier] = status
        require(covers["total"] == len(cover_status), f"incomplete JSON cover partition: {name}")
        require(harness["n_properties"] == checks["total"] + covers["total"],
                f"incomplete JSON property partition: {name}")
        attrs = harness["attributes"]
        require(attrs["should_panic"] is False and attrs["stubs"] == [],
                f"unexpected harness attributes: {name}")
        if case["mode"] in ("PFC", "PFC+recursion"):
            kind = attrs["kind"]
            target = (kind.get("ProofForContract", {}).get("target_fn")
                      if isinstance(kind, dict) else None)
            require(isinstance(kind, dict) and set(kind) == {"ProofForContract"}
                    and isinstance(target, str)
                    and (target == case["target"] or target.endswith("::" + case["target"])),
                    f"wrong PFC target: {name}: expected={case['target']!r}, actual={kind!r}")
            require(attrs["verified_stubs"] == [], f"unexpected verified stubs: {name}")
            if case["mode"] == "PFC+recursion":
                require(harness["contract"] is not None
                        and bool(harness["contract"]["recursion_tracker"]),
                        f"recursive PFC mode metadata missing: {name}")
        else:
            require(attrs["kind"] == "Proof" and attrs["verified_stubs"] == [],
                    f"wrong ordinary Assert mode: {name}")
        markers = re.findall(r"(?m)^Checking harness " + re.escape(name) + r"\.\.\.$", regular)
        require(len(markers) == 1, f"missing/duplicate exact regular root marker: {name}")
        marker = re.search(r"(?m)^Checking harness " + re.escape(name) + r"\.\.\.$", regular)
        remaining = regular[marker.end():]
        next_marker = re.search(r"(?m)^Checking harness .+\.\.\.$", remaining)
        block_end = marker.end() + next_marker.start() if next_marker else len(regular)
        all_rows = CHECKER.regular_properties(regular[marker.start():block_end])
        expected_count = harness["n_properties"]
        require(type(expected_count) is int and len(all_rows) == expected_count,
                f"regular root inventory incomplete: {name}")
        require(len({row["id"] for row in all_rows}) == len(all_rows),
                f"duplicate regular root property identity: {name}")
        cover_rows = [row for row in all_rows if row["id"] in cover_status]
        selected_rows = [row for row in all_rows if row["id"] not in cover_status]
        require({row["id"]: row["status"] for row in cover_rows} == cover_status,
                f"regular/JSON cover inventory mismatch: {name}")
        require(check_ids <= {row["id"] for row in selected_rows},
                f"JSON failure/unreachable IDs absent from root regular inventory: {name}")
        require(Counter_status(selected_rows) == {
            "SUCCESS": checks["success"], "FAILURE": len(checks["failure"]),
            "UNREACHABLE": len(checks["unreachable"])},
            f"regular/JSON inventory mismatch: {name}")
        regular_failures = {row["id"] for row in selected_rows if row["status"] == "FAILURE"}
        regular_unreachable = {row["id"] for row in selected_rows
                               if row["status"] == "UNREACHABLE"}
        require(regular_failures == set(failure_ids),
                f"regular/JSON failure ID mismatch: {name}")
        require(regular_unreachable == set(unreachable_ids),
                f"regular/JSON unreachable ID mismatch: {name}")
        failed = harness["failed_properties"]
        require(isinstance(failed, list), f"missing failed-properties list: {name}")
        failed_ids = [item.get("id") for item in failed if isinstance(item, dict)]
        require(len(failed_ids) == len(failed) and len(failed_ids) == len(set(failed_ids)),
                f"malformed/duplicate failed-properties: {name}")
        require(type(harness["n_failed"]) is int
                and harness["n_failed"] == len(failed) == len(failure_ids),
                f"failed-property counter mismatch: {name}")
        require(set(failed_ids) == set(failure_ids),
                f"failed-properties inventory mismatch: {name}")
        require((verdict == "FAILURE") == bool(failed), f"verdict/failure drift: {name}")
        failure_kind = harness["failure_kind"]
        require(failure_kind in {"ERROR", "NONE", "OTHER", "PANICS_ONLY"},
                f"invalid failure kind: {name}")
        require((verdict == "SUCCESS") == (failure_kind == "NONE"),
                f"verdict/failure-kind drift: {name}")
        by_regular = {row["id"]: row for row in selected_rows}
        failed_by_id = {item["id"]: item for item in failed}
        for row in selected_rows:
            if row["status"] == "FAILURE":
                require(row["id"] in failed_by_id
                        and row["description"] == failed_by_id[row["id"]]["description"],
                        f"regular/JSON failure detail mismatch: {name}")
        unsupported = harness["unsupported_constructs"]
        require(isinstance(unsupported, list), f"missing Unsupported inventory: {name}")
        unsupported_ids = [item.get("id") for item in unsupported if isinstance(item, dict)]
        require(len(unsupported_ids) == len(unsupported)
                and len(unsupported_ids) == len(set(unsupported_ids)),
                f"malformed/duplicate Unsupported inventory: {name}")
        normalized_unsupported = []
        for item in unsupported:
            require(item["status"] in {"SUCCESS", "FAILURE", "UNREACHABLE"},
                    f"nonterminal Unsupported status: {name}")
            regular_item = by_regular.get(item["id"])
            require(regular_item is not None and regular_item["status"] == item["status"]
                    and regular_item["description"] == item["description"],
                    f"regular/JSON Unsupported inventory mismatch: {name}")
            if item["status"] == "FAILURE":
                failure = failed_by_id.get(item["id"])
                require(failure is not None and all(item[key] == failure[key] for key in
                        ("description", "class", "file", "line", "trace_available", "status")),
                        f"failed Unsupported metadata mismatch: {name}")
            normalized_unsupported.append({key: CHECKER.normalize(item[key], receipt["build_prefix"])
                                           for key in ("id", "description", "class", "file", "line",
                                                       "trace_available", "status")})
        require(verdict == case["expected_verdict"], f"unexpected verdict: {name}")
        def normalize_rows(rows):
            return [CHECKER.normalize_property(row, receipt["build_prefix"]) for row in rows]
        normalized_failed = [{key: CHECKER.normalize(item[key], receipt["build_prefix"])
                              for key in ("id", "description", "class", "file", "line",
                                          "trace_available", "status")}
                             for item in failed]
        roots.append({"expected_root": name, "actual_root": name,
                      "inventory_complete": True, "verdict": verdict,
                      "failure_kind": failure_kind, "n_failed": harness["n_failed"],
                      "checks": normalize_rows(selected_rows), "covers": normalize_rows(cover_rows),
                      "failed_properties": normalized_failed,
                      "unsupported_constructs": normalized_unsupported})
    return {"run_state": "COMPLETE", "requested_roots": selectors, "roots": roots}


def Counter_status(rows):
    result = {"SUCCESS": 0, "FAILURE": 0, "UNREACHABLE": 0}
    for row in rows:
        require(row["status"] in result, "unknown regular status")
        result[row["status"]] += 1
    return result
