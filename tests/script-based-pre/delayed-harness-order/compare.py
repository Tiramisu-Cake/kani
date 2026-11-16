#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT

import argparse
import collections
import hashlib
import json
import os
from pathlib import Path
import sys

HARNESS = {
    "delayed_harness": ["delayed_harness"],
    "initialized_control_harness": ["initialized_control_harness"],
    "paired": ["delayed_harness", "initialized_control_harness"],
}


class Incomplete(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Incomplete(message)


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def normalized_failures(entry):
    props = entry["failed_properties"]
    require(isinstance(props, list), "failed_properties must be an array")
    normalized = []
    for prop in props:
        require(isinstance(prop, dict), "failed property must be an object")
        description = prop.get("description")
        status = prop.get("status")
        klass = prop.get("class")
        line = prop.get("line")
        require(isinstance(description, str) and description, "failed property description missing")
        require(status == "FAILURE", "failed property has unsupported status")
        require(isinstance(klass, str) and klass, "failed property class missing")
        require(line is None or isinstance(line, str), "failed property line has wrong type")
        normalized.append((description, status, klass, line))
    return collections.Counter(normalized)


def parse_document(label, doc, wanted):
    require(isinstance(doc, dict), f"{label}: export must be an object")
    require(doc.get("run_state") == "COMPLETE", f"{label}: run is not complete")
    selection = doc.get("harness_selection")
    require(isinstance(selection, dict), f"{label}: harness selection missing")
    filters = selection.get("requested_filters")
    require(filters == HARNESS[wanted], f"{label}: wrong requested filters")
    require(isinstance(selection.get("exact"), bool), f"{label}: exact-filter flag missing or invalid")
    require(selection.get("unmatched_filters") == [], f"{label}: unmatched filter")
    require(integer(selection.get("matched_count")) and selection["matched_count"] == len(HARNESS[wanted]),
            f"{label}: wrong matched count")
    entries = doc.get("harnesses")
    require(isinstance(entries, list), f"{label}: harnesses must be an array")
    names = [e.get("name") for e in entries if isinstance(e, dict)]
    require(len(names) == len(entries), f"{label}: malformed harness entry")
    short_names = [name.split("::")[-1] if isinstance(name, str) else None for name in names]
    require(all(isinstance(name, str) and name for name in short_names), f"{label}: invalid harness name")
    require(len(set(names)) == len(names) and len(set(short_names)) == len(short_names), f"{label}: duplicate harness")
    require(set(short_names) == set(HARNESS[wanted]), f"{label}: wrong selected harnesses")

    result = {}
    for entry, name in zip(entries, short_names):
        outcome = entry.get("outcome")
        require(isinstance(outcome, dict), f"{label}/{name}: outcome missing")
        require(outcome.get("kind") == "COMPLETED", f"{label}/{name}: crashed, timed out, or incomplete")
        verdict = outcome.get("verdict")
        require(verdict in ("SUCCESS", "FAILURE"), f"{label}/{name}: unsupported outcome")
        for field in ("n_properties", "n_failed"):
            require(integer(entry.get(field)), f"{label}/{name}: {field} missing or invalid")
        checks = entry.get("checks")
        require(isinstance(checks, dict), f"{label}/{name}: checks missing")
        for field in ("total", "success"):
            require(integer(checks.get(field)), f"{label}/{name}: checks.{field} missing or invalid")
        require(checks["total"] == entry["n_properties"], f"{label}/{name}: property total mismatch")
        for field in ("failure", "undetermined", "error", "unknown", "unreachable"):
            require(isinstance(checks.get(field), list), f"{label}/{name}: checks.{field} missing or invalid")
            require(all(isinstance(item, str) for item in checks[field]),
                    f"{label}/{name}: checks.{field} contains a malformed entry")
        require(isinstance(checks.get("other"), list) and not checks["other"],
                f"{label}/{name}: unclassified checks present")
        require(not checks["undetermined"] and not checks["error"] and not checks["unknown"],
                f"{label}/{name}: unsupported or unresolved checks")
        require(checks["success"] + entry["n_failed"] + len(checks["unreachable"]) == checks["total"],
                f"{label}/{name}: check counts mismatch")
        covers = entry.get("covers")
        require(isinstance(covers, dict) and integer(covers.get("total")) and covers["total"] == 0,
                f"{label}/{name}: unexpected cover properties")
        unsupported = entry.get("unsupported_constructs")
        require(isinstance(unsupported, list) and not unsupported, f"{label}/{name}: unsupported constructs present")
        failures = normalized_failures(entry)
        require(entry["n_failed"] == sum(failures.values()), f"{label}/{name}: failed property count mismatch")
        require(len(checks["failure"]) == entry["n_failed"], f"{label}/{name}: failure list count mismatch")

        require((verdict == "FAILURE") == (entry["n_failed"] > 0),
                f"{label}/{name}: verdict disagrees with failure count")
        require(all("uninitialized" in item[0].lower() for item in failures),
                f"{label}/{name}: failure was not uninitialized-memory-only")
        if wanted != "paired":
            expected_verdict = "FAILURE" if name == "delayed_harness" else "SUCCESS"
            require(verdict == expected_verdict,
                    f"{label}: isolated {name} did not have its expected verdict")
        result[name] = {
            "verdict": verdict,
            "n_properties": entry["n_properties"],
            "n_failed": entry["n_failed"],
            "checks_total": checks["total"],
            "checks_success": checks["success"],
            "checks_unreachable": len(checks["unreachable"]),
            "failed_semantics": sorted((list(item) + [count]) for item, count in failures.items()),
        }
    return result


def parse_export(label, path, wanted):
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise Incomplete(f"{label}: export unavailable or invalid: {exc}") from exc
    return parse_document(label, doc, wanted)


def parse_run(label, wanted, runs_dir):
    try:
        export_path = runs_dir / f"{label}.json"
        inventory = parse_export(label, export_path, wanted)
        status = int((runs_dir / f"{label}.status").read_text(encoding="utf-8").strip())
        expected_nonzero = any(e["verdict"] == "FAILURE" for e in inventory.values())
        expected_status = 1 if expected_nonzero else 0
        require(status == expected_status, f"{label}: process exit {status} disagrees with expected exit {expected_status}")
        argv = (runs_dir / f"{label}.argv").read_bytes().decode().rstrip("\0").split("\0")
        rustflags = (runs_dir / f"{label}.rustflags").read_text(encoding="utf-8").strip()
        target_dir = (runs_dir / f"{label}.target-dir").read_text(encoding="utf-8").strip()
        inventory_digest = hashlib.sha256(json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return {
            "exit_code": status,
            "argv": argv,
            "rustflags": rustflags,
            "target_dir": target_dir,
            "export_sha256": hashlib.sha256(export_path.read_bytes()).hexdigest(),
            "log_sha256": hashlib.sha256((runs_dir / f"{label}.log").read_bytes()).hexdigest(),
            "inventory_sha256": inventory_digest,
            "harnesses": inventory,
        }
    except Incomplete:
        raise
    except Exception as exc:
        raise Incomplete(f"{label}: {exc}") from exc


def same_inventory(single, paired, harness):
    return single["harnesses"][harness] == paired["harnesses"][harness]


def any_inventory_difference(solo, paired):
    return any(not same_inventory(solo, paired, name) for name in solo["harnesses"])


def compare_runs(runs_dir):
    runs = {}
    comparisons = {}
    observed = False
    incomplete = False
    for mode in ("delayed_first", "control_first"):
        cases = {
            "delayed_alone": (f"{mode}-delayed-alone", "delayed_harness"),
            "control_alone": (f"{mode}-control-alone", "initialized_control_harness"),
            "paired": (f"{mode}-paired", "paired"),
        }
        parsed = {}
        for key, (label, wanted) in cases.items():
            try:
                parsed[key] = parse_run(label, wanted, runs_dir)
            except Incomplete as exc:
                incomplete = True
                parsed[key] = {"incomplete": str(exc)}
        runs[mode] = parsed
        pairs = {}
        if any("incomplete" in item for item in parsed.values()):
            comparisons[mode] = {"status": "INCOMPLETE"}
            continue
        for solo, harness in (("delayed_alone", "delayed_harness"), ("control_alone", "initialized_control_harness")):
            same = same_inventory(parsed[solo], parsed["paired"], harness)
            pairs[f"{solo}_vs_paired"] = same
            observed |= not same
        comparisons[mode] = pairs
    classification = "INCONCLUSIVE" if incomplete else ("DEFECT_PRESENT" if observed else "DEFECT_ABSENT_FOR_TEST")
    return {"classification": classification, "runs": runs, "comparisons": comparisons,
            "order_coverage": "UNESTABLISHED",
            "order_coverage_reason": "The stock compiler source has no per-harness ordering log; codegen_order sorts by reachable-item count only when export workers are available."}


def synthetic_doc(names, delayed_failure=True, control_success=True, partial=False, null_check=False):
    entries = []
    for name in names:
        delayed = name == "delayed_harness"
        failure = (delayed and delayed_failure) or (not delayed and not control_success)
        n_failed = 1 if failure else 0
        checks = {"total": 3, "success": 2 - n_failed, "failure": ["unstable-id"] * n_failed,
                  "undetermined": [], "error": [], "unknown": [], "unreachable": ["unreachable-id"], "other": []}
        if null_check and delayed:
            checks["success"] = None
        outcome = {"kind": "COMPLETED", "verdict": "FAILURE" if failure else "SUCCESS"}
        entries.append({
            "name": name,
            "outcome": outcome,
            "n_properties": 3,
            "n_failed": n_failed,
            "checks": checks,
            "failed_properties": ([{"description": "Undefined Behavior: Reading from an uninitialized pointer of type `u128`",
                                    "status": "FAILURE", "class": "SAFETY_CHECK", "line": "21", "id": "unstable-id"}] if failure else []),
            "unsupported_constructs": [],
            "covers": {"total": 0},
        })
    return {"run_state": "PARTIAL" if partial else "COMPLETE",
            "harness_selection": {"requested_filters": names, "exact": False, "unmatched_filters": [], "matched_count": len(names)},
            "harnesses": entries}


def synthetic_test():
    delayed = parse_document("synthetic-delayed", synthetic_doc(["delayed_harness"]), "delayed_harness")["delayed_harness"]
    control = parse_document("synthetic-control", synthetic_doc(["initialized_control_harness"]), "initialized_control_harness")["initialized_control_harness"]
    paired_doc = synthetic_doc(["delayed_harness", "initialized_control_harness"])
    paired_doc["harnesses"][0]["checks"]["failure"] = ["different-unstable-id"]
    paired_doc["harnesses"][0]["failed_properties"][0]["id"] = "different-unstable-id"
    paired = parse_document("synthetic-paired", paired_doc, "paired")
    # The delayed run and mixed run exit nonzero; the control-only run exits zero.
    assert validate_expected_process(1, {"delayed_harness": delayed})
    assert validate_expected_process(0, {"initialized_control_harness": control})
    assert validate_expected_process(1, paired)
    solo_delayed = {"harnesses": {"delayed_harness": delayed}}
    solo_control = {"harnesses": {"initialized_control_harness": control}}
    paired_run = {"harnesses": paired}
    assert not any_inventory_difference(solo_delayed, paired_run)
    assert not any_inventory_difference(solo_control, paired_run)
    changed_doc = synthetic_doc(["delayed_harness", "initialized_control_harness"])
    changed_doc["harnesses"][1]["n_properties"] = 4
    changed_doc["harnesses"][1]["checks"]["total"] = 4
    changed_doc["harnesses"][1]["checks"]["success"] = 3
    changed = parse_document("synthetic-changed", changed_doc, "paired")
    assert any_inventory_difference(solo_control, {"harnesses": changed})
    leaked_doc = synthetic_doc(["delayed_harness", "initialized_control_harness"], control_success=False)
    leaked = parse_document("synthetic-leak", leaked_doc, "paired")
    assert leaked["initialized_control_harness"]["verdict"] == "FAILURE"
    assert any_inventory_difference(solo_control, {"harnesses": leaked})
    crashed = synthetic_doc(["delayed_harness"])
    crashed["harnesses"][0]["outcome"] = {"kind": "CRASHED", "code": 101}
    for malformed in (None, {}, synthetic_doc(["delayed_harness"], partial=True),
                      synthetic_doc(["delayed_harness"], null_check=True), crashed):
        try:
            parse_document("synthetic-invalid", malformed, "delayed_harness")
        except Incomplete:
            pass
        else:
            raise AssertionError("malformed or partial export accepted")
    isolated_bad_control = synthetic_doc(["initialized_control_harness"], control_success=False)
    try:
        parse_document("synthetic-invalid-control", isolated_bad_control, "initialized_control_harness")
    except Incomplete:
        pass
    else:
        raise AssertionError("unexpected isolated control failure accepted")


def validate_expected_process(status, inventory):
    nonzero = any(e["verdict"] == "FAILURE" for e in inventory.values())
    return status == (1 if nonzero else 0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs-dir", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        synthetic_test()
        print("F4 comparator synthetic checks passed")
        return 0
    if args.runs_dir is None:
        parser.error("--runs-dir is required")
    try:
        receipt = compare_runs(args.runs_dir)
    except Incomplete as exc:
        receipt = {"classification": "INCONCLUSIVE", "reason": str(exc), "order_coverage": "UNESTABLISHED"}
    receipt["schema"] = "kani-confirm-main-f4-v1"
    evidence_dir = os.environ.get("CONFIRM_EVIDENCE_DIR")
    receipt_path = Path(evidence_dir) / "F4-native.json" if evidence_dir else None
    if receipt_path:
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
    if receipt_path:
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    classification = receipt["classification"]
    if classification == "INCONCLUSIVE":
        print("Delayed UB verification is inconclusive.")
        return 2
    if classification == "DEFECT_PRESENT":
        print("Delayed UB check results differ between isolated and paired harness verification.")
        return 1
    print("Delayed UB check results are consistent across isolated and paired harness verification.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
