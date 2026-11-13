#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Run isolated mixed roots and two fresh-process selector-order collections."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

from compare import check_single, compare_selection, require

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
ORACLE_DIR = ROOT / "tests/json-handler/uninit-contract-oracles"
SPEC = importlib.util.spec_from_file_location("uninit_oracle_checker", ORACLE_DIR / "checker.py")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate_process_result(return_code, expected_exit, timed_out=False, start_error=None):
    require(not timed_out, "TIMEOUT")
    require(start_error is None, f"PROCESS_START_OR_OUTPUT_ERROR: {start_error}")
    require(type(return_code) is int and return_code == expected_exit,
            f"NONVERIFICATION_OR_EXIT_MISMATCH: actual={return_code!r}, expected={expected_exit}")


def command(kani, manifest, selectors, directory):
    argv = [kani, str(ROOT / manifest["source"]), "-Z", "uninit-checks",
            "-Z", "function-contracts", "-Z", "export-json", "-Z", "unstable-options"]
    for selector in selectors:
        argv += ["--harness", selector]
    return argv + ["--exact", "--jobs", str(manifest["jobs"]),
                   "--target-dir", str(directory / "target"),
                   "--export-json", str(directory / "export.json"),
                   "--output-format=regular", "--cbmc-args", "--object-bits",
                   str(manifest["object_bits"])]


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
                "tests/json-handler/uninit-part1-composition/mixed.rs",
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
        selected_rows = CHECKER.regular_properties(regular[marker.start():block_end])
        expected_count = harness["n_properties"]
        require(type(expected_count) is int and len(selected_rows) == expected_count,
                f"regular root inventory incomplete: {name}")
        require(len({row["id"] for row in selected_rows}) == len(selected_rows),
                f"duplicate regular root property identity: {name}")
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
                                           if key == "file" else item[key]
                                           for key in ("id", "description", "class", "file", "line",
                                                       "trace_available", "status")})
        require(verdict == case["expected_verdict"], f"unexpected verdict: {name}")
        normalized = []
        for row in selected_rows:
            normalized.append({"id": row["id"], "status": row["status"],
                               "description": row["description"],
                               "location": CHECKER.normalize(row["location"], receipt["build_prefix"])
                               if row["location"] else None})
        normalized_failed = [{key: CHECKER.normalize(item[key], receipt["build_prefix"])
                              if key == "file" else item[key]
                              for key in ("id", "description", "class", "file", "line",
                                          "trace_available", "status")}
                             for item in failed]
        roots.append({"expected_root": name, "actual_root": name,
                      "inventory_complete": True, "verdict": verdict,
                      "failure_kind": failure_kind, "n_failed": harness["n_failed"],
                      "checks": normalized,
                      "failed_properties": normalized_failed,
                      "unsupported_constructs": normalized_unsupported})
    return {"run_state": "COMPLETE", "requested_roots": selectors, "roots": roots}


def Counter_status(rows):
    result = {"SUCCESS": 0, "FAILURE": 0, "UNREACHABLE": 0}
    for row in rows:
        require(row["status"] in result, "unknown regular status")
        result[row["status"]] += 1
    return result


def execute(kani, manifest, selectors, case_by_name, parent, run_id):
    directory = parent / run_id
    directory.mkdir()
    source = ROOT / manifest["source"]
    before = sha256(source)
    require(before == manifest["source_sha256"], "source hash differs from manifest")
    env = os.environ.copy()
    env["RUSTFLAGS"] = "--edition 2021 -D warnings"
    env["NO_COLOR"] = "1"
    argv = command(kani, manifest, selectors, directory)
    receipt = {"run_id": run_id, "selectors": selectors, "input": manifest["source"],
               "source_sha256": before, "build_prefix": str(ROOT), "cwd": str(ROOT),
               "argv": argv, "started_epoch": time.time(), "original_exit": None,
               "timed_out": False, "error": None, "snapshot_errors": {},
               "expected_exit": int(any(case_by_name[name]["expected_verdict"] == "FAILURE"
                                        for name in selectors))}
    process_error = None
    try:
        with (directory / "regular.out").open("wb") as output:
            result = subprocess.run(argv, cwd=ROOT,
                                    env=env, stdout=output, stderr=subprocess.STDOUT,
                                    check=False, timeout=180)
            # Preserve the original process result before any later filesystem work.
            receipt["original_exit"] = result.returncode
    except subprocess.TimeoutExpired as error:
        receipt["timed_out"] = True
        receipt["error"] = repr(error)
        process_error = ValueError(f"TIMEOUT after 180 seconds: {run_id}")
        process_error.__cause__ = error
    except OSError as error:
        receipt["error"] = repr(error)
        process_error = ValueError(f"PROCESS_START_OR_OUTPUT_ERROR: {run_id}: {error}")
        process_error.__cause__ = error
    finally:
        receipt["finished_epoch"] = time.time()
        for field, path in (("input_sha256_after", source),
                            ("export_sha256", directory / "export.json"),
                            ("regular_sha256", directory / "regular.out")):
            try:
                receipt[field] = sha256(path)
            except OSError as error:
                receipt[field] = None
                receipt["snapshot_errors"][field] = repr(error)
        (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if process_error is not None:
        raise process_error
    receipt["original_exit"] = result.returncode
    try:
        require("input_sha256_after" not in receipt["snapshot_errors"],
                f"SNAPSHOT_ERROR: {receipt['snapshot_errors']}")
        require(receipt["input_sha256_after"] == before,
                "INPUT_HASH_CHANGED during invocation")
        validate_process_result(result.returncode, receipt["expected_exit"])
        data = CHECKER.load_export(directory / "export.json")
        regular = (directory / "regular.out").read_text(errors="replace")
        observed = observation(data, regular, selectors, case_by_name, receipt)
        return observed, receipt
    except Exception as error:
        receipt["error"] = repr(error)
        (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kani", default="kani")
    parser.add_argument("--keep-output", action="store_true",
                        help="retain temporary exports and regular logs")
    parser.add_argument("--collect-unbound", action="store_true",
                        help="explicit pre-binding capture; prints complete observations and exits 2")
    args = parser.parse_args()
    return capture(args)


def capture(args):
    base = None
    step = "preflight"
    try:
        manifest = json.loads((HERE / "roots.json").read_text())
        cases = manifest["roots"]
        case_by_name = {case["name"]: case for case in cases}
        require(len(case_by_name) == len(cases), "duplicate manifest root")
        require(sha256(ROOT / manifest["source"]) == manifest["source_sha256"], "manifest source hash mismatch")
        binding_pending = any(case["binding"] != "REGRESSION_BOUND"
                              or not isinstance(case.get("expected_inventory"), list)
                              or not isinstance(case.get("expected_failures"), list)
                              or not isinstance(case.get("expected_unsupported_inventory"), list)
                              or case.get("expected_failure_kind") not in
                                  {"ERROR", "NONE", "OTHER", "PANICS_ONLY"}
                              for case in cases)
        require(not binding_pending or args.collect_unbound,
                "BINDING_PENDING: use --collect-unbound for pre-C1 evidence capture; no PASS credit")
        base = Path(tempfile.mkdtemp(prefix="kani-uninit-part1-composition-"))
        isolated = {}
        combined_observations = []
        receipts = []
        for case in cases:
            step = "isolated-" + case["name"] + ": execute/observe"
            result, receipt = execute(args.kani, manifest, [case["name"]], case_by_name,
                                      base, "isolated-" + case["name"])
            isolated[case["name"]] = result
            receipts.append(receipt)
            step = "isolated-" + case["name"] + ": compare/binding"
            isolated_root = compare_selection(result, {case["name"]: case})[case["name"]]
            if not binding_pending:
                check_single(isolated_root, {"binding": case["binding"],
                                             "expected_verdict": case["expected_verdict"],
                                             "checks": case["expected_inventory"],
                                             "failure_kind": case["expected_failure_kind"],
                                             "failed_properties": case["expected_failures"],
                                             "unsupported_constructs":
                                                 case["expected_unsupported_inventory"]})
        for order in manifest["orders"]:
            step = order["id"] + ": execute/observe"
            selected = order["selectors"]
            combined, receipt = execute(args.kani, manifest, selected, case_by_name,
                                        base, order["id"])
            receipts.append(receipt)
            combined_observations.append({"order": order["id"], "observation": combined})
            singles = {name: isolated[name] for name in selected}
            step = order["id"] + ": compare inventories"
            combined_by_name = compare_selection(combined, case_by_name)
            isolated_by_name = {name: compare_selection(singles[name], case_by_name)[name]
                                for name in selected}
            from compare import inventory
            for name in selected:
                require(inventory(isolated_by_name[name]) == inventory(combined_by_name[name]),
                        f"mixed-root inventory changed: {name} in {order['id']}")
        step = "write capture report"
        report = {"status": "UNBOUND_CAPTURE" if binding_pending else "PASS",
                  "binding_status": "BINDING_PENDING" if binding_pending else "REGRESSION_BOUND",
                  "root_inventory_observations": isolated,
                  "combined_inventory_observations": combined_observations,
                  "order_credit": "NOT_ESTABLISHED",
                  "producer_order": manifest["producer_order_receipt"]["status"],
                  "runs": receipts}
        (base / "capture.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print("Composition observation: " + json.dumps(report, sort_keys=True))
        # Exit 2 distinguishes useful capture from qualified regression success.
        return 2 if binding_pending else 0
    except (Exception, KeyboardInterrupt) as error:
        diagnostic = f"Composition stopped at {step}: {type(error).__name__}: {error}"
        print(diagnostic, file=sys.stderr, flush=True)
        saved_receipts = []
        if base is not None:
            for path in sorted(base.rglob("receipt.json")):
                try:
                    saved_receipts.append(json.loads(path.read_text()))
                except Exception as receipt_error:
                    saved_receipts.append({"receipt_path": str(path),
                                           "read_error": repr(receipt_error)})
        report = {"status": "FAIL", "step": step, "error": repr(error), "runs": saved_receipts}
        if base is not None:
            try:
                (base / "capture.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            except OSError as report_error:
                print(f"Could not save failure report: {report_error}", file=sys.stderr, flush=True)
        print("Composition observation: " + json.dumps(report, sort_keys=True), flush=True)
        if base is not None:
            for log in sorted(base.rglob("regular.out")):
                try:
                    for line in log.read_text(errors="replace").splitlines():
                        print(f"{log.parent.name}: {line}", flush=True)
                except OSError as log_error:
                    print(f"Could not read {log}: {log_error}", file=sys.stderr, flush=True)
        # Keep the reason visible at the end even when regular logs are very long.
        print(diagnostic, file=sys.stderr, flush=True)
        return 130 if isinstance(error, KeyboardInterrupt) else 1
    finally:
        if base is not None:
            if args.keep_output or args.collect_unbound:
                print(f"Retained mixed-root outputs: {base}", flush=True)
            else:
                import shutil
                shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
