#!/usr/bin/env python3
"""Conservatively curate selected CBMC JSON trace records using explicit bindings.

Schema is intentionally small and fail-closed. This does not infer runtime pointer
identity, offsets, or the last executed writer from CBMC variable names.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_RECORDS = 2048
MAX_RECORD_BYTES = 16 * 1024
MAX_ERRORS = 100
MAX_ERROR_CHARS = 256
MAX_PROPERTIES = 1024
MAX_FIELD_CHARS = 4096
IDENTITY_FIELDS = ("source", "stage", "target")
CATEGORIES = {"raw_eq_operand", "shadow_state", "pointer_witness_transition"}
STATUSES = {"FAILURE", "SUCCESS", "ERROR", "UNKNOWN", "NOT_CHECKED", "UNDETERMINED"}


class CuratorError(Exception):
    pass


class BoundedErrors(list[str]):
    def __init__(self) -> None:
        super().__init__()
        self.total = 0

    def append(self, message: str) -> None:
        self.total += 1
        if len(self) < MAX_ERRORS:
            super().append(message[:MAX_ERROR_CHARS])


def load_json(path: str) -> Any:
    p = Path(path)
    if p.stat().st_size > MAX_INPUT_BYTES:
        raise CuratorError(f"{path}: input exceeds {MAX_INPUT_BYTES} bytes")
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, UnicodeError, json.JSONDecodeError) as e:
        raise CuratorError(f"{path}: cannot read JSON: {e}") from e


def obj(value: Any, where: str, errors: list[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        errors.append(f"{where}: expected object")
        return {}
    return value


def nonempty_string(value: Any, where: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or not value:
        errors.append(f"{where}: expected non-empty string")
        return None
    if len(value) > MAX_FIELD_CHARS:
        errors.append(f"{where}: string exceeds {MAX_FIELD_CHARS} characters")
        return None
    return value


def identity(value: Any, where: str, errors: list[str]) -> dict[str, str]:
    data = obj(value, where, errors)
    result: dict[str, str] = {}
    for key in IDENTITY_FIELDS:
        val = nonempty_string(data.get(key), f"{where}.{key}", errors)
        if val is not None:
            result[key] = val
    return result


def source_location_matches(actual: Any, expected: Any, where: str, errors: list[str]) -> None:
    if not isinstance(actual, dict):
        errors.append(f"{where}: missing or non-object sourceLocation")
        return
    if not isinstance(expected, dict):
        errors.append(f"{where}: binding requires cbmc_source_location object")
        return
    if not expected or not any(isinstance(v, str) and v for v in expected.values()):
        errors.append(f"{where}: cbmc_source_location binding must name a source coordinate")
        return
    if any(field not in {"file", "function", "line", "column"} for field in expected):
        errors.append(f"{where}: cbmc_source_location contains unknown fields")
        return
    for field in ("file", "function", "line", "column"):
        if field in expected:
            if not isinstance(expected[field], str) or not expected[field]:
                errors.append(f"{where}: cbmc_source_location.{field} must be a non-empty string")
            elif actual.get(field) != expected[field]:
                errors.append(f"{where}: sourceLocation.{field} mismatch")


def cbmc_properties(document: Any, errors: list[str]) -> tuple[dict[str, dict[str, Any]], str | None]:
    if not isinstance(document, list):
        errors.append("cbmc: expected CBMC JSON UI top-level array")
        return {}, None
    result_events = [x for x in document if isinstance(x, dict) and "result" in x]
    status_events = [x for x in document if isinstance(x, dict) and "cProverStatus" in x]
    if len(result_events) != 1:
        errors.append("cbmc: expected exactly one complete result array")
    if len(status_events) != 1:
        errors.append("cbmc: expected exactly one cProverStatus completion event")
    status = None
    if len(status_events) == 1:
        status = nonempty_string(status_events[0].get("cProverStatus"), "cbmc.cProverStatus", errors)
    props: dict[str, dict[str, Any]] = {}
    if len(result_events) == 1:
        rows = result_events[0].get("result")
        if not isinstance(rows, list):
            errors.append("cbmc.result: expected array")
        else:
            for i, row in enumerate(rows):
                p = obj(row, f"cbmc.result[{i}]", errors)
                pid = nonempty_string(p.get("property"), f"cbmc.result[{i}].property", errors)
                if pid is None:
                    continue
                if pid in props:
                    errors.append(f"cbmc: duplicate property {pid}")
                    continue
                st = nonempty_string(p.get("status"), f"cbmc.{pid}.status", errors)
                if st is not None and st not in STATUSES:
                    errors.append(f"cbmc.{pid}.status: unsupported status {st!r}")
                desc = p.get("description")
                if not isinstance(desc, str):
                    errors.append(f"cbmc.{pid}.description: expected string")
                trace = p.get("trace")
                if trace is not None and not isinstance(trace, list):
                    errors.append(f"cbmc.{pid}.trace: expected array or absent")
                props[pid] = p
    return props, status


def trace_item_valid(item: Any, where: str, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(item, dict):
        errors.append(f"{where}: expected object")
        return None
    if not isinstance(item.get("stepType"), str):
        errors.append(f"{where}.stepType: expected string")
        return None
    if "lhs" in item and item["lhs"] is not None and not isinstance(item["lhs"], str):
        errors.append(f"{where}.lhs: expected string or null")
        return None
    if "sourceLocation" in item and item["sourceLocation"] is not None:
        loc = item["sourceLocation"]
        if not isinstance(loc, dict) or any(v is not None and (not isinstance(v, str) or len(v) > MAX_FIELD_CHARS) for v in loc.values()):
            errors.append(f"{where}.sourceLocation: expected object of strings/nulls")
            return None
    if "value" in item and item["value"] is not None and not trace_value_valid(item["value"], f"{where}.value", errors):
        return None
    return item


def trace_value_valid(value: Any, where: str, errors: list[str]) -> bool:
    """Validate the optional CBMC TraceValue shape consumed by Kani's parser."""
    if not isinstance(value, dict):
        errors.append(f"{where}: expected TraceValue object or null")
        return False
    binary, data, width, elements = (value.get(k) for k in ("binary", "data", "width", "elements"))
    if binary is not None and not isinstance(binary, str):
        errors.append(f"{where}.binary: expected string or null")
        return False
    if data is not None and not isinstance(data, (str, bool)):
        errors.append(f"{where}.data: expected string, boolean, or null")
        return False
    if width is not None and (not isinstance(width, int) or isinstance(width, bool) or width < 0):
        errors.append(f"{where}.width: expected non-negative integer or null")
        return False
    if elements is not None:
        if not isinstance(elements, list):
            errors.append(f"{where}.elements: expected array or null")
            return False
        for i, element in enumerate(elements):
            if not isinstance(element, dict) or "value" not in element:
                errors.append(f"{where}.elements[{i}]: expected object with value")
                return False
            if not trace_value_valid(element["value"], f"{where}.elements[{i}].value", errors):
                return False
    return True


def curate(cbmc: Any, manifest: Any, binding_doc: Any, input_sha256: str | None = None) -> tuple[dict[str, Any], bool]:
    errors = BoundedErrors()
    if input_sha256 is None:
        synthetic_bytes = json.dumps(cbmc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        input_sha256 = hashlib.sha256(synthetic_bytes).hexdigest()
    m = obj(manifest, "manifest", errors)
    bdoc = obj(binding_doc, "bindings", errors)
    expected_hash = nonempty_string(m.get("expected_trace_sha256"), "manifest.expected_trace_sha256", errors)
    binding_hash = nonempty_string(bdoc.get("expected_trace_sha256"), "bindings.expected_trace_sha256", errors)
    if expected_hash is not None and (len(expected_hash) != 64 or any(c not in "0123456789abcdef" for c in expected_hash)):
        errors.append("manifest.expected_trace_sha256: expected lowercase SHA256 hex")
    if binding_hash is not None and (len(binding_hash) != 64 or any(c not in "0123456789abcdef" for c in binding_hash)):
        errors.append("bindings.expected_trace_sha256: expected lowercase SHA256 hex")
    if expected_hash != input_sha256:
        errors.append("manifest expected trace SHA256 does not match original CBMC JSON bytes")
    if binding_hash != input_sha256:
        errors.append("bindings expected trace SHA256 does not match original CBMC JSON bytes")
    mid = identity(m.get("identity"), "manifest.identity", errors)
    bid = identity(bdoc.get("identity"), "bindings.identity", errors)
    if mid != bid:
        errors.append("bindings.identity does not match manifest identity")

    exits = obj(m.get("original_exits"), "manifest.original_exits", errors)
    solver_exit = exits.get("solver")
    verification_exit = exits.get("verification")
    if not isinstance(solver_exit, int) or isinstance(solver_exit, bool):
        errors.append("manifest.original_exits.solver: expected integer")
    if not (isinstance(verification_exit, (int, str)) and not isinstance(verification_exit, bool)):
        errors.append("manifest.original_exits.verification: expected integer or string")
    elif isinstance(verification_exit, str):
        verification_exit = verification_exit.upper()
        if verification_exit not in {"SUCCESS", "FAILURE", "ERROR", "TIMEOUT", "INCOMPLETE"}:
            errors.append("manifest.original_exits.verification: unsupported status label")
        if verification_exit in {"ERROR", "TIMEOUT", "INCOMPLETE"}:
            errors.append(f"original verification exit {verification_exit} is nonterminal")
    if isinstance(solver_exit, int) and not isinstance(solver_exit, bool) and solver_exit not in (0, 5, 10):
        errors.append(f"original solver exit {solver_exit} is nonterminal or unsupported")

    props, prover_status = cbmc_properties(cbmc, errors)
    expected_prover = nonempty_string(exits.get("cbmc_status"), "manifest.original_exits.cbmc_status", errors)
    if expected_prover is not None and expected_prover not in {"SUCCESS", "FAILURE"}:
        errors.append(f"original CBMC status {expected_prover} is nonterminal or unsupported")
    if expected_prover is None:
        pass
    elif prover_status is not None and prover_status != expected_prover:
        errors.append("CBMC cProverStatus does not match manifest original status")
    if isinstance(solver_exit, int) and not isinstance(solver_exit, bool):
        if solver_exit == 0 and prover_status != "SUCCESS":
            errors.append("solver exit 0 requires cProverStatus SUCCESS")
        elif solver_exit in (5, 10) and prover_status != "FAILURE":
            errors.append(f"solver exit {solver_exit} requires cProverStatus FAILURE")
        elif solver_exit == 5 and not any(
            p.get("status") in {"UNKNOWN", "UNDETERMINED", "NOT_CHECKED"} for p in props.values()
        ):
            errors.append("solver exit 5 requires an UNKNOWN/UNDETERMINED/NOT_CHECKED property")

    bindings = bdoc.get("properties")
    if not isinstance(bindings, dict) or not bindings:
        errors.append("bindings.properties: expected non-empty object")
        bindings = {}
    if len(bindings) > MAX_PROPERTIES:
        errors.append(f"bindings.properties exceeds {MAX_PROPERTIES} property cap")
        bindings = dict(list(bindings.items())[:MAX_PROPERTIES])
    reports: list[dict[str, Any]] = []
    emitted = dropped = 0
    coverage: dict[str, dict[str, Any]] = {}
    for pid, binding_value in bindings.items():
        if not isinstance(pid, str) or not pid or len(pid) > MAX_FIELD_CHARS:
            errors.append("bindings.properties contains invalid property id")
            continue
        where = f"bindings.properties[{pid!r}]"
        bind = obj(binding_value, where, errors)
        if bind.get("property_id") != pid:
            errors.append(f"{where}.property_id mismatch")
        for field in IDENTITY_FIELDS:
            if bind.get(field) != mid.get(field):
                errors.append(f"{where}.{field} does not match manifest identity")
        p = props.get(pid)
        if p is None:
            errors.append(f"bound property {pid} absent from CBMC result")
            continue
        source = bind.get("cbmc_source_location")
        source_location_matches(p.get("sourceLocation"), source, f"CBMC property {pid}", errors)
        status = p.get("status")
        if not isinstance(status, str) or status not in STATUSES:
            continue
        goto = nonempty_string(bind.get("goto_binding"), f"{where}.goto_binding", errors)
        trace_lhs = bind.get("trace_lhs")
        required = bind.get("required_trace_lhs")
        if not isinstance(trace_lhs, dict):
            errors.append(f"{where}.trace_lhs: expected category-to-symbols object")
            trace_lhs = {}
        normalized: dict[str, list[str]] = {}
        for category, symbols in trace_lhs.items():
            if category not in CATEGORIES:
                errors.append(f"{where}.trace_lhs: unknown category {category!r}")
            if not isinstance(symbols, list) or any(not isinstance(x, str) or not x for x in symbols):
                errors.append(f"{where}.trace_lhs.{category}: expected array of non-empty strings")
                continue
            normalized[category] = symbols
        if not isinstance(required, list) or any(not isinstance(x, str) or not x for x in required):
            errors.append(f"{where}.required_trace_lhs: expected array of non-empty strings")
            required = []
        if status == "FAILURE" and not required:
            errors.append(f"{where}.required_trace_lhs must identify required witness fields for a failure")
        known = {s for symbols in normalized.values() for s in symbols}
        if any(s not in known for s in required):
            errors.append(f"{where}.required_trace_lhs contains symbol without explicit category binding")
        record: dict[str, Any] = {
            "ordinal": -1,
            "step_type": p.get("stepType"),
            "lhs": p.get("lhs"),
            "source_location": p.get("sourceLocation"),
            "value": p.get("value"),
            "binding_category": "",
        }
        selected: list[dict[str, Any]] = []
        seen: set[str] = set()
        trace = p.get("trace")
        trace_complete = isinstance(trace, list)
        if status == "FAILURE":
            if not trace_complete or not trace:
                errors.append(f"CBMC property {pid}: failing property has no complete trace array")
                trace = []
            failure_positions = [i for i, raw in enumerate(trace)
                                 if isinstance(raw, dict) and raw.get("stepType") == "failure"]
            final_failure_valid = (
                bool(trace) and failure_positions == [len(trace) - 1]
                and isinstance(trace[-1], dict) and trace[-1].get("property") == pid
            )
            if not final_failure_valid:
                errors.append(f"CBMC property {pid}: trace must end with matching failure step/property")
                trace_complete = False
            for ordinal, raw in enumerate(trace):
                item = trace_item_valid(raw, f"CBMC property {pid}.trace[{ordinal}]", errors)
                if item is None:
                    trace_complete = False
                    continue
                lhs = item.get("lhs")
                category = next((cat for cat, names in normalized.items() if lhs in names), None)
                if category is None:
                    if item.get("stepType") != "failure":
                        dropped += 1
                    continue
                selected_record = {"ordinal": ordinal, "step_type": item["stepType"],
                                   "lhs": lhs, "source_location": item.get("sourceLocation"),
                                   "value": item.get("value"), "binding_category": category}
                size = len(json.dumps(selected_record, ensure_ascii=False, separators=(",", ":")).encode())
                if emitted >= MAX_RECORDS or size > MAX_RECORD_BYTES:
                    dropped += 1
                    trace_complete = False
                    continue
                selected.append(selected_record)
                if item.get("value") is not None:
                    seen.add(lhs)
                emitted += 1
            if final_failure_valid:
                failure_record = {"ordinal": len(trace) - 1, "step_type": "failure", "lhs": None,
                                  "source_location": trace[-1].get("sourceLocation"), "value": None,
                                  "property_id": pid, "binding_category": "property_failure"}
                if emitted < MAX_RECORDS:
                    selected.append(failure_record)
                    emitted += 1
                else:
                    dropped += 1
                    trace_complete = False
            selected.sort(key=lambda item: item["ordinal"])
        missing = sorted(set(required) - seen)
        if status == "FAILURE" and missing:
            errors.append(f"CBMC property {pid}: required trace symbols missing: {', '.join(missing)}")
        if status == "FAILURE" and not trace_complete and not missing:
            errors.append(f"CBMC property {pid}: curated trace is incomplete or capped")
        if status not in ("FAILURE", "SUCCESS"):
            errors.append(f"CBMC property {pid}: status {status} does not establish a failure or success")
        complete = status != "FAILURE" or (trace_complete and not missing)
        coverage[pid] = {"status": status, "trace_complete": complete,
                         "required_symbols": len(required), "observed_required_symbols": len(set(required) & seen),
                         "selected_records": len(selected), "missing_symbols": missing}
        reports.append({"property_id": pid, "status": status, "source_binding": {
            "source": mid.get("source"), "stage": mid.get("stage"), "target": mid.get("target"),
            "goto_binding": goto}, "runtime_witness": selected if status == "FAILURE" else "N/A",
            "runtime_witness_status": "CURATED_SUBSET" if status == "FAILURE" else "N/A",
            "causal_claim": False, "causal_data": "UNKNOWN" if status == "FAILURE" else "N/A"})

    unbound = sorted(set(props) - set(bindings))
    if unbound:
        errors.append(f"CBMC result contains {len(unbound)} unbound properties (sample: {', '.join(unbound[:10])})")
    report = {"schema_version": "kani3300-d0-curated-trace-v1", "identity": mid,
              "original_input_sha256": input_sha256,
              "original_exits": {"solver": solver_exit, "verification": verification_exit,
                                 "cbmc_status": expected_prover},
              "curated_properties": reports, "coverage": coverage,
              "records_emitted": emitted, "records_dropped": dropped,
              "record_cap": MAX_RECORDS, "byte_cap": MAX_OUTPUT_BYTES,
              "causal_claim": False, "error_count": errors.total,
              "errors": [e[:MAX_ERROR_CHARS] for e in errors[:MAX_ERRORS]],
              "unbound_property_count": len(unbound),
              "curator_status": "INCOMPLETE" if errors else "COMPLETE"}
    # Enforce the actual pretty-printed CLI representation, including metadata/errors.
    encoded = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    while len(encoded) > MAX_OUTPUT_BYTES and any(isinstance(x["runtime_witness"], list) and x["runtime_witness"] for x in reports):
        for item in reversed(reports):
            if isinstance(item["runtime_witness"], list) and item["runtime_witness"]:
                item["runtime_witness"].pop()
                report["records_emitted"] -= 1
                report["records_dropped"] += 1
                report["coverage"][item["property_id"]]["trace_complete"] = False
                report["curator_status"] = "INCOMPLETE"
                report["error_count"] += 1
                if len(report["errors"]) < MAX_ERRORS:
                    report["errors"].append("output byte cap reached; curated records truncated")
                break
        encoded = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        report["curated_properties"] = []
        report["coverage"] = {}
        report["records_dropped"] = report["records_emitted"] + report["records_dropped"]
        report["records_emitted"] = 0
        report["curator_status"] = "INCOMPLETE"
        report["error_count"] += 1
        report["errors"] = ["report metadata exceeded cap; details omitted"]
        encoded = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    return report, not errors and report["curator_status"] == "COMPLETE"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("cbmc_json", help="original complete CBMC --json-ui JSON")
    ap.add_argument("manifest", help="explicit run identity and original exit/status manifest")
    ap.add_argument("bindings", help="explicit source-stage-target/property/GOTO binding map")
    ap.add_argument("-o", "--output", required=True, help="curated JSON report path")
    args = ap.parse_args()
    try:
        raw = Path(args.cbmc_json).read_bytes()
        if len(raw) > MAX_INPUT_BYTES:
            raise CuratorError(f"{args.cbmc_json}: input exceeds {MAX_INPUT_BYTES} bytes")
        cbmc = json.loads(raw)
        report, complete = curate(cbmc, load_json(args.manifest), load_json(args.bindings), hashlib.sha256(raw).hexdigest())
    except (CuratorError, OSError, ValueError) as e:
        print(f"curator: {e}", file=sys.stderr)
        return 2
    data = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if len(data.encode("utf-8")) > MAX_OUTPUT_BYTES:
        print("curator: internal output cap failure", file=sys.stderr)
        return 2
    Path(args.output).write_text(data, encoding="utf-8")
    return 0 if complete else 2


if __name__ == "__main__":
    raise SystemExit(main())
