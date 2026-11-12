# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Create bounded, hash-bound property and GOTO inventories for a captured run.

Raw solver and inventory JSON remain in the private ``out`` directory. The
three JSON files intended for explicit handoff contain metadata only and fail
closed whenever a source/property/PC/operand binding is not established.
The JSON UI event arrays and instruction fields follow CBMC 6.11.0:
``src/goto-programs/show_properties.cpp``,
``src/goto-programs/show_goto_functions_json.cpp``, and
``src/util/ui_message.cpp`` at https://github.com/diffblue/cbmc/tree/cbmc-6.11.0.
"""
from __future__ import annotations

import hashlib
import json
import os
import selectors
import subprocess
import time
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_PROPERTIES = 1024
MAX_ERRORS = 100
MAX_TIMEOUT_SECONDS = 60
CAPTURE_SCHEMA = "kani3300-d0-cbmc-capture-v1"


class InventoryError(Exception):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: Path, cap: int = MAX_JSON_BYTES) -> Any:
    try:
        if path.stat().st_size > cap:
            raise InventoryError(f"{path.name}: exceeds {cap}-byte cap")
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InventoryError(f"{path.name}: invalid or unavailable JSON ({exc})") from exc


def _write_json(path: Path, value: Any) -> None:
    data = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(data) > 1024 * 1024:
        raise InventoryError(f"{path.name}: curated output exceeds 1 MiB")
    path.write_bytes(data)


def _bounded_run(argv: list[str], timeout: int = MAX_TIMEOUT_SECONDS) -> tuple[int | None, bytes, str | None]:
    """Run a read-only inventory command, retaining at most MAX_JSON_BYTES."""
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except OSError as exc:
        return None, b"", f"cannot start {Path(argv[0]).name}: {exc}"
    assert proc.stdout is not None
    out = bytearray()
    deadline = time.monotonic() + timeout
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    try:
        while True:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                proc.kill()
                proc.wait()
                return None, bytes(out), "inventory command timed out"
            if not selector.select(remaining_time):
                proc.kill()
                proc.wait()
                return None, bytes(out), "inventory command timed out"
            chunk = os.read(proc.stdout.fileno(), 64 * 1024)
            if not chunk:
                break
            remaining = MAX_JSON_BYTES + 1 - len(out)
            if remaining > 0:
                out.extend(chunk[:remaining])
            if len(out) > MAX_JSON_BYTES:
                proc.kill()
                proc.wait()
                return None, bytes(out[:MAX_JSON_BYTES]), "inventory output exceeded 64 MiB cap"
        try:
            return proc.wait(timeout=timeout), bytes(out), None
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return None, bytes(out), "inventory command timed out"
    finally:
        selector.close()
        proc.stdout.close()


def _solver_input(argv: Any, errors: list[str]) -> Path | None:
    if not isinstance(argv, list) or not argv or any(not isinstance(x, str) for x in argv):
        errors.append("capture argv missing or wrong type")
        return None
    if Path(argv[0]).name != "cbmc":
        errors.append("capture argv does not record invocation as cbmc")
        return None
    # kani-driver::cbmc_flags appends the goto file directly before
    # --verbosity 9, then regular output appends --json-ui. Require this
    # source-anchored layout; do not guess from suffix or nearby files.
    try:
        if len(argv) < 5 or argv[-1] != "--json-ui":
            raise ValueError
        marker = len(argv) - 3
        if argv[marker] != "--verbosity" or argv[marker + 1] != "9" or marker < 1:
            raise ValueError
        candidate = Path(argv[marker - 1])
        if candidate.name.startswith("-") or not candidate.is_file():
            raise ValueError
        return candidate.resolve(strict=True)
    except (ValueError, OSError):
        errors.append("could not establish exact solver input from kani-driver argv")
        return None


def _property_rows(doc: Any, errors: list[str]) -> dict[str, dict[str, Any]]:
    """Read the documented CBMC --show-properties JSON object conservatively."""
    if not isinstance(doc, list):
        errors.append("show-properties JSON UI: expected top-level event array")
        return {}
    events = [event for event in doc if isinstance(event, dict) and "properties" in event]
    if len(events) != 1:
        errors.append("show-properties JSON UI: expected exactly one properties event")
        return {}
    rows = events[0].get("properties")
    if not isinstance(rows, list):
        errors.append("show-properties JSON: missing properties array")
        return {}
    if len(rows) > MAX_PROPERTIES:
        errors.append("show-properties JSON exceeds 1,024-property cap")
        rows = rows[:MAX_PROPERTIES]
    found: dict[str, dict[str, Any]] = {}
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"show-properties[{i}]: expected object")
            continue
        pid = row.get("name")
        if not isinstance(pid, str) or not pid:
            errors.append(f"show-properties[{i}].name: missing property ID")
            continue
        if pid in found:
            errors.append(f"show-properties: duplicate property ID {pid[:100]}")
            continue
        found[pid] = row
    return found


def _solver_rows(doc: Any, errors: list[str]) -> tuple[dict[str, dict[str, Any]], str | None]:
    if not isinstance(doc, list):
        errors.append("solver JSON: expected CBMC JSON UI top-level array")
        return {}, None
    evs = [item for item in doc if isinstance(item, dict) and "result" in item]
    status_evs = [item for item in doc if isinstance(item, dict) and "cProverStatus" in item]
    if len(evs) != 1 or not isinstance(evs[0].get("result"), list):
        errors.append("solver JSON: missing or ambiguous complete result array")
        return {}, None
    if len(status_evs) != 1 or not isinstance(status_evs[0].get("cProverStatus"), str):
        errors.append("solver JSON: missing or ambiguous completion status")
        status = None
    else:
        status = status_evs[0]["cProverStatus"]
    props: dict[str, dict[str, Any]] = {}
    for i, row in enumerate(evs[0]["result"]):
        if not isinstance(row, dict) or not isinstance(row.get("property"), str) or not row["property"]:
            errors.append(f"solver result[{i}]: missing/wrong-type property ID")
            continue
        pid = row["property"]
        if pid in props:
            errors.append(f"solver JSON: duplicate property ID {pid[:100]}")
        else:
            props[pid] = row
    return props, status


SOURCE_LOCATION_FIELDS = ("file", "line", "column", "function", "propertyId", "propertyClass")


def _location_key(value: Any, where: str, errors: list[str]) -> tuple[tuple[str, str], ...] | None:
    if not isinstance(value, dict):
        errors.append(f"{where}: sourceLocation must be an object")
        return None
    result: list[tuple[str, str]] = []
    for field in SOURCE_LOCATION_FIELDS:
        item = value.get(field)
        if item is not None:
            if not isinstance(item, str) or not item:
                errors.append(f"{where}.{field}: expected non-empty string")
                return None
            result.append((field, item))
    present = dict(result)
    if not all(k in present for k in ("file", "line", "propertyId", "propertyClass")):
        errors.append(f"{where}: sourceLocation requires file, line, propertyId, and propertyClass")
        return None
    return tuple(result)


def _goto_functions(doc: Any, errors: list[str]) -> list[dict[str, Any]]:
    """Parse CBMC 6.11.0 JSON UI event array / show-goto-functions schema."""
    if not isinstance(doc, list):
        errors.append("show-goto-functions JSON UI: expected top-level event array")
        return []
    events = [event for event in doc if isinstance(event, dict) and "functions" in event]
    if len(events) != 1:
        errors.append("show-goto-functions JSON UI: expected exactly one functions event")
        return []
    functions = events[0].get("functions")
    if not isinstance(functions, list):
        errors.append("show-goto-functions.functions: expected array")
        return []
    if len(functions) > 200_000:
        errors.append("show-goto-functions exceeds 200,000-function cap")
        return []
    return [x for x in functions if isinstance(x, dict)]


def _property_pc_bindings(properties: dict[str, dict[str, Any]],
                          solver_props: dict[str, dict[str, Any]],
                          functions: list[dict[str, Any]],
                          errors: list[str]) -> dict[str, dict[str, Any]]:
    """Bind only unique assert instructions carrying the exact property ID."""
    result: dict[str, dict[str, Any]] = {}
    by_property: dict[str, list[dict[str, Any]]] = {}
    for function in functions:
        for instruction in function.get("instructions", []) if isinstance(function.get("instructions"), list) else []:
            loc = instruction.get("sourceLocation") if isinstance(instruction, dict) else None
            if isinstance(loc, dict) and isinstance(loc.get("propertyId"), str):
                by_property.setdefault(loc["propertyId"], []).append({"name": function.get("name"), "instructions": [instruction]})
    for pid, prop in properties.items():
        prop_loc = prop.get("sourceLocation")
        prop_key = _location_key(prop_loc, f"show-properties[{pid}].sourceLocation", errors)
        if not isinstance(prop_loc, dict) or prop_loc.get("propertyId") != pid:
            errors.append(f"show-properties[{pid}]: propertyId mismatch")
        solver = solver_props.get(pid)
        solver_loc = solver.get("sourceLocation") if isinstance(solver, dict) else None
        solver_key = _location_key(solver_loc, f"solver[{pid}].sourceLocation", errors)
        if prop_key is None or solver_key is None or prop_key != solver_key:
            errors.append(f"property {pid[:100]}: solver and show-properties sourceLocation mismatch")
            continue
        matches: list[dict[str, Any]] = []
        for function in by_property.get(pid, []):
            fname = function.get("name")
            instructions = function.get("instructions")
            if not isinstance(fname, str) or not isinstance(instructions, list):
                continue
            for instruction in instructions:
                if not isinstance(instruction, dict):
                    continue
                loc = instruction.get("sourceLocation")
                if not isinstance(loc, dict) or loc.get("propertyId") != pid:
                    continue
                ins_text = instruction.get("instruction")
                pc = instruction.get("locationNumber")
                ins_key = _location_key(loc, f"GOTO {fname} sourceLocation", errors)
                if (not isinstance(ins_text, str) or not ins_text.startswith("ASSERT ")
                        or (not isinstance(pc, (str, int)) or isinstance(pc, bool))
                        or ins_key != prop_key):
                    continue
                labels = instruction.get("labels", [])
                targets = instruction.get("targets", [])
                code = instruction.get("code")
                guard = instruction.get("guard")
                if not isinstance(labels, list) or any(not isinstance(x, str) for x in labels):
                    errors.append(f"GOTO {fname} PC {pc}: labels malformed")
                    continue
                if not isinstance(targets, list) or any(not isinstance(x, (str, int)) or isinstance(x, bool) for x in targets):
                    errors.append(f"GOTO {fname} PC {pc}: targets malformed")
                    continue
                if len(json.dumps({"code": code, "guard": guard}, separators=(",", ":")).encode("utf-8")) > 16 * 1024:
                    errors.append(f"GOTO {fname} PC {pc}: assertion code exceeds 16 KiB record cap")
                    continue
                matches.append({"function": fname, "pc": str(pc), "labels": labels,
                                "instruction": ins_text, "code": code, "guard": guard,
                                "targets": [str(x) for x in targets],
                                "source_location": {k: loc[k] for k in SOURCE_LOCATION_FIELDS if k in loc}})
        if len(matches) != 1:
            errors.append(f"property {pid[:100]}: expected one exact GOTO assertion PC, found {len(matches)}")
            continue
        result[pid] = matches[0]
    return result


def _root_binding(raw_path: Path, goto_input: Path | None, input_hash: str | None,
                  errors: list[str]) -> dict[str, str] | None:
    """Bind solver input to the runner-recorded actual harness metadata row."""
    roots_path = raw_path.parent.parent / "roots.json"
    try:
        roots_doc = _load_json(roots_path, 1024 * 1024)
    except InventoryError as exc:
        errors.append(f"roots mapping unavailable: {exc}")
        return None
    if not isinstance(roots_doc, list) or not all(isinstance(x, dict) for x in roots_doc):
        errors.append("roots mapping must be an array of harness metadata rows")
        return None
    matches: list[dict[str, str]] = []
    for row in roots_doc:
        solver_input = row.get("solver_input")
        solver_hash = row.get("solver_input_sha256")
        pretty = row.get("pretty_name")
        mangled = row.get("mangled_name")
        metadata_file = row.get("metadata_file")
        metadata_hash = row.get("metadata_sha256")
        if not all(isinstance(x, str) and x for x in
                   (solver_input, solver_hash, pretty, mangled, metadata_file, metadata_hash)):
            continue
        try:
            resolved = Path(solver_input).resolve(strict=True)
        except OSError:
            continue
        if goto_input is not None and resolved == goto_input and solver_hash == input_hash:
            try:
                meta_path = Path(metadata_file).resolve(strict=True)
                if _sha256(meta_path) != metadata_hash:
                    errors.append(f"roots mapping {pretty}: metadata SHA256 mismatch")
                    continue
            except OSError:
                errors.append(f"roots mapping {pretty}: metadata file unavailable")
                continue
            matches.append({"pretty_name": pretty, "mangled_name": mangled,
                            "solver_input": str(resolved), "solver_input_sha256": solver_hash,
                            "metadata_file": str(meta_path), "metadata_sha256": metadata_hash})
    if len(matches) != 1:
        errors.append(f"roots mapping: expected one exact harness/input row, found {len(matches)}")
        return None
    return matches[0]


def generate(raw_path: Path, meta_path: Path, source: str, case: str,
             verification_exit: int, cbmc: str, goto_instrument: str,
             out: Path) -> dict[str, Any]:
    """Inventory the actual captured GOTO input and write bounded artifacts.

    The raw solver capture and complete inventory command output are retained
    only in ``out``. If a binding cannot be established without inference, the
    returned result is INCOMPLETE and the curated bindings state UNKNOWN.
    """
    raw_path, meta_path, out = Path(raw_path), Path(meta_path), Path(out)
    out.mkdir(parents=True, exist_ok=True)
    errors: list[str] = []
    original_exits: dict[str, Any] = {"solver": None, "verification": verification_exit,
                                      "property_inventory": None, "goto_inventory": None,
                                      "curation": None}
    identity = {"source": source if isinstance(source, str) else "UNKNOWN",
                "stage": "solver-json", "target": f"{case}:solver-input-UNKNOWN"}
    input_hash: str | None = None
    inventory_hashes: dict[str, str | None] = {"properties": None, "goto_functions": None}
    solver_props: dict[str, dict[str, Any]] = {}
    cbmc_status: str | None = None
    properties: dict[str, dict[str, Any]] = {}
    goto_doc: Any = None

    if not isinstance(source, str) or not source:
        errors.append("source must be a non-empty source identity string")
    elif len(source) != 40 or any(char not in "0123456789abcdef" for char in source):
        errors.append("source must be a lowercase 40-character Git SHA1 identity")
    if not isinstance(case, str) or not case:
        errors.append("case must be a non-empty string")
    elif case not in {"A", "B", "AB", "BA", "D", "pair"}:
        errors.append("case is not one of the requested diagnostic cases")
    if not isinstance(verification_exit, int) or isinstance(verification_exit, bool):
        errors.append("verification_exit must be an integer")
    try:
        metadata = _load_json(meta_path, 1024 * 1024)
    except InventoryError as exc:
        errors.append(str(exc))
        metadata = {}
    if not isinstance(metadata, dict):
        errors.append("capture metadata: expected object")
        metadata = {}
    if metadata.get("schema_version") != CAPTURE_SCHEMA:
        errors.append("capture metadata schema mismatch")
    if metadata.get("capture_state") != "COMPLETE":
        errors.append("capture_state is not COMPLETE")
    if metadata.get("captured_complete") is not True:
        errors.append("captured_complete is not true")
    dropped_bytes = metadata.get("dropped_bytes")
    if not isinstance(dropped_bytes, int) or isinstance(dropped_bytes, bool) or dropped_bytes != 0:
        errors.append("capture has dropped bytes or wrong-typed dropped_bytes")
    if metadata.get("child_signal") is not None or metadata.get("wrapper_signal") is not None:
        errors.append("capture records a signal")
    child_exit = metadata.get("child_exit")
    if not isinstance(child_exit, int) or isinstance(child_exit, bool):
        errors.append("capture child_exit missing or wrong type")
    original_exits["solver"] = child_exit

    try:
        raw_size = raw_path.stat().st_size
        if raw_size > MAX_INPUT_BYTES:
            errors.append("captured solver JSON exceeds 64 MiB cap")
        raw_hash = _sha256(raw_path)
    except OSError as exc:
        errors.append(f"captured solver JSON unavailable: {exc}")
        raw_hash = None
    if raw_hash is not None:
        if metadata.get("original_stdout_sha256") != raw_hash:
            errors.append("capture metadata SHA256 does not match retained solver JSON")
        retained_bytes = metadata.get("retained_bytes")
        if not isinstance(retained_bytes, int) or isinstance(retained_bytes, bool) or retained_bytes != raw_size:
            errors.append("capture retained_bytes does not match solver JSON size")
        if metadata.get("retained_stdout_file") != raw_path.name:
            errors.append("capture retained filename does not match supplied solver JSON")
    if child_exit not in (0, 10):
        errors.append("solver exit is not a completed 0/10 result")

    goto_input = _solver_input(metadata.get("argv"), errors)
    if goto_input is not None:
        try:
            input_hash = _sha256(goto_input)
        except OSError as exc:
            errors.append(f"cannot hash exact solver input: {exc}")
            goto_input = None
    root = _root_binding(raw_path, goto_input, input_hash, errors)
    if root is not None:
        identity["target"] = f"{case}:{root['pretty_name']}:{input_hash}"

    try:
        solver_doc = _load_json(raw_path)
    except InventoryError as exc:
        errors.append(str(exc))
        solver_doc = None
    solver_props, cbmc_status = _solver_rows(solver_doc, errors)
    if not solver_props:
        errors.append("solver JSON contains no property results")
    if cbmc_status not in ("SUCCESS", "FAILURE"):
        errors.append("solver cProverStatus missing or unsupported")
    if isinstance(child_exit, int) and not isinstance(child_exit, bool):
        if child_exit == 0 and cbmc_status != "SUCCESS":
            errors.append("solver exit 0 disagrees with cProverStatus")
        elif child_exit == 10 and cbmc_status != "FAILURE":
            errors.append("nonzero solver exit disagrees with cProverStatus")

    if goto_input is not None and isinstance(cbmc, str) and cbmc and isinstance(goto_instrument, str) and goto_instrument:
        commands = (
            ("properties", [cbmc, "--show-properties", "--json-ui", str(goto_input)], "properties.inventory.json"),
            ("goto_functions", [goto_instrument, "--show-goto-functions", "--json-ui", str(goto_input)], "goto-functions.inventory.json"),
        )
        parsed: dict[str, Any] = {}
        for key, argv, filename in commands:
            exit_code, stdout, run_error = _bounded_run(argv)
            original_exits["property_inventory" if key == "properties" else "goto_inventory"] = exit_code
            private_path = out / filename
            try:
                private_path.write_bytes(stdout)
                inventory_hashes[key] = hashlib.sha256(stdout).hexdigest()
            except OSError as exc:
                errors.append(f"cannot retain private {key} inventory: {exc}")
            if run_error:
                errors.append(f"{key} command: {run_error}")
            if exit_code != 0:
                errors.append(f"{key} command exited {exit_code}")
            try:
                parsed[key] = json.loads(stdout.decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                errors.append(f"{key} command produced invalid JSON ({exc})")
                parsed[key] = None
        properties = _property_rows(parsed.get("properties"), errors)
        goto_doc = parsed.get("goto_functions")
        functions = _goto_functions(goto_doc, errors)
    else:
        errors.append("inventory commands not run: exact input or tool path unavailable")
        functions = []

    if solver_props and properties:
        missing = sorted(set(solver_props) - set(properties))
        extra = sorted(set(properties) - set(solver_props))
        if missing:
            errors.append("solver result IDs absent from show-properties inventory")
        if extra:
            errors.append("show-properties IDs absent from solver result inventory")
    elif solver_props or properties:
        errors.append("cannot compare solver and show-properties inventories")

    pc_bindings = _property_pc_bindings(properties, solver_props, functions, errors)

    bindings_properties: dict[str, Any] = {}
    inventory_properties: list[dict[str, Any]] = []
    solver_indices = {pid: ordinal for ordinal, pid in enumerate(solver_props)}
    inventory_indices = {pid: ordinal for ordinal, pid in enumerate(properties)}
    for pid in sorted(set(solver_props) | set(properties))[:MAX_PROPERTIES]:
        row = properties.get(pid, {})
        result = solver_props.get(pid, {})
        verdict = result.get("status") if isinstance(result, dict) else None
        source_loc = row.get("sourceLocation", row.get("source_location")) if isinstance(row, dict) else None
        pc_binding = pc_bindings.get(pid) if root is not None else None
        if pc_binding is None:
            goto_binding = None
            binding_status = "UNKNOWN"
            binding_error = "exact assertion PC/source binding unavailable"
        else:
            goto_binding = f"{pc_binding['function']}#pc={pc_binding['pc']}"
            binding_status = "STATIC_COMPLETE"
            binding_error = None
        binding = {
            "property_id": pid,
            "solver_result_index": solver_indices.get(pid), "property_inventory_index": inventory_indices.get(pid),
            "source": identity["source"], "stage": identity["stage"], "target": identity["target"],
            "cbmc_source_location": ({k: source_loc[k] for k in ("file", "function", "line", "column")
                                      if isinstance(source_loc, dict) and k in source_loc}),
            "result_status": verdict if isinstance(verdict, str) else "UNKNOWN",
            "goto_binding": goto_binding,
            "goto_pc_chain": pc_binding if pc_binding is not None else "UNKNOWN",
            "trace_lhs": {"raw_eq_operand": [], "shadow_state": [], "pointer_witness_transition": []},
            "required_trace_lhs": [],
            "binding_status": binding_status,
            "binding_error": binding_error,
        }
        if verdict == "FAILURE":
            binding["unknown_witness"] = {
                "status": "UNKNOWN", "source_operand": "UNKNOWN", "source_origin": "UNKNOWN",
                "goto_symbol": "UNKNOWN", "runtime_pointer": "UNKNOWN",
                "tracked_object": "UNKNOWN", "last_executed_transition": "UNKNOWN",
                "reason": "requires complete trace plus explicit operand/edge and runtime-symbol binding",
            }
        bindings_properties[pid] = binding
        inventory_properties.append({"property_id": pid,
                                     "solver_result_index": solver_indices.get(pid), "property_inventory_index": inventory_indices.get(pid),
                                     "description": row.get("description") if isinstance(row.get("description"), str) else None,
                                     "class": row.get("class") if isinstance(row.get("class"), str) else None,
                                     "source_location": source_loc if isinstance(source_loc, dict) else "UNKNOWN",
                                     "result_status": verdict if isinstance(verdict, str) else "UNKNOWN"})
        if pc_binding is None:
            errors.append(f"property {pid[:100]}: exact assertion PC/source binding unavailable")
        if verdict == "FAILURE":
            errors.append(f"property {pid[:100]} failed: runtime operand and edge witness unavailable")
        if not isinstance(verdict, str):
            errors.append(f"property {pid[:100]} has missing/wrong-type result status")
    if len(solver_props) > MAX_PROPERTIES or len(properties) > MAX_PROPERTIES:
        errors.append("property inventory exceeds 1,024-property cap")

    manifest = {
        "schema_version": "kani3300-d0-inventory-v1", "identity": identity,
        "case": case if isinstance(case, str) else "UNKNOWN", "capture": {
            "state": metadata.get("capture_state", "UNKNOWN"), "solver_json_sha256": raw_hash,
            "solver_json_bytes": raw_size if "raw_size" in locals() else None,
            "input_sha256": input_hash, "input_path": str(goto_input) if goto_input else None,
            "argv": metadata.get("argv") if isinstance(metadata.get("argv"), list) else "UNKNOWN",
        },
        "root": root if root is not None else "UNKNOWN",
        "original_exits": {**original_exits, "cbmc_status": cbmc_status},
        "inventories": {"sha256": inventory_hashes, "property_count": len(properties),
                        "goto_functions_type": type(goto_doc).__name__ if goto_doc is not None else "UNKNOWN"},
        "expected_trace_sha256": raw_hash,
        "property_count": len(solver_props), "errors": errors[:MAX_ERRORS],
        "status": "COMPLETE" if not errors else "INCOMPLETE",
    }
    provenance = {"request": "g0:5956660766:kani3300/d0/CI-REQUEST.md",
                  "workflow_commit": os.environ.get("GITHUB_SHA", "UNKNOWN"),
                  "capture_meta_file": meta_path.name, "capture_meta_sha256": _sha256(meta_path) if meta_path.is_file() else "UNKNOWN",
                  "solver_file": raw_path.name, "solver_sha256": raw_hash,
                  "emitted": len(inventory_properties),
                  "dropped": max(0, len(set(solver_props) | set(properties)) - len(inventory_properties)),
                  "filtered": 0, "coverage": {"phase": "solver-json", "root": root,
                      "properties": len(solver_props), "static_pc_bindings": len(pc_bindings),
                      "runtime_operand_binding": "UNKNOWN", "instance_binding": "UNKNOWN"}}
    manifest["provenance"] = provenance
    all_static = bool(bindings_properties) and all(
        p["binding_status"] == "STATIC_COMPLETE" for p in bindings_properties.values())
    all_success = bool(bindings_properties) and all(
        p["result_status"] == "SUCCESS" for p in bindings_properties.values())
    bindings = {"identity": identity, "expected_trace_sha256": raw_hash, "provenance": provenance,
                "properties": bindings_properties,
                "status": "COMPLETE" if all_static and all_success else "INCOMPLETE"}
    prop_inventory = {"identity": identity, "properties": inventory_properties, "provenance": provenance,
                      "status": "COMPLETE" if not errors else "INCOMPLETE"}
    try:
        _write_json(out / "manifest.json", manifest)
        _write_json(out / "bindings.json", bindings)
        _write_json(out / "property-inventory.json", prop_inventory)
    except (OSError, InventoryError) as exc:
        errors.append(str(exc))
        manifest["errors"] = errors[:MAX_ERRORS]
        manifest["status"] = "INCOMPLETE"
        return {"status": "INCOMPLETE", "errors": errors[:MAX_ERRORS],
                "original_exits": {**original_exits, "cbmc_status": cbmc_status},
                "input_sha256": input_hash}
    curator = Path(__file__).with_name("curate_cbmc_trace.py")
    if raw_hash is None or not curator.is_file():
        errors.append("curator unavailable or solver capture hash missing")
        curation_exit = None
    else:
        curation_exit, _, curation_error = _bounded_run([
            os.environ.get("PYTHON", "python3"), str(curator), str(raw_path),
            str(out / "manifest.json"), str(out / "bindings.json"),
            "--output", str(out / "curated.json")], timeout=MAX_TIMEOUT_SECONDS)
        if curation_error:
            errors.append(f"curation command: {curation_error}")
        original_exits["curation"] = curation_exit
        if curation_exit != 0:
            errors.append(f"curation exited {curation_exit}; handoff remains incomplete")
        try:
            report = _load_json(out / "curated.json", 1024 * 1024)
            if not isinstance(report, dict):
                raise InventoryError("curated report must be an object")
            report_exits = report.get("original_exits")
            report["provenance"] = provenance
            if isinstance(report_exits, dict):
                report_exits.update({"property_inventory": original_exits["property_inventory"],
                                     "goto_inventory": original_exits["goto_inventory"],
                                     "curation": curation_exit})
            _write_json(out / "curated.json", report)
        except InventoryError as exc:
            errors.append(f"curated report unavailable: {exc}")
    manifest["original_exits"]["curation"] = curation_exit
    manifest["errors"] = errors[:MAX_ERRORS]
    manifest["status"] = "COMPLETE" if not errors else "INCOMPLETE"
    try:
        _write_json(out / "manifest.json", manifest)
    except (OSError, InventoryError) as exc:
        errors.append(str(exc))
    return {"status": manifest["status"], "errors": errors[:MAX_ERRORS],
            "original_exits": {**original_exits, "cbmc_status": cbmc_status}, "input_sha256": input_hash,
            "property_count": len(solver_props)}
