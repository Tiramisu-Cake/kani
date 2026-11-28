"""Bounded projection of a SmallSort singleton or native multi-root batch.

All fields are observations from regular stdout, stock JSON, and the resource
supervisor. This module never assigns proof credit.
"""
from __future__ import annotations

from collections import Counter
from importlib.util import module_from_spec, spec_from_file_location
import json
import math
from pathlib import Path
import re

import native_metrics
import request as spec

HERE = Path(__file__).resolve().parent
PARSER = spec_from_file_location("cal1_native_evidence", HERE.parent / "ch8-kani5196-control" / "evidence.py")
evidence = module_from_spec(PARSER)
PARSER.loader.exec_module(evidence)

COPY_BACK_PROPERTIES = {
    "safety_check.1": "`src` must be properly aligned",
    "safety_check.2": "`dst` must be properly aligned",
    "arithmetic_overflow.1": "copy_nonoverlapping: attempt to compute number in bytes which would overflow",
    "precondition_instance.1": "memcpy src/dst overlap",
    "precondition_instance.2": "memcpy source region readable",
    "precondition_instance.3": "memcpy destination region writeable",
}
COPY_BACK_INSTANCE = "ptr::copy_nonoverlapping::<u8>"
INSERT_COPY_INSTANCE = "ptr::copy_nonoverlapping::<u64>"
COPY_BACK_COORDINATE = ("core/src/ptr/mod.rs", 587, 14)

MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_PROJECTION_BYTES = 4 * 1024 * 1024
STDOUT_LIMIT = 16 * 1024 * 1024
STDERR_LIMIT = 4 * 1024 * 1024
COPY_BACK_SLOT_IDS = frozenset((*spec.COPY_BACK_SLOT_IDS, *spec.CONSUMER_SLOT_IDS,
                                *spec.U64_N26_N32_CONSUMER_SLOT_IDS))
LEGACY_COPY_BACK_SLOT_IDS = frozenset((*spec.COPY_BACK_SLOT_IDS, *spec.CONSUMER_SLOT_IDS))
U64_SLOT_IDS = frozenset((*spec.U64_N13_SLOT_IDS, *spec.U64_N14_N17_SLOT_IDS,
                          *spec.U64_N18_N19_SLOT_IDS, *spec.U64_N22_N25_PROVIDER_SLOT_IDS,
                          *spec.U64_N26_N32_PROVIDER_SLOT_IDS, *spec.U64_N26_N32_CONSUMER_SLOT_IDS))
U64_CHECK_TARGETS = (spec.U64_N18_N19_CHECK_TARGETS | spec.U64_N22_N25_PROVIDER_CHECK_TARGETS
                     | spec.PROVIDER_CHECK_TARGETS)
U64_PLAIN_IDS = U64_SLOT_IDS.difference(U64_CHECK_TARGETS)
U64_N26_N32_CHECK_IDS = frozenset(spec.PROVIDER_CHECK_TARGETS)
U64_N26_N32_PROVIDER_PLAIN_IDS = frozenset(spec.U64_N26_N32_PROVIDER_SLOT_IDS).difference(U64_N26_N32_CHECK_IDS)
U64_N26_N32_CONSUMER_IDS = frozenset(spec.U64_N26_N32_CONSUMER_SLOT_IDS)
U64_N26_N32_PLAIN_IDS = U64_N26_N32_PROVIDER_PLAIN_IDS | U64_N26_N32_CONSUMER_IDS
PILOT_SLOT_IDS = frozenset(spec.PILOT_SLOT_IDS)
PILOT_CHECK_TARGETS = spec.PILOT_CHECK_TARGETS
PILOT_CHECK_IDS = frozenset(PILOT_CHECK_TARGETS)
PILOT_PLAIN_IDS = PILOT_SLOT_IDS - PILOT_CHECK_IDS
PILOT_MODULE_FILE = spec.PILOT_MODULE_FILE
PILOT_PREFIX = spec.PILOT_PREFIX
FIX1_SLOT_IDS = frozenset(spec.FIX1_SLOT_IDS)
CLOSE_SLOT_IDS = frozenset((*spec.CLOSE_SLOT_IDS, *spec.WITNESS_SLOT_IDS))
FIX1_CHECK_TARGETS = spec.FIX1_CHECK_TARGETS
WIDE_N12_N14_CHECK_IDS = frozenset(spec.WIDE_N12_N14_CHECK_SLOT_IDS)
N32_CHECK_IDS = frozenset(spec.N32_CHECK_SLOT_IDS)
N32_PLAIN_IDS = frozenset(spec.N32_PLAIN_SLOT_IDS)
N32_SLOT_IDS = N32_CHECK_IDS | N32_PLAIN_IDS
N32_CLOSURE_IDS = frozenset(spec.N32_CLOSURE_SLOT_IDS)
WIDE_TYPE = f"{spec.PILOT_PREFIX}Wide"
# Each family binds one exact Check target, one scoped write, one actual directional copy site and its copy type.
SPLIT_MERGE_CHECKS = {
    **{slot: (spec.FIX1_PREFIX, FIX1_CHECK_TARGETS[slot], spec.FIX1_MODIFIES[slot],
              885 if slot == "GEN-N16-WIDE-S48-MERGE-UP" else 918, spec.FIX1_CHECKS, WIDE_TYPE)
       for slot in spec.FIX1_SLOT_IDS},
    **{slot: (spec.WIDE_N12_N14_PREFIX, spec.WIDE_N12_N14_CHECK_TARGETS[slot], spec.WIDE_N12_N14_MODIFIES[slot],
              spec.WIDE_N12_N14_COPY_LINES[direction], spec.WIDE_N12_N14_CHECKS, WIDE_TYPE)
       for slot, (_, direction) in spec.WIDE_N12_N14_CHECK_GEOMETRY.items()},
    **{slot: (spec.N32_PREFIX, spec.N32_CHECK_TARGETS[slot], spec.N32_MODIFIES[slot], spec.N32_COPY_LINES[role],
              spec.N32_CHECKS, "u64" if kind == "u64" else WIDE_TYPE)
       for slot, (kind, role) in spec.N32_GEOMETRY.items() if slot in spec.N32_CHECK_TARGETS},
}
PILOT_U64_SLOT_IDS = frozenset({
    "GEN-N16-S8-R32-FULL", "GEN-N16-S8-R32-BITS", "GEN-N16-U64-S32-MERGE-PAIR",
})
PILOT_ASSIGNS_PROPERTIES = {
    "memcpy.assigns.1": ("assigns", None, "<builtin-library-memcpy>", 46, None, None),
    "memcpy.assigns.2": ("assigns", None, "<builtin-library-memcpy>", 47, None, None),
}
FIX1_WRAPPER_SUFFIXES = ("_READ", "_WRITE", "_DISJOINT", "_CURSORS")
PILOT_SORT4_COPY_SITES = [
    {"file": spec.SMALLSORT_FILE, "line": 832, "column": 9,
     "token": "ptr::copy_nonoverlapping(min, dst, 1);"},
    {"file": spec.SMALLSORT_FILE, "line": 833, "column": 9,
     "token": "ptr::copy_nonoverlapping(lo, dst.add(1), 1);"},
    {"file": spec.SMALLSORT_FILE, "line": 834, "column": 9,
     "token": "ptr::copy_nonoverlapping(hi, dst.add(2), 1);"},
    {"file": spec.SMALLSORT_FILE, "line": 835, "column": 9,
     "token": "ptr::copy_nonoverlapping(max, dst.add(3), 1);"},
]
PILOT_MERGE_COPY_SITES = [
    {"file": spec.SMALLSORT_FILE, "line": 885, "column": 9,
     "token": "ptr::copy_nonoverlapping(src, dst, 1);"},
    {"file": spec.SMALLSORT_FILE, "line": 918, "column": 9,
     "token": "ptr::copy_nonoverlapping(src, dst, 1);"},
]
PILOT_FILL_COPY_SITES = [
    {"file": PILOT_MODULE_FILE, "line": 236, "column": 9,
     "token": "ptr::copy_nonoverlapping(s.add(12), d.add(12), 1);",
     "transcribes": {"file": spec.SMALLSORT_FILE, "line": 329, "column": 17,
                     "token": "ptr::copy_nonoverlapping(src.add(i), dst.add(i), 1);"}},
    {"file": spec.SMALLSORT_FILE, "line": 722, "column": 13,
     "token": "ptr::copy_nonoverlapping(sift, gap_guard.dst, 1);"},
    {"file": spec.SMALLSORT_FILE, "line": 362, "column": 13,
     "token": "ptr::copy_nonoverlapping(self.src, self.dst, self.len);"},
]
U64_COPY_PROPERTIES = {
    "ptr::copy::<u64>.safety_check.1": ("safety_check", "`src` must be properly aligned", "core/src/ptr/mod.rs", 682, 9),
    "ptr::copy::<u64>.safety_check.2": ("safety_check", "`dst` must be properly aligned", "core/src/ptr/mod.rs", 682, 9),
    "ptr::copy::<u64>.arithmetic_overflow.1": ("arithmetic_overflow", "copy: attempt to compute number in bytes which would overflow", "core/src/ptr/mod.rs", 682, 9),
    "ptr::copy::<u64>.precondition_instance.1": ("precondition_instance", "memmove source region readable", "core/src/ptr/mod.rs", 682, 9),
    "ptr::copy::<u64>.precondition_instance.2": ("precondition_instance", "memmove destination region writeable", "core/src/ptr/mod.rs", 682, 9),
    **{f"ptr::copy_nonoverlapping::<u64>.{key}": (key.split(".")[0], value, "core/src/ptr/mod.rs", 587, 14)
       for key, value in COPY_BACK_PROPERTIES.items()},
}
INSERT_SLOT_IDS = {spec.INSERT_SLOT_ID, "U64-N19-INSERT-RIGHT", *spec.U64_N20_N21_INSERT_GEOMETRIES,
                   *spec.INSERT_GEOMETRIES}
SWAP_SLOT_IDS = {*spec.U64_N13_SLOT_IDS, "U64-S9-B10-SWAP", "U64-S9-B11-SWAP",
                 spec.SWAP_SLOT_ID, spec.S13_SWAP_SLOT_ID}
SORT9_SLOT_IDS = frozenset((*spec.U64_N18_N19_SORT9_GEOMETRIES, "U64-S9-B11-L11-BITS",
                            *spec.SORT9_GEOMETRIES, spec.S13_BITS_SLOT_ID))
BOUND_SLOT_IDS = COPY_BACK_SLOT_IDS.union(spec.MERGE_SLOT_IDS, U64_SLOT_IDS, PILOT_SLOT_IDS, FIX1_SLOT_IDS, CLOSE_SLOT_IDS,
                                          WIDE_N12_N14_CHECK_IDS, N32_SLOT_IDS, N32_CLOSURE_IDS)
EXPECTED_FEATURES = {"unstable-options", "export-json", *spec.STOCK_Z}
NUMBER = r"(\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)"
TIMINGS = {
    "native_vt_seconds": re.compile(r"^Verification Time: " + NUMBER + r"s$"),
    "symex_seconds": re.compile(r"^Runtime Symex: " + NUMBER + r"s$"),
    "ssa_seconds": re.compile(r"^Runtime Convert SSA: " + NUMBER + r"s$"),
    "sat_seconds": re.compile(r"^Runtime Solver: " + NUMBER + r"s$"),
    "decision_procedure_seconds": re.compile(r"^Runtime decision procedure: " + NUMBER + r"s$"),
}
CARGO_TIME = re.compile(r"^Finished .+ profile .+ in (?:(\d+)m\s+)?" + NUMBER + r"s$")
PHASE_MARKERS = (
    ("harness-selected", re.compile(r"^Checking harness .+\.\.\.$")),
    ("symex", re.compile(r"^Starting Bounded Model Checking$")),
    ("ssa", re.compile(r"^converting SSA.*$")),
    ("sat", re.compile(r"^(?:Solving with|Running (?:propositional reduction|.*CaDiCaL)).*$")),
    ("complete", re.compile(r"^Verification Time: " + NUMBER + r"s$")),
)


def _pilot_copy_expected(type_name):
    prefix = f"ptr::copy_nonoverlapping::<{type_name}>"
    return {
        f"{prefix}.{key}": (key.split(".")[0], description, "core/src/ptr/mod.rs", 587, 14, prefix)
        for key, description in COPY_BACK_PROPERTIES.items()
    }


def _validate_pilot_properties(row):
    """Pin pilot rows to their scalar-copy specialization and stock Check anchors."""
    rid = row["id"]
    type_name = "u64" if rid in PILOT_U64_SLOT_IDS else f"{PILOT_PREFIX}Wide"
    expected = _pilot_copy_expected(type_name)
    if rid in PILOT_PLAIN_IDS:
        props = (row.get("native_evidence") or {}).get("required_properties")
        if (not isinstance(props, list) or len(props) != len(expected)
                or {item.get("id") for item in props if isinstance(item, dict)} != set(expected)):
            raise ValueError(f"pilot plain slot {rid} requires all six exact typed-copy properties")
        for prop in props:
            binding = expected.get(prop.get("id")) if isinstance(prop, dict) else None
            if binding is None or tuple(prop.get(key) for key in
                                         ("class", "description", "file", "line", "column", "function")) != binding:
                raise ValueError(f"pilot plain slot {rid} has a wrong typed-copy binding")
    else:
        check = PILOT_CHECK_TARGETS.get(rid)
        gate = row.get("check_evidence") or {}
        target_instance = f"{PILOT_PREFIX}{check}"
        if (gate.get("target_instance") != target_instance or gate.get("definition") != target_instance
                or gate.get("file") != PILOT_MODULE_FILE or len(gate.get("lines", [])) != 1
                or gate.get("modifies") != ["s.wrapping_add(k)", "s.wrapping_add(15 - k)"]):
            raise ValueError(f"pilot Check slot {rid} has a wrong target, source definition, or modifies scope")
        checked = gate.get("checked_assertions")
        expected_checked = [label for label in row.get("required_assertions", [])
                            if label.endswith(("_READ", "_WRITE", "_DISJOINT", "_CURSORS"))]
        if checked != expected_checked or len(checked) != 8:
            raise ValueError(f"pilot Check slot {rid} must bind both scoped cursor triples")
        props = gate.get("properties")
        required_ids = set(expected) | set(PILOT_ASSIGNS_PROPERTIES)
        if (not isinstance(props, list) or len(props) != len(required_ids)
                or {item.get("id") for item in props if isinstance(item, dict)} != required_ids):
            raise ValueError(f"pilot Check slot {rid} requires scoped assigns and six typed-copy properties")
        for prop in props:
            binding = expected.get(prop.get("id")) if isinstance(prop, dict) else None
            if binding is None and isinstance(prop, dict):
                binding = PILOT_ASSIGNS_PROPERTIES.get(prop.get("id"))
            if binding is None or tuple(prop.get(key) for key in
                                         ("class", "description", "file", "line", "column", "function")) != binding:
                raise ValueError(f"pilot Check slot {rid} has a wrong typed-copy or assigns binding")
    sites = ((row.get("check_evidence") or {}).get("copy_sites") if rid in PILOT_CHECK_IDS else
             (row.get("native_evidence") or {}).get("copy_sites"))
    if rid in {"GEN-N16-S8-R32-FULL", "GEN-N16-S8-R32-BITS"}:
        expected_sites = PILOT_SORT4_COPY_SITES + PILOT_MERGE_COPY_SITES
    elif rid == "GEN-N16-WIDE-S4-R48":
        expected_sites = PILOT_SORT4_COPY_SITES
    elif rid == "GEN-N16-WIDE-FILL-R48-REL4":
        expected_sites = PILOT_FILL_COPY_SITES
    else:
        expected_sites = PILOT_MERGE_COPY_SITES
    if sites != expected_sites:
        raise ValueError(f"pilot slot {rid} has wrong local or actual typed-copy sites")


def _validate_fix1_properties(row):
    """Bind each split merge Check to its one directional merge site, copy type and native properties."""
    rid = row["id"]
    prefix, short_target, modifies, site_line, checks, type_name = SPLIT_MERGE_CHECKS[rid]
    target = prefix + short_target
    expected_sites = [{"file": spec.SMALLSORT_FILE, "line": site_line, "column": 9,
                       "token": "ptr::copy_nonoverlapping(src, dst, 1);"}]
    gate = row.get("check_evidence") or {}
    binding = checks.get(row.get("selector"))
    lines = gate.get("lines")
    if (gate.get("target_instance") != target or gate.get("definition") != target or
            gate.get("file") != PILOT_MODULE_FILE or not isinstance(lines, list) or len(lines) != 1 or
            gate.get("column") != 5 or gate.get("modifies") != [modifies] or binding != (target, PILOT_MODULE_FILE)):
        raise ValueError(f"split merge Check slot {rid} has a wrong target, source definition, or direction scope")
    checked = gate.get("checked_assertions")
    expected_checked = [label for label in row.get("required_assertions", [])
                        if label.endswith(FIX1_WRAPPER_SUFFIXES)]
    if (not isinstance(checked, list) or checked != expected_checked or
            len(checked) != len(FIX1_WRAPPER_SUFFIXES)):
        raise ValueError(f"split merge Check slot {rid} must bind its four scoped wrapper assertions")
    expected = _pilot_copy_expected(type_name) | PILOT_ASSIGNS_PROPERTIES
    props = gate.get("properties")
    if (not isinstance(props, list) or len(props) != len(expected) or
            {item.get("id") for item in props if isinstance(item, dict)} != set(expected)):
        raise ValueError(f"split merge Check slot {rid} requires scoped assigns and six typed-copy properties")
    for prop in props:
        binding = expected.get(prop.get("id")) if isinstance(prop, dict) else None
        if (binding is None or tuple(prop.get(key) for key in
                                     ("class", "description", "file", "line", "column", "function")) != binding):
            raise ValueError(f"split merge Check slot {rid} has a wrong typed-copy or assigns binding")
    if gate.get("copy_sites") != expected_sites:
        raise ValueError(f"split merge Check slot {rid} has wrong actual typed-copy site or direction")


def _validate_n32_plain_properties(row):
    """Bind the three plain N32 supports to their exact selector, outcome and grouped copy type."""
    slot = row["id"]
    kind, role = spec.N32_GEOMETRY[slot]
    if (row["selector"] != spec.N32_PREFIX + slot.lower().replace("-", "_") or row.get("check") is not None
            or row.get("check_evidence") is not None or row["replace"]):
        raise ValueError(f"N32 slot {slot} requires its exact plain Proof selector")
    if row.get("expected_outcome") != "VERIFIED" or row.get("expected_failure") is not None:
        raise ValueError(f"N32 slot {slot} has wrong expected outcome or failure anchor")
    native = row.get("native_evidence") or {}
    expected = _pilot_copy_expected("u64" if kind == "u64" else WIDE_TYPE)
    required = native.get("required_properties")
    fields = ("class", "description", "file", "line", "column", "function")
    if (not isinstance(required, list) or any(not isinstance(prop, dict) for prop in required)
            or len(required) != len(expected)
            or {prop.get("id"): tuple(prop.get(field) for field in fields) for prop in required} != expected):
        raise ValueError(f"N32 slot {slot} has wrong typed-copy binding")
    sites = native.get("copy_sites")
    expected_sites = PILOT_SORT4_COPY_SITES + PILOT_MERGE_COPY_SITES if role == "s8" else None
    if role == "fill":
        local = sites[0] if isinstance(sites, list) and sites and isinstance(sites[0], dict) else {}
        expected_sites = [{"file": PILOT_MODULE_FILE, "line": local.get("line"), "column": 13,
                           "token": "ptr::copy_nonoverlapping(s.add(31), d.add(31), 1);",
                           "transcribes": PILOT_FILL_COPY_SITES[0]["transcribes"]}, *PILOT_FILL_COPY_SITES[1:]]
        if type(local.get("line")) is not int or local["line"] < 1:
            raise ValueError(f"N32 slot {slot} has no local fill copy coordinate")
    if sites != expected_sites:
        raise ValueError(f"N32 slot {slot} has wrong local or actual typed-copy sites")


def _validate_n32_closure_properties(row):
    """Bind the three plain closure roots to their exact selector, sole failure, copy type and reached sites."""
    slot = row["id"]
    kind, role, _, failure_label = spec.N32_CLOSURE_GEOMETRY[slot]
    if (row["selector"] != spec.N32_CLOSURE_SELECTORS[slot] or row.get("check") is not None
            or row.get("check_evidence") is not None or row["replace"]):
        raise ValueError(f"N32 closure slot {slot} requires its exact plain Proof selector")
    failure = row.get("expected_failure")
    failure_matches = failure is None if failure_label is None else (
        isinstance(failure, dict) and failure.get("label") == failure_label and failure.get("class") == "assertion"
        and failure.get("function") == spec.N32_CLOSURE_SELECTORS[slot])
    if row.get("expected_outcome") != ("FAILED" if failure_label else "VERIFIED") or not failure_matches:
        raise ValueError(f"N32 closure slot {slot} has wrong expected outcome or failure anchor")
    if row.get("stdout_delivery") != spec.SLOT_STDOUT_DELIVERY[slot]:
        raise ValueError(f"N32 closure slot {slot} has the wrong frozen stdout delivery")
    native = row.get("native_evidence") or {}
    expected = _pilot_copy_expected("u64" if kind == "u64" else WIDE_TYPE)
    required = native.get("required_properties")
    fields = ("class", "description", "file", "line", "column", "function")
    if (not isinstance(required, list) or any(not isinstance(prop, dict) for prop in required)
            or len(required) != len(expected)
            or {prop.get("id"): tuple(prop.get(field) for field in fields) for prop in required} != expected):
        raise ValueError(f"N32 closure slot {slot} has wrong typed-copy binding")
    fill = [{"file": spec.SMALLSORT_FILE, "line": 329, "column": 17,
             "token": "ptr::copy_nonoverlapping(src.add(i), dst.add(i), 1);"}]
    expected_sites = (PILOT_SORT4_COPY_SITES + PILOT_MERGE_COPY_SITES if role == "s8" else
                      PILOT_SORT4_COPY_SITES + fill + PILOT_MERGE_COPY_SITES)
    if native.get("copy_sites") != expected_sites or native.get("copy_back") is not False:
        raise ValueError(f"N32 closure slot {slot} has wrong actual typed-copy sites")


def _validate_close_properties(row):
    slot = row["id"]
    witness = spec.WITNESS_ROOTS.get(slot)
    selector = witness[0] if witness else spec.CLOSE_PREFIX + slot.lower().replace("-", "_")
    if row["selector"] != selector or row.get("check") is not None or row.get("check_evidence") is not None or row["replace"]:
        raise ValueError(f"CLOSE slot {slot} requires its exact plain Proof selector")
    failure_label = witness[1] if witness else spec.CLOSE_FAILURES.get(slot)
    expected_outcome = "FAILED" if failure_label else "VERIFIED"
    failure = row.get("expected_failure")
    failure_matches = failure is None if failure_label is None else (
        isinstance(failure, dict) and failure.get("label") == failure_label and failure.get("class") == "assertion"
    )
    if row.get("expected_outcome") != expected_outcome or not failure_matches:
        raise ValueError(f"CLOSE slot {slot} has wrong expected outcome or failure anchor")
    type_name = "u64" if slot in spec.CLOSE_U64_SLOTS else f"{PILOT_PREFIX}Wide"
    expected = _pilot_copy_expected(type_name)
    required = (row.get("native_evidence") or {}).get("required_properties")
    if not isinstance(required, list) or len(required) != len(expected):
        raise ValueError(f"CLOSE slot {slot} requires six grouped typed-copy properties")
    fields = ("class", "description", "file", "line", "column", "function")
    if any(not isinstance(prop, dict) for prop in required) or {
        prop.get("id"): tuple(prop.get(field) for field in fields) for prop in required
    } != expected:
        raise ValueError(f"CLOSE slot {slot} has wrong typed-copy binding")


def _read(path: Path, cap: int):
    try:
        with path.open("rb") as stream:
            data = stream.read(cap + 1)
        if len(data) > cap:
            return data[:cap], False, f"{path.name} exceeds {cap} bytes"
        return data, True, None
    except FileNotFoundError:
        return b"", False, f"{path.name} is missing"
    except OSError as exc:
        return b"", False, f"{path.name} unreadable: {type(exc).__name__}: {str(exc)[:200]}"


def _validate_rows(rows):
    if not isinstance(rows, list) or not rows:
        raise ValueError("rows must be a non-empty list")
    selectors, ids = [], set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("row is not an object")
        rid, selector = row.get("id"), row.get("selector")
        if not isinstance(rid, str) or not rid or rid in ids:
            raise ValueError("row IDs must be unique non-empty strings")
        if not isinstance(selector, str) or not selector or selector in selectors:
            raise ValueError("selectors must be unique non-empty strings")
        if type(row.get("unwind")) is not int or row["unwind"] < 1:
            raise ValueError(f"invalid unwind for {rid}")
        if type(row.get("check")) not in (str, type(None)):
            raise ValueError(f"invalid Check role for {rid}")
        if rid in BOUND_SLOT_IDS and (row.get("check") is not None) != bool(row.get("check_evidence")):
            raise ValueError(f"missing or unexpected Check evidence specification for {rid}")
        if (not isinstance(row.get("replace"), list) or
                any(not isinstance(x, str) for x in row["replace"]) or
                not isinstance(row.get("covers"), list) or
                any(not isinstance(x, str) or not x for x in row["covers"]) or
                len(row["covers"]) != len(set(row["covers"]))):
            raise ValueError(f"invalid role or cover list for {rid}")
        if rid in U64_PLAIN_IDS and (
                row.get("check") is not None or row.get("check_evidence") is not None or row["replace"]):
            raise ValueError(f"u64 slot {rid} must be a plain Proof without Check or Replace")
        if rid in U64_CHECK_TARGETS and (row["check"] != U64_CHECK_TARGETS[rid] or row["replace"]):
            raise ValueError(f"u64 slot {rid} requires its exact Check and no Replace")
        if rid in PILOT_SLOT_IDS:
            expected_check = PILOT_CHECK_TARGETS.get(rid)
            if row["check"] != expected_check or row["replace"]:
                raise ValueError(f"pilot slot {rid} requires its exact Proof role and no Replace")
            _validate_pilot_properties(row)
        if rid in SPLIT_MERGE_CHECKS:
            expected_check = SPLIT_MERGE_CHECKS[rid][1]
            if row["check"] != expected_check or row["replace"]:
                raise ValueError(f"split merge slot {rid} requires its exact Proof role and no Replace")
            _validate_fix1_properties(row)
        if rid in CLOSE_SLOT_IDS:
            _validate_close_properties(row)
        if rid in N32_PLAIN_IDS:
            _validate_n32_plain_properties(row)
        if rid in N32_CLOSURE_IDS:
            _validate_n32_closure_properties(row)
        if rid in U64_N26_N32_PROVIDER_PLAIN_IDS:
            anchors = (row.get("native_evidence") or {}).get("required_properties")
            if not isinstance(anchors, list) or {p.get("id") for p in anchors if isinstance(p, dict)} != set(U64_COPY_PROPERTIES):
                raise ValueError(f"u64 provider plain slot {rid} requires both typed-copy property groups")
            for prop in anchors:
                expected = U64_COPY_PROPERTIES.get(prop.get("id")) if isinstance(prop, dict) else None
                if (expected is None or (prop.get("class"), prop.get("description"), prop.get("file"),
                                         prop.get("line"), prop.get("column")) != expected):
                    raise ValueError(f"u64 provider plain slot {rid} has a wrong typed-copy binding")
        if rid in U64_N26_N32_CONSUMER_IDS:
            anchors = (row.get("native_evidence") or {}).get("required_properties")
            expected_ids = {f"ptr::copy_nonoverlapping::<u64>.{key}" for key in COPY_BACK_PROPERTIES}
            if not isinstance(anchors, list) or {p.get("id") for p in anchors if isinstance(p, dict)} != expected_ids:
                raise ValueError(f"u64 consumer slot {rid} requires all six grouped typed-copy properties")
            for prop in anchors:
                expected = U64_COPY_PROPERTIES.get(prop.get("id")) if isinstance(prop, dict) else None
                if (expected is None or (prop.get("class"), prop.get("description"), prop.get("file"),
                                         prop.get("line"), prop.get("column")) != expected):
                    raise ValueError(f"u64 consumer slot {rid} has a wrong typed-copy binding")
        if rid in U64_N26_N32_CHECK_IDS:
            props = (row.get("check_evidence") or {}).get("properties", [])
            expected_ids = {"memcpy.assigns.1", "memcpy.assigns.2",
                            *(f"ptr::copy_nonoverlapping::<u64>.{key}" for key in COPY_BACK_PROPERTIES)}
            if {prop.get("id") for prop in props if isinstance(prop, dict)} != expected_ids:
                raise ValueError(f"u64 provider Check {rid} requires scoped assigns and six typed-copy properties")
        expected = row.get("expected_outcome")
        assertions = row.get("required_assertions", [])
        if (not isinstance(assertions, list) or
                any(not isinstance(x, str) or not x for x in assertions) or
                len(assertions) != len(set(assertions))):
            raise ValueError(f"invalid required assertions for {rid}")
        native = row.get("native_evidence")
        if rid in BOUND_SLOT_IDS:
            coordinates = native.get("coordinates") if isinstance(native, dict) else None
            labels = set(assertions) | set(row["covers"])
            failure = row.get("expected_failure")
            if isinstance(failure, dict) and isinstance(failure.get("label"), str):
                labels.add(failure["label"])
            if not isinstance(coordinates, dict) or set(coordinates) != labels:
                raise ValueError(f"missing or extra pinned native coordinates for {rid}")
            copy_back = rid in COPY_BACK_SLOT_IDS
            if rid in PILOT_SLOT_IDS | SPLIT_MERGE_CHECKS.keys() and "copy_back" in native:
                raise ValueError(f"pilot slot {rid} must not use the historical copy_back role")
            if rid not in PILOT_SLOT_IDS | SPLIT_MERGE_CHECKS.keys() and native.get("copy_back") is not copy_back:
                raise ValueError(f"slot {rid} requires copy_back={str(copy_back).lower()}")
            if copy_back and (row["check"] is not None or row["replace"]):
                raise ValueError(f"copy-back slot {rid} requires a plain Proof")
            for label, coordinate in coordinates.items():
                if (not isinstance(coordinate, dict) or not isinstance(coordinate.get("file"), str) or
                        type(coordinate.get("line")) is not int or coordinate["line"] < 1 or
                        type(coordinate.get("column")) is not int or coordinate["column"] < 1 or
                        not isinstance(coordinate.get("function"), str) or not coordinate["function"]):
                    raise ValueError(f"malformed native coordinate for {rid}: {label}")
                if "class" in coordinate and coordinate["class"] not in ("assertion", "cover"):
                    raise ValueError(f"malformed native property class for {rid}: {label}")
                if (rid in U64_SLOT_IDS | CLOSE_SLOT_IDS | N32_CLOSURE_IDS
                        and coordinate.get("class") not in ("assertion", "cover")):
                    raise ValueError(f"missing native property class for {rid}: {label}")
                if "class" in coordinate and coordinate["class"] != ("cover" if label in row["covers"] else "assertion"):
                    raise ValueError(f"native property class disagrees with role for {rid}: {label}")
        elif native is not None:
            raise ValueError(f"unexpected native coordinates for {rid}")
        repeatable = row.get("repeatable_assertions", [])
        if (not isinstance(repeatable, list) or any(not isinstance(x, str) or not x for x in repeatable)
                or len(repeatable) != len(set(repeatable)) or not set(repeatable) <= set(assertions)):
            raise ValueError(f"invalid repeatable assertions for {rid}")
        if expected is not None:
            if expected not in ("VERIFIED", "FAILED"):
                raise ValueError(f"invalid expected outcome for {rid}")
            failure = row.get("expected_failure")
            if (expected == "VERIFIED" and failure is not None) or (
                    expected == "FAILED" and not isinstance(failure, dict)):
                raise ValueError(f"invalid expected failure for {rid}")
            if expected == "FAILED" and (not isinstance(failure.get("label"), str) or
                    not isinstance(failure.get("file"), str) or type(failure.get("line")) is not int):
                raise ValueError(f"malformed expected failure for {rid}")
            if isinstance(failure, dict) and "class" in failure and failure["class"] != "assertion":
                raise ValueError(f"expected failure for {rid} must be an assertion")
            if expected == "FAILED" and rid in U64_SLOT_IDS and failure.get("class") != "assertion":
                raise ValueError(f"u64 failure for {rid} must pin assertion class")
            if expected == "FAILED" and "function" in failure and (
                    not isinstance(failure["function"], str) or not failure["function"]):
                raise ValueError(f"malformed expected failure function for {rid}")
            if expected == "FAILED" and ("column" in failure and
                    (type(failure["column"]) is not int or failure["column"] < 1)):
                raise ValueError(f"malformed expected failure for {rid}")
            if expected == "FAILED" and ("native_id" in failure and
                    (not isinstance(failure["native_id"], str) or not failure["native_id"])):
                raise ValueError(f"malformed expected failure for {rid}")
        ids.add(rid); selectors.append(selector)
    return selectors


def _native(data: bytes, selector: str):
    parsed = evidence.regular(data, selector)
    checks = [{key: p.get(key) for key in ("id", "stock_export_id", "class", "status", "description", "location", "source_coordinate")}
              for p in parsed.get("observations", [])]
    counts = Counter((p["class"], p["status"]) for p in checks)
    return parsed, checks, {f"{cls}.{status}": n for (cls, status), n in sorted(counts.items())}


def _location_matches(location, filename, line, column=None, function=None):
    if not isinstance(location, str) or not isinstance(filename, str):
        return False
    location, separator, observed_function = location.partition(" in function ")
    if function is not None and (not separator or observed_function != function):
        return False
    parts = location.rsplit(":", 2)
    observed_column = None
    if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
        observed_file, observed_line, observed_column = parts[0], parts[1], int(parts[2])
    elif len(parts) >= 2 and parts[-1].isdigit():
        observed_file, observed_line = ":".join(parts[:-1]), parts[-1]
    else:
        return False
    if int(observed_line) != line:
        return False
    # A function-qualified target is an exact source binding: both the column
    # and function selector must be present in regular output. Legacy targets
    # without a function retain support for pinned records that omit columns.
    if column is not None and (observed_column != column if function is not None else
                               observed_column is not None and observed_column != column):
        return False
    return spec.source_file_matches(observed_file, filename)


def _stock_bucket_ids(buckets, key):
    values = buckets.get(key, [])
    if not isinstance(values, list):
        return []
    if key.endswith(".other"):
        return [item.get("id") for item in values if isinstance(item, dict)]
    return values


def _native_id(value):
    # The regular printer preserves the crate prefix on some generated symbols.
    return re.sub(r"^core::|(?<=, )core::", "", value or "")


def _checked_property(prop, target, kind):
    pattern = re.escape(target) + r"(?:::\{closure#[0-9]+\})+\." + kind + r"\.[0-9]+"
    return re.fullmatch(pattern, _native_id(prop.get("id"))) is not None


def _required_assertion_matches(row, label, properties):
    matches = [p for p in properties if p.get("class") == "assertion" and p.get("description") == label]
    gate = row.get("check_evidence") or {}
    if label in gate.get("checked_assertions", []):
        # A non-Check instance can also appear in regular as UNREACHABLE.
        return [p for p in matches if _checked_property(p, gate["target_instance"], "assertion")]
    return matches


def _native_check_evidence(row, properties, stock):
    gate = row.get("check_evidence")
    if not gate:
        return [], []
    terminals = stock.get("terminal") or []
    contract = terminals[0].get("contract") if len(terminals) == 1 else None
    symbol = contract.get("contracted_function_name") if isinstance(contract, dict) else None
    errors, selected = [], []
    attributes = terminals[0].get("attributes") if len(terminals) == 1 else None
    role = attributes.get("kind") if isinstance(attributes, dict) else None
    if role != {"ProofForContract": {"target_fn": row["check"]}}:
        errors.append("stock contract target does not match the frozen Check")
    for kind, description in (("single_top_level_call", "Only a single top-level call"),
                              ("no_recursive_call", "No recursive call")):
        matches = [p for p in properties if p.get("class") == kind and
                   _checked_property(p, gate["target_instance"], kind)]
        selected.extend(matches)
        expected = f"{description} to function {symbol} when checking contract {symbol}"
        prop = matches[0] if len(matches) == 1 else {}
        # The function extracted from the ID checks agreement with the regular location.
        # Independent anchors are the frozen target_instance regex above, the stock
        # target and symbol, and the modifies line and column 1 for frozen Checks.
        function = prop["id"].rsplit(".", 2)[0] if prop and "definition" in gate else None
        column = gate.get("column", 1) if function else None
        if (not symbol or prop.get("status") != "SUCCESS" or prop.get("description") != expected
                or not any(_location_matches(prop.get("location"), gate["file"], line, column, function)
                           for line in gate["lines"])):
            errors.append(f"Check {kind} not bound to the stock contract symbol and exact modifies location")
    for anchor in gate["properties"]:
        matches = [p for p in properties if _native_id(p.get("id")) == anchor["id"]]
        selected.extend(matches)
        location = matches[0].get("location") if len(matches) == 1 else None
        if anchor.get("column") is not None and isinstance(location, str):
            _, separator, observed_function = location.partition(" in function ")
            location_matches = bool(separator) and _location_matches(
                location, anchor["file"], anchor["line"], anchor["column"], anchor.get("function", observed_function))
        else:
            location_matches = bool(matches) and _location_matches(
                location, anchor["file"], anchor["line"])
        if (len(matches) != 1 or matches[0].get("status") != "SUCCESS"
                or not location_matches or any(matches[0].get(field) != anchor[field]
                                               for field in ("class", "description") if field in anchor)):
            errors.append(f"required Check property {anchor['id']} missing or has wrong location/status")
    if (row["id"] in spec.MERGE_SLOT_IDS or row["id"] in U64_CHECK_TARGETS or
            row["id"] in PILOT_CHECK_IDS or row["id"] in SPLIT_MERGE_CHECKS):
        # DFCC unwind assertions can belong to builtin write-set helpers.
        unwinds = [p for p in properties if p.get("class") == "unwind"]
        selected.extend(unwinds)
        if not unwinds or any(p.get("status") != "SUCCESS" for p in unwinds):
            errors.append("Check requires successful native unwind evidence")
    return errors, selected


def _insert_copy_role(prop):
    location = prop.get("location")
    if not isinstance(location, str):
        return None
    function = location.partition(" in function ")[2]
    instance = _native_id(function)
    for role, coordinate in spec.INSERT_COPY_COORDINATES.items():
        if not function or not _location_matches(location, *coordinate, function):
            continue
        if role == "ptr_wrapper" and instance == INSERT_COPY_INSTANCE:
            return role
        if role == "shift" and instance.split("::<", 1)[0] == "slice::sort::shared::smallsort::insert_tail":
            return role
        if role == "gap_fill" and "smallsort::CopyOnDrop<" in instance and instance.endswith("::drop"):
            return role
    return None


def _native_source_evidence(row, properties):
    """Require each requested label at its pinned source file, line, column and function."""
    gate = row.get("native_evidence")
    if not gate:
        return [], []
    errors, selected = [], []
    covers = set(row["covers"])
    failure = row.get("expected_failure") or {}
    checked_assertions = set((row.get("check_evidence") or {}).get("checked_assertions", []))
    for label, anchor in gate["coordinates"].items():
        kind = anchor.get("class", "cover" if label in covers else "assertion")
        expected_status = "SATISFIED" if kind == "cover" else (
            "FAILURE" if label == failure.get("label") else "SUCCESS")
        all_matches = [p for p in properties if p.get("class") == kind and p.get("description") == label]
        matches = (_required_assertion_matches(row, label, properties) if label in checked_assertions
                   else all_matches)
        pattern = re.escape(anchor["function"]) + r"(?:::\{closure#[0-9]+\})*\." + kind + r"\.[0-9]+"
        exact = []
        for prop in matches:
            location = prop.get("location")
            observed_function = location.partition(" in function ")[2] if isinstance(location, str) else ""
            base_function = re.sub(r"(?:::\{closure#[0-9]+\})+$", "", observed_function or "")
            if (re.fullmatch(pattern, _native_id(prop.get("id"))) and
                    _location_matches(location, anchor["file"], anchor["line"], anchor["column"],
                                      observed_function) and
                    base_function == anchor["function"]):
                exact.append(prop)
        selected.extend(exact)
        if len(matches) != 1 or len(exact) != 1 or exact[0].get("status") != expected_status:
            errors.append(f"native {label} missing or has wrong function, coordinate, or status")
    for anchor in gate.get("required_properties", []):
        matches = [p for p in properties if _native_id(p.get("id")) == anchor["id"]]
        selected.extend(matches)
        location = matches[0].get("location") if len(matches) == 1 else None
        if (len(matches) != 1 or matches[0].get("status") != "SUCCESS"
                or any(matches[0].get(field) != anchor[field] for field in ("class", "description"))
                or not _location_matches(location, anchor["file"], anchor["line"], anchor["column"],
                                         anchor["function"])):
            errors.append(f"required typed-copy property {anchor['id']} missing or has wrong location/status")
    if gate.get("copy_back"):
        unwinds = [p for p in properties if p.get("class") == "unwind"]
        selected.extend(unwinds)
        # Stock verifies that unwinding is enabled. Plain Proof can emit no
        # unwinding properties when CBMC fully resolves the loop bounds.
        if any(p.get("status") != "SUCCESS" for p in unwinds):
            errors.append("copy-back evidence requires every emitted unwind property to succeed")
        if row["id"] in LEGACY_COPY_BACK_SLOT_IDS:
            for suffix, description in COPY_BACK_PROPERTIES.items():
                prop_id = f"{COPY_BACK_INSTANCE}.{suffix}"
                matches = [p for p in properties if _native_id(p.get("id")) == prop_id]
                selected.extend(matches)
                if (len(matches) != 1 or matches[0].get("class") != suffix.split(".")[0]
                        or matches[0].get("status") != "SUCCESS" or matches[0].get("description") != description
                        or not _location_matches(matches[0].get("location"), *COPY_BACK_COORDINATE, COPY_BACK_INSTANCE)):
                    errors.append(f"grouped copy property {prop_id} missing or has wrong location, class, description or status")
    if row["id"] in SWAP_SLOT_IDS or row["id"] in SORT9_SLOT_IDS:
        # Generated IDs are telemetry for later offline binding to the swap sites.
        for prefix in ("ptr::copy::<u64>.", "ptr::copy_nonoverlapping::<u64>."):
            selected.extend(p for p in properties if _native_id(p.get("id", "")).startswith(prefix))
    if row["id"] in INSERT_SLOT_IDS:
        copies = [p for p in properties if _native_id(p.get("id")).startswith(INSERT_COPY_INSTANCE + ".")]
        selected.extend(copies)
        expected = {(suffix.split(".")[0], description) for suffix, description in COPY_BACK_PROPERTIES.items()}
        observed = {(p.get("class"), p.get("description")) for p in copies
                    if _insert_copy_role(p) == "ptr_wrapper"}
        if not expected <= observed or any(p.get("status") != "SUCCESS" for p in copies):
            errors.append("insert step requires successful native u64 copy_nonoverlapping safety groups")
    if row["id"] in U64_SLOT_IDS:
        # Stock independently establishes unwinding=ON, even if no unwind property is emitted.
        unwinds = [p for p in properties if p.get("class") == "unwind"]
        selected.extend(unwinds)
        if any(p.get("status") != "SUCCESS" for p in unwinds):
            errors.append("u64 proof requires every emitted unwind property to succeed")
    if row["id"] in PILOT_PLAIN_IDS | CLOSE_SLOT_IDS | N32_PLAIN_IDS | N32_CLOSURE_IDS:
        unwinds = [p for p in properties if p.get("class") == "unwind"]
        selected.extend(unwinds)
        if any(p.get("status") != "SUCCESS" for p in unwinds):
            errors.append("plain pilot Proof requires every emitted unwind property to succeed")
    return errors, selected


def _expected_result(row, outcome, complete, native_checks, stock):
    """Compare the frozen expected outcome and labels against both native channels."""
    expected = row.get("expected_outcome")
    if expected is None:
        return None
    if not complete or stock.get("state") != "COMPLETE" or outcome not in ("VERIFIED", "FAILED"):
        return {"status": "UNAVAILABLE", "expected_outcome": expected, "observed_outcome": outcome,
                "required_assertions": row["required_assertions"], "required_covers": row["covers"],
                "reached_covers": [], "reason": "slot did not produce a complete terminal projection"}
    reasons = []
    assertions = row["required_assertions"]
    repeatable_assertions = set(row.get("repeatable_assertions", []))
    required_covers = row["covers"]
    if outcome != expected:
        reasons.append(f"observed outcome {outcome} does not match {expected}")

    for label in assertions:
        matches = _required_assertion_matches(row, label, native_checks)
        count_ok = len(matches) >= 1 if label in repeatable_assertions else len(matches) == 1
        if not count_ok or any(p.get("status") != "SUCCESS" for p in matches):
            reasons.append(f"required assertion {label} missing, duplicated, or has wrong status")
    check_errors, _ = _native_check_evidence(row, native_checks, stock)
    reasons.extend(check_errors)
    source_errors, _ = _native_source_evidence(row, native_checks)
    reasons.extend(source_errors)

    reached_covers = []
    stock_buckets = stock.get("property_ids", {})
    stock_buckets = stock_buckets.get(row["id"], stock_buckets)
    reached = set(_stock_bucket_ids(stock_buckets, "covers.satisfied"))
    for label in required_covers:
        matches = [p for p in native_checks if p.get("class") == "cover" and p.get("description") == label]
        if not matches or any(p.get("status") != "SATISFIED" for p in matches):
            reasons.append(f"required cover {label} missing or not fully reached in regular output")
            continue
        if any(p.get("stock_export_id") not in reached for p in matches):
            reasons.append(f"required cover {label} not fully reached in stock export")
        else:
            reached_covers.append(label)

    stock_failures = stock.get("failed_properties", [])
    native_failures = [p for p in native_checks if p.get("status") == "FAILURE"]
    allowed_check_statuses = {"SUCCESS", "UNREACHABLE"}
    if expected == "FAILED":
        allowed_check_statuses.add("FAILURE")
    if any(p.get("status") not in (
            {"SATISFIED", "UNSATISFIABLE", "UNREACHABLE"} if p.get("class") == "cover" else allowed_check_statuses
    ) for p in native_checks):
        reasons.append("unexpected native property status")
    if expected == "VERIFIED":
        if native_failures or stock_failures:
            reasons.append("unexpected failed property")
    else:
        target = row["expected_failure"]
        native_target = [p for p in native_failures if p.get("description") == target["label"]]
        stock_target = [p for p in stock_failures if isinstance(p, dict) and
                        p.get("description") == target["label"]]
        if len(native_failures) != 1 or len(native_target) != 1 or len(stock_failures) != 1 or len(stock_target) != 1:
            reasons.append("control does not have exactly the intended sole failure")
        else:
            native, exported = native_target[0], stock_target[0]
            if native.get("class") != "assertion" or exported.get("class") != "assertion":
                reasons.append("intended failure is not an assertion in both channels")
            if native.get("stock_export_id") != exported.get("id"):
                reasons.append("native and stock failure property IDs disagree")
            if native.get("id") != exported.get("id"):
                reasons.append("regular and stock failure native IDs disagree")
            if exported.get("status") != "FAILURE":
                reasons.append("stock failure record status is not FAILURE")
            if target.get("native_id") is not None and native.get("id") != target["native_id"]:
                reasons.append("native failure ID does not match pinned property ID")
            if not _location_matches(native.get("location"), target["file"], target["line"],
                                     target.get("column"), target.get("function")):
                reasons.append("native failure location/function does not match expected source coordinate")
            # RFC 0015 stock failure locations have file and line only.
            if not spec.source_file_matches(exported.get("file"), target["file"]) or exported.get("line") != str(target["line"]):
                reasons.append("stock failure location does not match expected source coordinate")

    # Successful property IDs are not in RFC 0015's checks bucket; reconcile
    # its success count against regular output and compare failed IDs above.
    totals = stock.get("totals", {})
    totals = totals.get(row["id"], totals)
    native_check_count = sum(p.get("class") != "cover" for p in native_checks)
    native_success_count = sum(p.get("class") != "cover" and p.get("status") == "SUCCESS" for p in native_checks)
    checks_total = totals.get("checks_total", totals.get("checks.total"))
    checks_success = totals.get("checks_success", totals.get("checks.success"))
    if checks_total != native_check_count or checks_success != native_success_count:
        reasons.append("regular and stock assertion totals disagree")
    for group, statuses in (("checks", {"failure": "FAILURE", "unreachable": "UNREACHABLE",
                                         "error": "ERROR"}),
                            ("covers", {"satisfied": "SATISFIED", "unsatisfiable": "UNSATISFIABLE",
                                        "unreachable": "UNREACHABLE", "error": "ERROR"})):
        property_class = "cover" if group == "covers" else None
        for bucket, status in statuses.items():
            native_ids = [p.get("stock_export_id") for p in native_checks
                          if ((p.get("class") == property_class) if property_class else p.get("class") != "cover")
                          and p.get("status") == status]
            stock_ids = _stock_bucket_ids(stock_buckets, f"{group}.{bucket}")
            if Counter(stock_ids) != Counter(native_ids):
                reasons.append(f"regular and stock {group} {bucket} property IDs disagree")
        native_undetermined = [p.get("stock_export_id") for p in native_checks
                              if ((p.get("class") == property_class) if property_class else p.get("class") != "cover")
                              and p.get("status") == "UNDETERMINED"]
        stock_undetermined = (_stock_bucket_ids(stock_buckets, f"{group}.undetermined") +
                              _stock_bucket_ids(stock_buckets, f"{group}.unknown"))
        if Counter(stock_undetermined) != Counter(native_undetermined):
            reasons.append(f"regular and stock {group} undetermined/unknown property IDs disagree")
        if _stock_bucket_ids(stock_buckets, f"{group}.other"):
            reasons.append(f"stock export contains {group} properties with unsupported statuses")

    return {"status": "MATCHED" if not reasons else "MISMATCHED", "expected_outcome": expected,
            "observed_outcome": outcome, "required_assertions": assertions,
            "required_covers": required_covers, "reached_covers": reached_covers,
            "reason": "; ".join(reasons) if reasons else None}


def _mandatory_anchors(row, native_checks, stock):
    """Keep the small, outcome-relevant native/export anchors out of bulky detail."""
    assertions = set(row.get("required_assertions", []))
    covers = set(row.get("covers", []))
    failure = row.get("expected_failure") or {}
    check_errors, check_properties = _native_check_evidence(row, native_checks, stock)
    source_errors, source_properties = _native_source_evidence(row, native_checks)
    asserted = [p for label in sorted(assertions)
                for p in _required_assertion_matches(row, label, native_checks)]
    relevant = [p for p in native_checks if p in asserted or p in check_properties or p in source_properties or
                (p.get("class") == "assertion" and p.get("description") == failure.get("label")) or
                (p.get("class") == "cover" and p.get("description") in covers)]
    regular_records = [{key: p.get(key) for key in
                        ("id", "stock_export_id", "class", "status", "description", "location")}
                       for p in relevant]
    stock_ids = stock.get("property_ids", {})
    stock_ids = stock_ids.get(row.get("id"), stock_ids)
    satisfied_cover_ids = _stock_bucket_ids(stock_ids, "covers.satisfied")
    stock_failures = stock.get("failed_properties", [])
    export_records = [{"id": value, "class": "cover", "status": "SATISFIED", "location": None,
                       "description": next((p.get("description") for p in relevant
                                             if p.get("class") == "cover" and
                                             p.get("stock_export_id") == value), None)}
                      for value in satisfied_cover_ids
                      if any(p.get("class") == "cover" and p.get("stock_export_id") == value
                             for p in relevant)]
    export_records.extend({"id": p.get("id"), "class": p.get("class"), "status": p.get("status"),
                           "description": p.get("description"), "file": p.get("file"),
                           "line": p.get("line"), "location": (f"{p.get('file')}:{p.get('line')}"
                                                                  if p.get("file") and p.get("line") else None)}
                          for p in stock_failures if isinstance(p, dict))
    counts = Counter((p.get("class"), p.get("description")) for p in relevant)
    repeatable = set(row.get("repeatable_assertions", []))
    complete = not (check_errors or source_errors) and all(counts[("assertion", label)] >= 1 if label in repeatable
                                        else counts[("assertion", label)] == 1 for label in assertions)
    complete &= all(counts[("cover", label)] >= 1 for label in covers)
    if row["id"] in BOUND_SLOT_IDS:
        complete &= (len({p["id"] for p in regular_records}) == len(regular_records)
                     and all(p["id"] and p["location"] for p in regular_records))
    if failure:
        complete &= counts[("assertion", failure.get("label"))] == 1
        complete &= len([p for p in stock_failures if isinstance(p, dict) and
                         p.get("description") == failure.get("label")]) == 1
    for key, group in (("regular_properties", regular_records), ("export_properties", export_records)):
        if len(group) > 64:
            complete = False
            if key == "regular_properties":
                regular_records = []
            else:
                export_records = []
        elif any(len(json.dumps(p, ensure_ascii=False).encode("utf-8")) > 2048 for p in group):
            complete = False
            filtered = [p for p in group if len(json.dumps(p, ensure_ascii=False).encode("utf-8")) <= 2048]
            if key == "regular_properties":
                regular_records = filtered
            else:
                export_records = filtered
    anchors = {"complete": bool(complete), "regular_properties": regular_records,
               "export_properties": export_records}
    if row["id"] in INSERT_SLOT_IDS:
        groups = {role: {"coordinate": {"file": file, "line": line, "column": column}, "regular_ids": []}
                  for role, (file, line, column) in spec.INSERT_COPY_COORDINATES.items()}
        unattributed = []
        for prop in regular_records:
            if not _native_id(prop["id"]).startswith(INSERT_COPY_INSTANCE + "."):
                continue
            role = _insert_copy_role(prop)
            if role:
                groups[role]["regular_ids"].append(prop["id"])
            else:
                unattributed.append(prop["id"])
        anchors["insert_copy_safety"] = groups | {"unattributed_regular_ids": unattributed}
    if row["id"] in U64_CHECK_TARGETS:
        gate = row["check_evidence"]
        anchors["checked_write_set"] = {key: gate[key] for key in ("definition", "modifies", "copy_sites")}
    return anchors


def _expected_config(doc, rows):
    errors = []
    if not isinstance(doc, dict):
        return ["stock root is not an object"], {}
    metadata = doc
    features = metadata.get("enabled_unstable_features")
    if (not isinstance(features, list) or not all(isinstance(value, str) for value in features)
            or set(features) != EXPECTED_FEATURES or len(features) != len(EXPECTED_FEATURES)):
        errors.append("unstable feature set mismatch")
    if metadata.get("kani_commit") != spec.TOOL[0] or metadata.get("kani_commit_dirty") is not False:
        errors.append("stock export tool identity mismatch")
    config = metadata.get("configuration")
    if not isinstance(config, dict):
        errors.append("configuration missing")
        config = {}
    checks = config.get("checks")
    if not isinstance(checks, dict):
        errors.append("configuration checks missing")
        checks = {}
    for key in ("memory_safety", "overflow", "unwinding", "undefined_function", "assertion_reach_checks"):
        if checks.get(key) is not True:
            errors.append(f"configuration {key} is not enabled")
    if checks.get("assert_contracts") is not False:
        errors.append("assert-contracts configuration mismatch")
    if config.get("coverage_enabled") is not False:
        errors.append("coverage configuration mismatch")
    cbmc_args = config.get("cbmc_args")
    if cbmc_args != ["--object-bits", str(rows[0]["object_bits"])]:
        errors.append("CBMC argument configuration mismatch")
    selected = [row["selector"] for row in rows]
    selection = metadata.get("harness_selection")
    if (not isinstance(selection, dict) or selection.get("requested_filters") != selected
            or selection.get("exact") is not True or selection.get("matched_count") != len(selected)
            or selection.get("unmatched_filters") != []):
        errors.append("exact selector selection mismatch")
    harnesses = metadata.get("harnesses")
    by_name = {h["name"]: h for h in harnesses if isinstance(h, dict) and isinstance(h.get("name"), str)} \
        if isinstance(harnesses, list) else {}
    # Stock sorts result rows by source location, separately from the frozen request order.
    if not isinstance(harnesses, list) or len(harnesses) != len(selected) or set(by_name) != set(selected):
        errors.append("exported selector roster mismatch")
    if metadata.get("run_state") not in ("COMPLETE", "PARTIAL", "INCOMPLETE", "NO_HARNESSES_SELECTED"):
        errors.append("unsupported stock terminal state")
    elif metadata.get("run_state") != "COMPLETE":
        errors.append("stock run is partial or has no selected harnesses")
    if metadata.get("schema_version") != "0.1.0":
        errors.append("stock schema version mismatch")
    if not isinstance(metadata.get("outcome"), dict):
        errors.append("run outcome missing")
    elif metadata["outcome"].get("kind") != "COMPLETED":
        errors.append("stock run outcome is not completed")
    terminals, totals, ids, verification_times = [], {}, {}, {}
    for row in rows:
        selector = row["selector"]
        harness = by_name.get(selector)
        if harness is None:
            continue
        if harness.get("resolved_unwind") != row["unwind"]:
            errors.append(f"resolved unwind mismatch for {selector}")
        if harness.get("resolved_solver") != "cadical":
            errors.append(f"resolved solver mismatch for {selector}")
        attributes = harness.get("attributes", {})
        kind = attributes.get("kind") if isinstance(attributes, dict) else None
        check = kind.get("ProofForContract") if isinstance(kind, dict) else None
        if row["check"]:
            target = check.get("target_fn") if isinstance(check, dict) else None
            if (not isinstance(target, str) or
                    (target if row.get("check_evidence") else target.rsplit("::", 1)[-1]) != row["check"]):
                errors.append(f"Check target mismatch for {selector}")
            contract = harness.get("contract")
            symbol = contract.get("contracted_function_name") if isinstance(contract, dict) else None
            if not isinstance(symbol, str) or not symbol:
                errors.append(f"bound Check symbol missing for {selector}")
        elif kind != "Proof" or (row["id"] in BOUND_SLOT_IDS and harness.get("contract") is not None):
            errors.append(f"expected ordinary proof for {selector}")
        if row["id"] in BOUND_SLOT_IDS and (
                harness.get("has_loop_contracts") is not False or
                not isinstance(attributes, dict) or attributes.get("should_panic") is not False):
            errors.append(f"REV2 proof root must run without loop contracts or should_panic for {selector}")
        replace = attributes.get("verified_stubs") if isinstance(attributes, dict) else None
        if (not isinstance(replace, list) or not all(isinstance(name, str) for name in replace)
                or Counter(name.rsplit("::", 1)[-1] for name in replace) != Counter(row["replace"])
                or attributes.get("stubs") != []):
            errors.append(f"Replace or ordinary stubs mismatch for {selector}")
        outcome = harness.get("outcome")
        term = outcome.get("kind") if isinstance(outcome, dict) else "UNKNOWN"
        verdict = outcome.get("verdict") if isinstance(outcome, dict) else None
        terminals.append({"selector": selector, "kind": term, "verdict": verdict,
                          "resolved_unwind": harness.get("resolved_unwind"),
                          "resolved_solver": harness.get("resolved_solver"),
                          "attributes": attributes, "contract": harness.get("contract"),
                          "has_loop_contracts": harness.get("has_loop_contracts")})
        resources = harness.get("resources")
        verification_times[selector] = (resources.get("verification_time_s")
                                        if isinstance(resources, dict) and
                                        type(resources.get("verification_time_s")) in (int, float)
                                        else None)
        row_totals, row_ids = {}, {}
        for group in ("checks", "covers"):
            bucket = harness.get(group)
            if not isinstance(bucket, dict):
                errors.append(f"{group} totals missing for {selector}")
                continue
            row_totals[f"{group}_total"] = bucket.get("total")
            names = ("unreachable", "undetermined", "error", "unknown", "other")
            names = ("failure", *names) if group == "checks" else ("satisfied", "unsatisfiable", *names)
            if group == "checks":
                row_totals["checks_success"] = bucket.get("success")
                row_ids["checks.success"] = []
            for name in names:
                value = bucket.get(name)
                row_ids[f"{group}.{name}"] = ([item.get("id") for item in value if isinstance(item, dict)]
                                                 if name == "other" and isinstance(value, list)
                                                 else list(value) if isinstance(value, list) else [])
        totals[row["id"]] = row_totals
        ids[row["id"]] = row_ids
    return errors, {"run_state": metadata.get("run_state"), "run_outcome": metadata.get("outcome"),
                    "terminals": terminals, "totals": totals, "property_ids": ids,
                    "verification_seconds_by_selector": verification_times,
                    "run_totals": metadata.get("summary")}


def _diagnostics(data):
    lines = data.decode("utf-8", errors="backslashreplace").splitlines()
    matched = [line[:500] for line in lines if re.search(
        r"(?i)(^error(?::|\[)|failed to|could not|panic|fatal|signal|killed|timed? ?out)", line)]
    return matched[-4:]


def _native_observations(stdout, stderr):
    text = stdout.decode("utf-8", errors="replace")
    values = {key: None for key in TIMINGS}
    values["compile_seconds"] = None
    combined = text + "\n" + stderr.decode("utf-8", errors="replace")
    for line in combined.splitlines():
        compile_time = CARGO_TIME.fullmatch(line.strip())
        if compile_time:
            seconds = 60 * int(compile_time[1] or 0) + float(compile_time[2])
            if math.isfinite(seconds):
                values["compile_seconds"] = seconds
        for key, pattern in TIMINGS.items():
            match = pattern.fullmatch(line.strip())
            if match:
                try:
                    number = float(match.group(1))
                    if math.isfinite(number) and number >= 0:
                        values[key] = (values[key] or 0) + number if key == "sat_seconds" else number
                except (ValueError, OverflowError):
                    pass
    phase, phase_timestamp = "UNKNOWN", None
    timestamp_re = re.compile(r"^(?:\[(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\]|(\d{2}:\d{2}:\d{2}(?:\.\d+)?))\s*(.*)$")
    for line in text.splitlines():
        timestamp = None
        body = line
        stamp = timestamp_re.fullmatch(line)
        if stamp:
            timestamp = stamp.group(1) or stamp.group(2)
            body = stamp.group(3)
        for name, pattern in PHASE_MARKERS:
            if pattern.fullmatch(body.strip()):
                phase, phase_timestamp = name, timestamp
    solver = None
    m = re.search(r"(?im)^.*\bCaDiCaL[ \t]+v?([0-9][A-Za-z0-9.+_~-]*)\b", combined)
    if m:
        solver = "CaDiCaL" + (" " + m.group(1) if m.group(1) else "")
    return values, {"phase": phase, "timestamp": phase_timestamp}, solver


def _outcome(child, regular_state, terminal, stock):
    reason = child.get("stop_reason") or child.get("termination_reason")
    if child.get("status") == "NOT_STARTED":
        return "NOT_STARTED"
    if reason and reason not in ("EXITED", "COMPLETED"):
        if reason == "TIMEOUT" or "TIMEOUT" in reason:
            return "TIMEOUT"
        return reason
    if child.get("signal") is not None:
        return "INTERRUPTED"
    if stock.get("state") != "COMPLETE":
        return "INCOMPLETE"
    terminals = stock.get("terminal") or stock.get("terminals") or []
    kinds = {item.get("kind") for item in terminals if isinstance(item, dict)}
    for kind in ("OUT_OF_MEMORY", "TIMEOUT", "CRASHED"):
        if kind in kinds:
            return kind
    if regular_state != "COMPLETE":
        return "INCOMPLETE"
    if terminals:
        verdicts = [item.get("verdict") for item in terminals if isinstance(item, dict)]
        if len(verdicts) == len(terminals) and kinds == {"COMPLETED"}:
            if all(v == "SUCCESS" for v in verdicts):
                return "VERIFIED"
            if all(v in ("SUCCESS", "FAILURE") for v in verdicts) and "FAILURE" in verdicts:
                return "FAILED"
            return "INCOMPLETE"
    if terminal == "VERIFICATION:- SUCCESSFUL":
        return "VERIFIED"
    if terminal and terminal.startswith("VERIFICATION:- FAILED"):
        return "FAILED"
    return "INCOMPLETE"


def _observed_outcome(child, regular_state, terminal, stock):
    """Expose the child verdict when native and stock terminal observations agree.

    This deliberately ignores profile/configuration completeness. It is a fast
    execution checkpoint, not an evidence acceptance result.
    """
    reason = child.get("stop_reason") or child.get("termination_reason")
    if child.get("status") == "NOT_STARTED":
        return "NOT_STARTED"
    if reason and reason not in ("EXITED", "COMPLETED"):
        if reason == "TIMEOUT" or "TIMEOUT" in reason:
            return "TIMEOUT"
        return reason
    if child.get("signal") is not None:
        return "INTERRUPTED"
    if regular_state != "COMPLETE":
        return "INCOMPLETE"
    if terminal == "VERIFICATION:- SUCCESSFUL":
        native = "SUCCESS"
    elif isinstance(terminal, str) and terminal.startswith("VERIFICATION:- FAILED"):
        native = "FAILURE"
    else:
        return "INCOMPLETE"
    terminals = stock.get("terminal") or stock.get("terminals") or []
    if not terminals:
        if child.get("exit_code") != int(native == "FAILURE"):
            return "INCOMPLETE"
        return "VERIFIED" if native == "SUCCESS" else "FAILED"
    verdicts = [item.get("verdict") for item in terminals if isinstance(item, dict)]
    kinds = {item.get("kind") for item in terminals if isinstance(item, dict)}
    if not terminals or kinds != {"COMPLETED"} or any(value not in ("SUCCESS", "FAILURE") for value in verdicts):
        return "INCOMPLETE"
    if len(verdicts) == 1:
        exported = verdicts[0]
        if exported != native or child.get("exit_code") != int(native == "FAILURE"):
            return "INCOMPLETE"
        return "VERIFIED" if native == "SUCCESS" else "FAILED"
    if native != ("FAILURE" if "FAILURE" in verdicts else "SUCCESS"):
        return "INCOMPLETE"
    expected_exit = int("FAILURE" in verdicts)
    if child.get("exit_code") != expected_exit:
        return "INCOMPLETE"
    return "FAILED" if expected_exit else "VERIFIED"


def project(directory: Path, rows: list[dict], child: dict, *, mode: str) -> dict:
    """Project a slot's bounded logs/export into a compact observation receipt."""
    try:
        if mode == "batch" or (isinstance(mode, str) and mode.startswith("batch-")):
            kind = "batch"
        elif mode == "singleton" or (isinstance(mode, str) and mode.startswith("single")):
            kind = "singleton"
        else:
            raise ValueError("mode must identify singleton or batch")
        selectors = _validate_rows(rows)
        if not isinstance(child, dict):
            raise ValueError("child must be an object")
    except (TypeError, ValueError) as exc:
        return {"schema": "rev2-slot-projection-v1", "outcome": "INCOMPLETE",
                "complete": False, "reason": str(exc)[:512], "mode": mode}

    directory = Path(directory)
    stdout, stdout_complete, stdout_error = _read(directory / "stdout.log", STDOUT_LIMIT)
    stderr, stderr_complete, stderr_error = _read(directory / "stderr.log", STDERR_LIMIT)
    metrics = native_metrics.collect({"stdout": (stdout, stdout_complete, stdout_error),
                                      "stderr": (stderr, stderr_complete, stderr_error)}, child)
    export, export_complete, export_error = _read(directory / "export.json", MAX_INPUT_BYTES)
    input_errors = [x for x in (stdout_error, stderr_error, export_error) if x]
    regular_result = None
    native_checks, native_counts, covers, expected_cover_counts = [], {}, [], {}
    terminal = None
    if kind == "singleton" and rows:
        regular_result, native_checks, native_counts = _native(stdout, rows[0]["selector"])
        terminal = regular_result.get("terminal", {}).get("verification")
        cover_props = [p for p in regular_result.get("observations", []) if p.get("class") == "cover"]
        for label in rows[0]["covers"]:
            matched = [p for p in cover_props if p.get("description") == label]
            cover_status = [p.get("status") for p in matched]
            reached = sum(s == "SATISFIED" for s in cover_status)
            state = "OBSERVED" if matched else "NOT_OBSERVED"
            covers.append({"label": label, "state": state, "property_ids": [p.get("id") for p in matched],
                           "statuses": cover_status, "satisfied_count": reached})
            expected_cover_counts[label] = {"observed": len(matched), "satisfied": reached}
    # Batch terminal/properties are taken from the stock export only; regular text
    # does not identify a particular root reliably in a multi-root invocation.
    stock_doc = None
    stock_error = None
    try:
        stock_doc = json.loads(export.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        stock_error = f"stock export malformed: {str(exc)[:250]}"
    if not isinstance(stock_doc, dict):
        stock = {"state": "INCOMPLETE", "reason": stock_error or "stock export root is not an object"}
    elif kind == "singleton":
        parsed = evidence.stock_export(export, rows[0]["selector"])
        projection = parsed.get("observations", [{}])[0] if parsed.get("observations") else {}
        fields = projection.get("fields", {})
        if parsed.get("state") == "COMPLETE":
            errors, compact = _expected_config(stock_doc, rows)
            parsed["state"] = "INCOMPLETE" if errors else "COMPLETE"
            parsed["reason"] = "; ".join(errors) if errors else parsed.get("reason")
        else:
            errors, compact = _expected_config(stock_doc, rows)
        stock = {"state": parsed.get("state"), "reason": parsed.get("reason"),
                 "harness_location": {key: fields.get(key) for key in ("file", "line")},
                 "failed_properties": fields.get("failed_properties", []),
                 "run_state": stock_doc.get("run_state"),
                 "terminal": compact.get("terminals", []),
                 "totals": projection.get("totals", compact.get("totals", {})),
                 "property_ids": projection.get("property_buckets", compact.get("property_ids", {})),
                 "effective": {"solver": fields.get("resolved_solver"),
                               "unwind": fields.get("resolved_unwind"),
                               "checks": parsed.get("metadata", {}).get("configuration_checks"),
                               "cbmc_args": parsed.get("metadata", {}).get("cbmc_args")}}
    else:
        errors, compact = _expected_config(stock_doc, rows)
        stock = {"state": "INCOMPLETE" if errors else "COMPLETE",
                 "reason": "; ".join(errors) if errors else None, **compact}

    timing_values, phase, solver_version = _native_observations(stdout, stderr)
    if kind == "singleton" and isinstance(stock_doc, dict):
        hs = stock_doc.get("harnesses", [])
        if isinstance(hs, list) and len(hs) == 1 and isinstance(hs[0], dict) and hs[0].get("name") == selectors[0]:
            resources = hs[0].get("resources")
            if isinstance(resources, dict) and type(resources.get("verification_time_s")) in (int, float):
                timing_values["verification_seconds"] = resources["verification_time_s"]
            else:
                timing_values["verification_seconds"] = None
        else:
            timing_values["verification_seconds"] = None
    else:
        timing_values["verification_seconds"] = None
    if kind == "singleton" and timing_values["verification_seconds"] is None and timing_values["native_vt_seconds"] is not None:
        timing_values["verification_seconds"] = timing_values["native_vt_seconds"]
        timing_values["verification_seconds_source"] = "NATIVE_VERIFICATION_TIME"
    elif timing_values["verification_seconds"] is not None:
        timing_values["verification_seconds_source"] = "STOCK_EXPORT"
    compact_stock = stock.get("terminal") or stock.get("terminals") or []
    if kind == "singleton" and compact_stock and terminal and compact_stock[0].get("kind") == "COMPLETED":
        native_verdict = "SUCCESS" if terminal.startswith("VERIFICATION:- SUCCESSFUL") else (
            "FAILURE" if terminal.startswith("VERIFICATION:- FAILED") else None)
        exported = compact_stock[0]
        if (native_verdict is None or exported.get("verdict") != native_verdict
                or child.get("exit_code") != int(native_verdict == "FAILURE")):
            stock["state"] = "INCOMPLETE"
            stock["reason"] = ((stock.get("reason") + "; ") if stock.get("reason") else "") + \
                               "native/export terminal or exit-code disagreement"
    elif kind == "batch":
        timing_values["verification_seconds_by_selector"] = stock.get("verification_seconds_by_selector", {})
        values = list(timing_values["verification_seconds_by_selector"].values())
        if len(values) == len(rows) and all(type(value) in (int, float) and math.isfinite(value) for value in values):
            timing_values["verification_seconds"] = sum(values)
            timing_values["verification_seconds_source"] = "STOCK_EXPORT"
        terminals = stock.get("terminals", [])
        expected_exit = int(any(result.get("verdict") == "FAILURE" for result in terminals))
        if stock["state"] == "COMPLETE" and child.get("exit_code") != expected_exit:
            stock.update(state="INCOMPLETE", reason="export terminal and exit code disagree")

    regular_state = regular_result.get("state") if regular_result else "COMPLETE"
    observed_outcome = _observed_outcome(child, regular_state, terminal, stock)
    outcome = _outcome(child, regular_state, terminal, stock)
    supervisor_ok = (child.get("reaped") is True and child.get("sampler_valid") is True
                     and child.get("stdout_complete") is not False and child.get("stderr_complete") is not False)
    complete = (not input_errors and export_complete and stdout_complete and stderr_complete
                and stock.get("state") == "COMPLETE" and supervisor_ok
                and outcome in {"VERIFIED", "FAILED"})
    # A fully observed terminal result and a complete stock receipt are required
    # before labeling a result VERIFIED/FAILED.
    if outcome in ("VERIFIED", "FAILED") and not complete:
        outcome = "INCOMPLETE"
    resolved = {item["selector"]: {key: item[key] for key in (
        "selector", "resolved_solver", "resolved_unwind", "kind", "verdict")} for item in compact_stock}
    if (outcome in {"TIMEOUT", "RSS_LIMIT"} and (stock["state"] != "COMPLETE" or not export_complete)
            and (kind == "singleton" or mode == "batch-jobs1")):
        # Stock launch lines have no worker ID. Only sequential slots can bind them to a harness.
        for selector, observation in native_metrics.sequential_cbmc_unwinds(stdout, selectors).items():
            item = resolved.setdefault(selector, {"selector": selector, "resolved_solver": None,
                                                  "resolved_unwind": None, "kind": "UNKNOWN", "verdict": None})
            if type(item["resolved_unwind"]) is not int:
                item.update(observation)
    diagnostics = _diagnostics(stderr) or _diagnostics(stdout)
    reason = child.get("stop_reason")
    if (metrics and rows[0]["object_bits"] == 11 and reason == "EXITED" and child.get("exit_code", 0)
            and any(stream["addressed_objects"] for stream in metrics["streams"].values())):
        outcome = "OBJECT_BITS_EXHAUSTED"
        reason = "CBMC_TOO_MANY_ADDRESSED_OBJECTS"
        complete = False
    if outcome == "INCOMPLETE":
        issues = [stock.get("reason"), regular_result.get("reason") if regular_result else None, *input_errors]
        reason = "; ".join(issue for issue in issues if issue)[:1024] or "terminal or sample incomplete"
    sampled_phase = child.get("last_observed_phase") or "UNKNOWN"
    sampled_at = child.get("last_phase_monotonic")
    # An untimed output marker cannot establish ordering against a timed process sample.
    phase_observations = {
        "native_stdout": phase,
        "sampled_process_image": {"phase": sampled_phase, "monotonic": sampled_at},
    }
    prefer_sampled = sampled_phase != "UNKNOWN" and (
        phase["phase"] in {"UNKNOWN", "harness-selected"}
        or (not complete and phase["timestamp"] is None and sampled_at is not None)
    )
    phase_source = "sampled_process_image" if prefer_sampled or phase["phase"] == "UNKNOWN" else "native_stdout"
    # Keep exact bounded failure and cover witnesses even if the detailed projection is dropped.
    def bounded_witnesses(properties):
        kept = []
        for prop in properties:
            if len(kept) == 32:
                break
            if len(json.dumps(prop, ensure_ascii=False).encode("utf-8")) <= 4096:
                kept.append(prop)
        return {"records": kept, "omitted": len(properties) - len(kept)}

    mandatory_anchors = (_mandatory_anchors(rows[0], native_checks, stock)
                         if kind == "singleton" and rows else
                         {"complete": True, "regular_properties": [], "export_properties": []})
    important = [prop for prop in native_checks if prop["class"] == "cover" or prop["status"] != "SUCCESS"]
    result_evidence = {
        "regular": {"state": (regular_result or {}).get("state"), "terminal": terminal,
                    "counts": native_counts, "witnesses": bounded_witnesses(important)},
        "export": {"state": stock["state"], "reason": (stock.get("reason") or "")[:512] or None,
                   "run_state": stock.get("run_state"), "location": stock.get("harness_location"),
                   "check_terminal": compact_stock[0] if len(compact_stock) == 1 and rows[0]["check"] else None,
                   "failures": bounded_witnesses(stock.get("failed_properties", []))},
        "mandatory_anchors": mandatory_anchors,
    }
    expected_result = (_expected_result(rows[0], outcome, complete, native_checks, stock)
                       if kind == "singleton" and len(rows) == 1 else None)
    if (expected_result and expected_result.get("status") == "MATCHED" and
            not mandatory_anchors["complete"]):
        expected_result["status"] = "MISMATCHED"
        expected_result["reason"] = "mandatory assertion/cover/failure anchors are incomplete"
    result = {
        "schema": "rev2-slot-projection-v1", "mode": mode, "outcome": outcome,
        "observed_outcome": observed_outcome,
        "complete": complete, "reason": reason, "censored": outcome in {
            "TIMEOUT", "RSS_LIMIT", "LIVE_MEMORY_PRESSURE", "LIVE_MEMORY_RESERVE", "OUT_OF_MEMORY",
        },
        "supervisor": {key: child.get(key) for key in (
            "stop_reason", "wall_seconds", "peak_rss_kib", "exit_code", "signal",
            "reaped", "max_verifier_children", "last_observed_phase", "last_phase_monotonic")},
        "selectors": selectors,
        "rows": [{"id": row["id"], "selector": row["selector"],
                  "check": row["check"], "replace": row["replace"]} for row in rows],
        "timings": timing_values,
        "last_phase": phase_observations[phase_source]["phase"],
        "last_phase_timestamp": phase["timestamp"] if phase_source == "native_stdout" else None,
        "last_phase_source": phase_source,
        "last_phase_monotonic": sampled_at if phase_source == "sampled_process_image" else None,
        "phase_observations": phase_observations,
        "native_checks": native_checks if kind == "singleton" else [],
        "native_check_counts": native_counts if kind == "singleton" else {},
        "native_terminal": terminal if kind == "singleton" else None,
        "covers": covers if kind == "singleton" else [],
        "cover_counts": expected_cover_counts if kind == "singleton" else {},
        "cover_summary": ({
            "native_reached": sum(p.get("status") == "SATISFIED" and p.get("class") == "cover" for p in native_checks),
            "native_total": sum(p.get("class") == "cover" for p in native_checks),
            "expected_reached_labels": [c["label"] for c in covers if c["satisfied_count"]],
            "expected_labels_total": len(covers),
            "native_projection_complete": regular_result.get("state") == "COMPLETE",
        } if kind == "singleton" else {
            "stock_total": (stock.get("run_totals") or {}).get("covers_total"),
            "stock_reached": (stock.get("run_totals") or {}).get("covers_satisfied"),
            "label_attribution": "UNKNOWN",
        }),
        "stock": stock, "solver_version": solver_version,
        "expected_result": expected_result,
        "resolved": [resolved[selector] for selector in selectors if selector in resolved],
        "native_metrics": metrics, "result_evidence": result_evidence,
        "diagnostic_excerpt": diagnostics,
        "input_errors": input_errors,
        "source": {"regular": "singleton only", "stock": "Kani RFC 0015 export",
                   "proof_credit": "NONE"},
    }
    _fit_projection(result)
    if rows[0]["id"] in spec.SLOT_IDS and result["outcome"] == "VERIFIED" and (
            not result["complete"] or not mandatory_anchors["complete"]):
        result.update(outcome="INCOMPLETE", complete=False, reason="VERIFIED_OBSERVATION_WITH_INCOMPLETE_PROJECTION")
    return result


def _fit_projection(result):
    def encode():
        return json.dumps(result, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")).encode("utf-8")
    data = encode()
    if len(data) > MAX_PROJECTION_BYTES:
        result["complete"] = False
        result["projection_truncated"] = True
        result["native_checks"] = []
        result["native_checks_truncated"] = True
        result["diagnostic_excerpt"] = [s[:160] for s in result.get("diagnostic_excerpt", [])[:2]]
        stock = result.get("stock", {})
        if isinstance(stock, dict):
            ids = stock.get("property_ids")
            if isinstance(ids, dict):
                stock["property_ids"] = {k: (v[:512] if isinstance(v, list) else v)
                                          for k, v in ids.items()}
                stock["property_ids_truncated"] = True
        result["covers"] = result.get("covers", [])[:64]
        result["cover_counts_truncated"] = True
        data = encode()
    if len(data) > MAX_PROJECTION_BYTES:
        result["stock"] = {"state": "INCOMPLETE", "reason": "projection size cap",
                            "run_state": result.get("stock", {}).get("run_state"),
                            "totals": result.get("stock", {}).get("totals"),
                            "property_ids": {}}
        result["covers"] = []
        result["cover_counts"] = {}
        result["diagnostic_excerpt"] = []
        result["projection_truncated"] = True
        data = encode()
    if len(data) > MAX_PROJECTION_BYTES:
        # Roster summary and supervisor status are retained even for pathological input.
        keep = {key: result.get(key) for key in ("schema", "mode", "outcome", "observed_outcome", "complete", "censored",
               "selectors", "supervisor", "timings", "last_phase", "last_phase_source", "last_phase_timestamp",
               "last_phase_monotonic", "phase_observations", "source", "native_metrics", "resolved", "result_evidence",
               "reason", "cover_summary")}
        keep["complete"] = False
        keep["projection_truncated"] = True
        result.clear(); result.update(keep)
        data = encode()
    if len(data) > MAX_PROJECTION_BYTES:
        result["native_metrics"] = None
        result["resolved"] = []
        result["timings"] = {}
        result["projection_evidence_omitted"] = True
        data = encode()
    result["projection_bytes"] = len(data)
    data = encode()
    result["projection_bytes"] = len(data)
