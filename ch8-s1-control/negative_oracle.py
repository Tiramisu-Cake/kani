"""Exact negative-observation oracle helpers.

This module recognizes a named assertion only after the caller has already
bound the export to its request row and pinned source. Oracle absence is a
closed failure; textual descriptions are never property identities.
"""
from __future__ import annotations

from typing import Any


def matches(harness: Any, oracle: Any) -> bool:
    if not isinstance(harness, dict) or not isinstance(oracle, dict):
        return False
    selector, property_id = oracle.get("selector"), oracle.get("property_id")
    export_file, line, prop_class = oracle.get("export_file"), oracle.get("line"), oracle.get("class")
    if (not all(isinstance(x, str) and x for x in (selector, property_id, export_file)) or
            not isinstance(line, int) or isinstance(line, bool) or line < 1 or
            prop_class != "assertion"):
        return False
    if (harness.get("name") != selector or
            harness.get("outcome") != {"kind": "COMPLETED", "verdict": "FAILURE"}):
        return False
    checks, covers, named = harness.get("checks"), harness.get("covers"), harness.get("failed_properties")
    if not isinstance(checks, dict) or not isinstance(covers, dict) or not isinstance(named, list) or len(named) != 1:
        return False
    if type(harness.get("n_failed")) is not int or harness["n_failed"] != 1:
        return False
    if checks.get("failure") != [property_id]:
        return False
    for key in ("undetermined", "error", "unknown", "other"):
        if checks.get(key) != []:
            return False
    unreachable = checks.get("unreachable")
    if not isinstance(unreachable, list) or any(not isinstance(x, str) for x in unreachable):
        return False
    if len(set(unreachable)) != len(unreachable) or property_id in unreachable:
        return False
    if any(type(checks.get(k)) is not int or checks[k] < 0 for k in ("total", "success")):
        return False
    if checks["total"] != checks["success"] + len(unreachable) + 1:
        return False
    sat = covers.get("satisfied")
    if (not isinstance(sat, list) or any(not isinstance(x, str) for x in sat) or
            len(set(sat)) != len(sat) or type(covers.get("total")) is not int or covers["total"] != len(sat)):
        return False
    if any(covers.get(k) != [] for k in ("unsatisfiable", "unreachable", "undetermined", "error", "unknown", "other")):
        return False
    if type(harness.get("n_properties")) is not int or harness["n_properties"] != checks["total"] + covers["total"]:
        return False
    unsupported = harness.get("unsupported_constructs")
    if (not isinstance(unsupported, list) or
            any(not isinstance(p, dict) or p.get("status") != "SUCCESS" or
                p.get("class") != "unsupported_construct" for p in unsupported)):
        return False
    prop = named[0]
    return (isinstance(prop, dict) and prop.get("id") == property_id and prop.get("file") == export_file and
            prop.get("line") == str(line) and prop.get("class") == "assertion" and
            prop.get("status") == "FAILURE")
