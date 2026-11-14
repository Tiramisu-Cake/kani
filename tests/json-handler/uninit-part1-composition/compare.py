#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Root-local composition oracle with exact per-root comparisons."""
from collections import Counter


class Rejected(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Rejected(message)


def freeze(value):
    """Make JSON identities comparable without discarding any fields."""
    if isinstance(value, dict):
        return tuple((key, freeze(value[key])) for key in sorted(value))
    if isinstance(value, list):
        return tuple(freeze(item) for item in value)
    return value


def inventory(root_observation):
    require(root_observation.get("inventory_complete") is True,
            "incomplete per-root inventory")
    require(root_observation.get("actual_root") == root_observation.get("expected_root"),
            "wrong root binding")
    rows = root_observation.get("checks")
    require(isinstance(rows, list), "missing check inventory")
    ids = [row.get("id") for row in rows if isinstance(row, dict)]
    require(len(ids) == len(rows) and all(isinstance(item, str) and item for item in ids),
            "malformed check row")
    require(len(set(ids)) == len(ids), "duplicate check identity")
    require(all(row.get("status") in {"SUCCESS", "FAILURE", "UNREACHABLE"}
                for row in rows), "nonterminal check status")
    covers = root_observation.get("covers")
    require(isinstance(covers, list), "missing cover inventory")
    cover_ids = [row.get("id") for row in covers if isinstance(row, dict)]
    require(len(cover_ids) == len(covers)
            and all(isinstance(item, str) and item for item in cover_ids)
            and len(set(cover_ids)) == len(cover_ids)
            and not set(cover_ids) & set(ids), "malformed/duplicate cover identity")
    require(all(row.get("status") in {"SATISFIED", "UNSATISFIABLE", "UNREACHABLE"}
                for row in covers), "nonterminal cover status")
    failure_kind = root_observation.get("failure_kind")
    require(failure_kind in {"ERROR", "NONE", "OTHER", "PANICS_ONLY"},
            "missing/invalid failure kind")
    failures = root_observation.get("failed_properties")
    unsupported = root_observation.get("unsupported_constructs")
    require(isinstance(failures, list), "missing failed-properties inventory")
    require(isinstance(unsupported, list), "missing Unsupported inventory")
    for label, properties in (("failure", failures), ("Unsupported", unsupported)):
        ids = [prop.get("id") for prop in properties if isinstance(prop, dict)]
        require(len(ids) == len(properties) and all(isinstance(item, str) and item for item in ids),
                f"malformed {label} inventory")
        require(len(ids) == len(set(ids)), f"duplicate {label} identity")
        require(all(prop.get("status") in {"SUCCESS", "FAILURE", "UNREACHABLE"}
                    for prop in properties), f"nonterminal {label} status")
        required_fields = {"id", "description", "class", "file", "line", "trace_available", "status"}
        require(all(required_fields <= set(prop) for prop in properties),
                f"incomplete {label} metadata")
    failure_ids = {prop["id"] for prop in rows if prop["status"] == "FAILURE"}
    require(failure_ids == {prop["id"] for prop in failures},
            "failed-properties/check failure identities differ")
    require(type(root_observation.get("n_failed")) is int
            and root_observation["n_failed"] == len(failures),
            "failed-property counter mismatch")
    check_by_id = {prop["id"]: prop for prop in rows}
    failed_by_id = {prop["id"]: prop for prop in failures}
    for prop in failures:
        require(prop["status"] == "FAILURE", "failed-properties status is not FAILURE")
        check = check_by_id[prop["id"]]
        require(check["description"] == prop["description"],
                "failed-properties/check description drift")
    for prop in unsupported:
        require(prop["id"] in check_by_id, "Unsupported ID absent from complete check inventory")
        check = check_by_id[prop["id"]]
        require(check["status"] == prop["status"] and check["description"] == prop["description"],
                "Unsupported/check inventory drift")
        if prop["status"] == "FAILURE":
            require(prop["id"] in failed_by_id, "failed Unsupported absent from failure inventory")
            failure = failed_by_id[prop["id"]]
            require(all(prop[key] == failure[key] for key in
                        ("description", "class", "file", "line", "trace_available", "status")),
                    "failed Unsupported metadata drift")
    return (Counter(freeze(row) for row in rows), failure_kind,
            Counter(freeze(row) for row in failures),
            Counter(freeze(row) for row in unsupported),
            Counter(freeze(row) for row in covers))


def check_single(root_observation, expected):
    """Compare one complete isolated root against reviewed exact identities."""
    actual = inventory(root_observation)
    require(expected.get("binding") == "REGRESSION_BOUND",
            "BINDING_PENDING: exact root inventories require coordinator review")
    rows = expected.get("checks")
    require(isinstance(rows, list), "missing reviewed check inventory")
    require(actual[0] == Counter(freeze(row) for row in rows),
            "lost check, extra check, or status/identity drift")
    for field, index, label in (("failed_properties", 2, "full failure inventory"),
                                ("unsupported_constructs", 3, "Unsupported inventory")):
        expected_rows = expected.get(field)
        require(isinstance(expected_rows, list), f"missing reviewed {label}")
        require(actual[index] == Counter(freeze(row) for row in expected_rows),
                f"{label} differs from reviewed binding")
    require(actual[1] == expected.get("failure_kind"),
            "failure kind differs from reviewed binding")
    require(actual[4] == Counter(freeze(row) for row in expected.get("covers", [])),
            "cover inventory differs from reviewed binding")
    failed = [row for row in rows if row.get("status") == "FAILURE"]
    require(root_observation.get("verdict") == expected.get("expected_verdict"),
            "wrong root verdict")
    observed_failed = [row for row in root_observation["checks"] if row["status"] == "FAILURE"]
    require(Counter(freeze(row) for row in observed_failed) == Counter(freeze(row) for row in failed),
            "extra or missing failure")
    return True


def compare_selection(run, expected_roots):
    """Validate a single or multi-root selection and return roots by exact name."""
    require(run.get("run_state") == "COMPLETE", "run incomplete")
    roots = run.get("roots")
    requested = run.get("requested_roots")
    require(isinstance(roots, list) and isinstance(requested, list), "missing selection/root list")
    names = [root.get("expected_root") for root in roots]
    require(len(names) == len(set(names)), "duplicate selected root")
    require(set(names) == set(requested), "selected root inventory incomplete or extra")
    require(set(requested) <= set(expected_roots), "unexpected requested root")
    by_name = {root["expected_root"]: root for root in roots}
    for name, observation in by_name.items():
        inventory(observation)
        require(observation.get("actual_root") == name, "wrong root in selected output")
    return by_name


def row_difference(before, after):
    """Preserve exact rows and multiplicities for a JSON-serializable diff."""
    remaining = Counter(freeze(row) for row in after)
    difference = []
    for row in before:
        key = freeze(row)
        if remaining[key]:
            remaining[key] -= 1
        else:
            difference.append(row)
    return difference


def compare_root(isolated, combined):
    """Return all drift and accept only exact equality of the complete inventories."""
    inventory(isolated)
    inventory(combined)
    require(isolated["expected_root"] == combined["expected_root"], "different root bindings")
    differences = {}
    for field in ("checks", "failed_properties", "unsupported_constructs", "covers"):
        removed = row_difference(isolated[field], combined[field])
        added = row_difference(combined[field], isolated[field])
        if removed or added:
            differences[field] = {"removed": removed, "added": added}
    for field in ("verdict", "failure_kind"):
        if isolated[field] != combined[field]:
            differences[field] = {"isolated": isolated[field], "combined": combined[field]}
    accepted = not differences
    return {"root": isolated["expected_root"], "accepted": accepted,
            "exact_match": not differences, "differences": differences}


def compare_pair(isolated, combined, expected_roots):
    """Require every selected root's complete inventory to match isolation exactly."""
    singles = compare_selection(isolated, expected_roots)
    joint = compare_selection(combined, expected_roots)
    require(set(singles) == set(joint), "combined selection has different roots")
    for name in singles:
        require(compare_root(singles[name], joint[name])["accepted"],
                f"mixed-root inventory changed: {name}")
    return True
