# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Inspect complete exports; never infer transformed-mode binding or proof credit."""


def require(condition, message):
    if not condition:
        raise ValueError(message)


def names_target(name, target):
    return name == target or name.endswith("::" + target)


def observe(data, root, exit_code):
    require(data.get("schema_version") == "0.1.0", "unexpected export schema")
    require(data.get("run_state") == "COMPLETE", "run did not complete")
    require(data.get("outcome", {}).get("kind") == "COMPLETED", "run outcome incomplete")
    selection = data["harness_selection"]
    require(selection["exact"] and selection["matched_count"] == 1
            and not selection["unmatched_filters"]
            and selection["requested_filters"] == [root["harness"]], "selection drift")
    require(len(data["harnesses"]) == 1, "expected exactly one root")
    harness = data["harnesses"][0]
    require(harness["name"] == root["harness"], "root name drift")
    outcome = harness["outcome"]
    require(outcome.get("kind") == "COMPLETED", "harness did not complete")
    verdict = outcome.get("verdict")
    require(verdict in ("SUCCESS", "FAILURE"), "missing completed verdict")
    require(exit_code == (0 if verdict == "SUCCESS" else 1), "exit/verdict mismatch")
    attrs = harness["attributes"]
    require(not attrs["should_panic"] and not attrs["stubs"], "unexpected harness attributes")
    require(attrs["unwind_value"] == 8 and harness["resolved_unwind"] == 8, "unwind drift")
    mode, target = root["intended_mode"], root["target"]
    if mode == "Replace":
        require(attrs["kind"] == "Proof" and len(attrs["verified_stubs"]) == 1
                and names_target(attrs["verified_stubs"][0], target), "verified stub missing")
    elif mode in ("SimpleCheck", "RecursiveCheck"):
        require(not attrs["verified_stubs"], "unexpected verified stub")
        kind = attrs["kind"]
        require(isinstance(kind, dict) and set(kind) == {"ProofForContract"}
                and names_target(kind["ProofForContract"]["target_fn"], target), "PFC target drift")
        require(harness["contract"] is not None, "no attached contract")
        tracker = harness["contract"]["recursion_tracker"]
        require(bool(tracker) == (mode == "RecursiveCheck"), "recursion tracker drift")
    else:
        require(mode == "Assert" and attrs["kind"] == "Proof"
                and not attrs["verified_stubs"], "ordinary companion metadata drift")

    configuration = data["configuration"]
    required_checks = ("memory_safety", "overflow", "unwinding", "undefined_function",
                       "assertion_reach_checks", "assert_contracts")
    require(all(configuration["checks"][name] for name in required_checks), "checks weakened")
    require(not configuration["checks"]["prove_safety_only"], "prove-safety-only enabled")
    require(configuration["cbmc_args"] == ["--object-bits", "12"], "CBMC profile drift")
    require({"uninit-checks", "function-contracts", "export-json", "unstable-options"}
            <= set(data["enabled_unstable_features"]), "required feature missing")
    checks, covers = harness["checks"], harness["covers"]
    for inventory in (checks, covers):
        require(not any(inventory[name] for name in ("undetermined", "error", "unknown", "other")),
                "unresolved property status")
    failed = harness["failed_properties"]
    failure_ids = [prop["id"] for prop in failed]
    require(len(set(failure_ids)) == len(failure_ids), "duplicate failure")
    require(set(failure_ids) == set(checks["failure"]), "failure inventory drift")
    require(all(prop["status"] == "FAILURE" for prop in failed), "non-failure in failures")
    require(harness["n_failed"] == len(failed), "failure count drift")
    require((verdict == "FAILURE") == bool(failed), "verdict/failures disagree")
    require(checks["total"] == checks["success"] + len(failed) + len(checks["unreachable"]),
            "check inventory incomplete")
    require(covers["total"] == sum(len(covers[key]) for key in
                                  ("satisfied", "unsatisfiable", "unreachable")),
            "cover inventory incomplete")
    require(harness["n_properties"] == checks["total"] + covers["total"], "property count drift")
    require(covers["total"] >= 2, "path cover properties missing")
    summary = data["summary"]
    expected_summary = dict(total=1, successful=int(verdict == "SUCCESS"),
                            failed=int(verdict == "FAILURE"), checks_total=checks["total"],
                            checks_success=checks["success"], covers_total=covers["total"],
                            covers_satisfied=len(covers["satisfied"]))
    require(all(summary[key] == value for key, value in expected_summary.items()), "summary drift")
    gaps = []
    if any(prop["status"] not in ("SUCCESS", "UNREACHABLE")
           for prop in harness["unsupported_constructs"]):
        gaps.append("UNSUPPORTED_PRESENT: does not establish the intended boundary")
    if any("assignable" in prop["description"] for prop in failed):
        gaps.append("FRAME_FAILURE: lawful prefix requires review")
    if covers["unsatisfiable"] or covers["unreachable"]:
        gaps.append("PATH_COVERS_INCOMPLETE: inspect prefix/base/recursive/return binding")
    return {
        "harness": root["harness"], "intended_mode": mode,
        "completed_outcome": outcome, "failures": failed, "checks": checks, "covers": covers,
        "unsupported_constructs": harness["unsupported_constructs"],
        "metadata_consistent": True, "binding_status": "BINDING_PENDING",
        "boundary_review": "UNREVIEWED", "gaps": gaps,
        "companion_pass": (verdict == "SUCCESS" and not gaps) if root["companion"] else None,
        "mode_qualification": False,
    }
