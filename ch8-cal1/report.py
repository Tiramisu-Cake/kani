"""Generate bounded receipts and the offline N32 closure summary for general Wide and stable u64."""
import datetime
import math
import os
import time

import request as spec
from run import clocks, dump, expected_slots, receipt, record_receipt_time, save_receipt
from supervisor import REAP_SCOPE, RSS_CAVEAT

UNKNOWN = "UNKNOWN"

def read_optional(path):
    try:
        return spec.read(path)
    except (OSError, ValueError):
        return None


def cell(value):
    if value is None or value == "":
        return UNKNOWN
    if isinstance(value, float):
        return f"{value:.3f}"
    if isinstance(value, (dict, list)):
        value = ", ".join(map(str, value)) if isinstance(value, list) else ", ".join(f"{k}={v}" for k, v in value.items())
    return str(value).replace("|", "\\|").replace("\n", " ")


def memory_text(telemetry, key):
    peak = telemetry.get(key) or {}
    return f"{cell(peak.get('group_rss_kib'))} / {cell(peak.get('cbmc_rss_kib'))} ({cell(peak.get('cbmc_count'))} PID)"


def pss_text(telemetry, peak_key, nearest_key):
    peak = telemetry.get(peak_key) or {}
    pss = peak.get("pss") or {}
    if pss.get("pss_kib") is not None:
        return f"{pss['pss_kib']} PID {pss['pid']} at RSS t={cell(pss['monotonic'])}"
    neighbor = telemetry.get(nearest_key)
    absent = pss.get("reason", UNKNOWN)
    if neighbor:
        return (f"{absent}. Nearest {neighbor['pss_kib']} PID {neighbor['pid']} at "
                f"RSS t={cell(neighbor['monotonic'])}")
    return absent


def cnf_text(metrics):
    def size(item):
        return f"{item['variables']} / {item['clauses']}"

    def marker(item):
        return f"{size(item)} line {item['line']} {item['solve_context']}"

    fields = []
    initial = metrics.get("initial_solve_cnf")
    if initial:
        fields.append("initial " + size(initial))
    for name, stream in metrics.get("streams", {}).items():
        cnf = stream["first_cnf"]
        first = marker(cnf) if cnf else stream["cnf_status"]
        later = ", later " + ", ".join(marker(item) for item in stream.get("subsequent_cnf", ())) \
            if stream.get("subsequent_cnf") else ""
        coverage = "complete capture" if stream["capture_complete"] else "prefix"
        if stream["capture_truncated"]:
            coverage += ", truncated"
        if stream["incomplete_tail"]:
            coverage += ", incomplete last line"
        if stream["cnf_omitted"]:
            coverage += f", {stream['cnf_omitted']} later CNF markers omitted"
        fields.append(f"{name} {first}{later} ({coverage})")
    return ". ".join(fields) or UNKNOWN


def slot_summary(row):
    child = row.get("child", {})
    timings = row.get("timings", {})
    root = row["roots"][0]
    return {
        "id": row["id"], "mode": row["mode"], "selector": root["selector"],
        "check": root.get("check"), "replace": root.get("replace"), "geometry": root.get("geometry"),
        "check_target": (root.get("check_evidence") or {}).get("target_instance"),
        "expected_outcome": root.get("expected_outcome"), "expected_failure": root.get("expected_failure"),
        "required_assertions": root.get("required_assertions"), "required_covers": root["covers"],
        "expected_result": row.get("expected_result"), "stdout_delivery": row.get("stdout_delivery"),
        "frozen_stdout_delivery": root.get("stdout_delivery"),
        "mandatory_anchors_complete": (row.get("result_evidence") or {}).get(
            "mandatory_anchors", {}).get("complete"),
        "object_bits": row.get("object_bits"), "resolved": row.get("resolved"),
        "outcome": row["outcome"], "observed_outcome": row.get("observed_outcome"), "reason": row["reason"], "censored": row["censored"],
        "process_outcome": row.get("process_outcome"), "exit_code": child.get("exit_code"),
        "cold_wall_seconds": row.get("cold_wall_seconds"), "supervisor_wall_seconds": child.get("wall_seconds"),
        "verification_seconds": timings.get("verification_seconds"),
        "verification_seconds_source": timings.get("verification_seconds_source"),
        "compile_seconds": timings.get("compile_seconds"), "peak_rss_kib": child.get("peak_rss_kib"),
        "effective_cap_kib": child.get("effective_cap_kib"), "rss_scope": child.get("rss_scope"),
        "reaped": child.get("reaped"), "sampler_valid": child.get("sampler_valid"),
        "last_phase": row.get("last_phase", UNKNOWN), "last_phase_monotonic": row.get("last_phase_monotonic"),
        "last_phase_timestamp": row.get("last_phase_timestamp"), "last_phase_source": row.get("last_phase_source"),
        "phase_observations": row.get("phase_observations"), "covers": row.get("covers"),
        "solver_version": row.get("solver_version"), "projection_complete": row.get("projection_complete"),
        "projection": row.get("projection"),
        "projection_status": row.get("projection_status"), "projection_outcome": row.get("projection_outcome"),
        "projection_truncated": row.get("projection_truncated", False),
        "publication_truncated": row.get("publication_truncated", False),
        "projection_budget_exhausted": row.get("projection_budget_exhausted", False),
        "receipt_write_deferred": row.get("receipt_write_deferred", False),
        "receipt_write_completed_monotonic": row.get("receipt_write_completed_monotonic"),
        "receipt_deadline_monotonic": row.get("receipt_deadline_monotonic"),
        "slot_elapsed_seconds": row.get("slot_elapsed_seconds"),
        "receipt_deadline_exceeded": row.get("receipt_deadline_exceeded"),
        "receipt": f"slots/{row['id']}/receipt.json",
        "stdout_relay": relay_summary(row),
    }


def relay_summary(row):
    """Bounded delivery facts for the relay slot. None for stock slots."""
    relay = row.get("stdout_relay")
    if relay is None:
        return None
    call = relay.get("call") or {}
    return {"status": relay.get("status"), "reasons": (relay.get("reasons") or [])[:16],
            "outcome": call.get("outcome"), "cbmc_pid": call.get("cbmc_pid"), "cbmc_start_id": call.get("cbmc_start_id"),
            "argv_sha256": call.get("argv_sha256"), "kani_command_matches": relay.get("kani_command_matches"),
            "spill_bytes": call.get("spill_bytes"), "spill_sha256": call.get("spill_sha256"),
            "replay_bytes": call.get("replay_bytes"), "replay_sha256": call.get("replay_sha256"),
            "marks": {key: call.get(key) for key in ("cbmc_start_monotonic", "wait_done_monotonic",
                                                      "replay_first_byte_monotonic", "replay_end_monotonic")},
            "relay_peak_rss_kib": call.get("relay_peak_rss_kib"),
            "spill_prefix_first_cnf": next((item["first_cnf"] for item in (relay.get("spill_prefix") or {}).values()
                                            if item.get("first_cnf")), None),
            "spill_prefix_reason": relay.get("spill_prefix_reason")}


def profile(row, limits=spec.LIMITS):
    """Judge one slot. A stock slot needs its frozen STOCK_PIPE role and no relay record at all.

    The relay slot needs its frozen STDOUT_RELAY label and a COMPLETE delivery; that is necessary, never
    sufficient, for a match."""
    observed = {"verification_seconds": limits["pick_up_vt_seconds"], "cold_wall_seconds": limits["cold_wall_seconds"],
                "peak_rss_kib": limits["singleton_kib"]}
    metrics = {field: "WITHIN_LIMIT" if value <= maximum else "OVER_LIMIT"
               for field, maximum in observed.items()
               if type(value := row.get(field)) in (int, float) and math.isfinite(value) and value >= 0}
    covers = row.get("covers") or {}
    expected = covers.get("expected_labels_total")
    reached = covers.get("expected_reached_labels")
    covers_reached = (type(expected) is int and expected == len(row["required_covers"]) > 0
                      and isinstance(reached, list) and all(isinstance(label, str) for label in reached)
                      and len(reached) == expected and set(reached) == set(row["required_covers"]))
    expected_result = row.get("expected_result")
    result_observed = (isinstance(expected_result, dict) and expected_result.get("status") == "MATCHED"
                       and row["outcome"] == row["expected_outcome"] == expected_result.get("observed_outcome")
                       and type(row["exit_code"]) is int
                       and row["exit_code"] == {"VERIFIED": 0, "FAILED": 1}.get(row["expected_outcome"]))
    result = (result_observed and row["projection_complete"] is True
              and isinstance(row.get("projection"), str) and row["projection_status"] == "COMPLETE"
              and row.get("projection_truncated") is not True
              and row.get("publication_truncated") is not True
              and row.get("projection_budget_exhausted") is not True
              and row["mandatory_anchors_complete"] is True and row["reaped"] is True
              and row["sampler_valid"] is True and covers_reached)
    completed, deadline = row["receipt_write_completed_monotonic"], row["receipt_deadline_monotonic"]
    timely = (type(completed) in (int, float) and type(deadline) in (int, float)
              and math.isfinite(deadline) and 0 < completed <= deadline
              and row["receipt_deadline_exceeded"] is False and not row["receipt_write_deferred"])
    relay = row.get("stdout_relay")
    relay_required = spec.RELAY_SLOT_ID is not None and row.get("id") == spec.RELAY_SLOT_ID
    delivery = ((relay or {}).get("status") == "COMPLETE" and row.get("stdout_delivery") == "COMPLETE"
                and row.get("frozen_stdout_delivery") == spec.STDOUT_RELAY_DELIVERY if relay_required else
                relay is None and row.get("stdout_delivery") == spec.STOCK_PIPE
                and row.get("frozen_stdout_delivery") == spec.STOCK_PIPE)
    result = result and delivery
    return {"metrics": {key: metrics.get(key, UNKNOWN) for key in observed},
            "stdout_delivery": (("COMPLETE" if delivery else "INCOMPLETE") if relay_required else
                                spec.STOCK_PIPE if delivery else "NOT_STOCK_PIPE"),
            "delivery_route": spec.STDOUT_RELAY_DELIVERY if relay_required else spec.STOCK_PIPE,
            "covers_reached": covers_reached, "matched_with_required_covers": result,
            "within_profile": result and timely and not row["censored"]
                              and len(metrics) == len(observed)
                              and all(value == "WITHIN_LIMIT" for value in metrics.values())}


def summarize(ids, records, system, setup, attestation):
    rows = []
    for record in records:
        row = slot_summary(record)
        row.update(memory_telemetry=record.get("memory_telemetry"), native_metrics=record.get("native_metrics"),
                   profile=profile(row))
        rows.append(row)
    attestation = attestation or {}
    started, finished, deadline = (attestation.get(key) for key in
                                   ("started_monotonic", "finished_monotonic", "deadline_monotonic"))
    attested = (attestation.get("status") == "COMPLETE"
                and all(type(value) in (int, float) and math.isfinite(value)
                        for value in (started, finished, deadline))
                and 0 < started <= finished <= deadline)
    exact_roster = (tuple(row["id"] for row in rows) == spec.SLOT_IDS
                    and all(row["mode"] == "singleton" and len(row["roots"]) == 1 for row in records)
                    and spec.roster_digest([row["roots"][0] for row in records]) == spec.ROSTER_DIGEST)
    roster_matched = exact_roster and all(row["profile"]["matched_with_required_covers"] for row in rows)
    for row in rows:
        row["slot_status"] = ("WITHIN_PROFILE" if exact_roster and attested and
                              row["profile"]["within_profile"] else "OPEN")
    within_profile = exact_roster and attested and all(row["slot_status"] == "WITHIN_PROFILE" for row in rows)
    diagnosis = ("GEN_STABLE_N32_CLOSURE_WITHIN_PROFILE" if within_profile
                 else "GEN_STABLE_N32_CLOSURE_OPEN")
    slot_diagnoses = {row["id"]: ("WITHIN_PROFILE" if row["slot_status"] == "WITHIN_PROFILE" else "OPEN")
                      for row in rows}
    # Each type is judged on its own slots: an OPEN Wide control does not withdraw complete u64 slots.
    type_diagnoses = {
        kind: ("WITHIN_PROFILE" if exact_roster and attested and all(slot_diagnoses.get(slot) == "WITHIN_PROFILE"
                                                                     for slot in slots) else "OPEN")
        for kind, slots in spec.TYPE_SLOT_IDS.items()}
    external_obligations = [
        "These three roots do not compose N32 by themselves: each type still needs its reviewed composite admission row.",
        "Transfer the Wide S4 from N16 (left base 0 to 0, right 8 to 16) and rel4-7 from the N16 right roots by a rigid -192/+192 byte shift.",
        "Reduce rel8-14 of both types to the measured rel15 roots of 46146034746/1 by padding with h=15-R key-zero records; rel14 has no own slot.",
        "Shift the measured right rel15 to the left base by -16 records and compose the 16 merge pairs by rank with the pilot Up/Down Checks.",
        "A literal control distinguishes its post on one input; it never covers arbitrary inputs, and the Wide control counts only with COMPLETE relay delivery.",
        "N31 with 15+16 halves and the odd center stays a later stage.",
    ]
    return ids | {"platform": system, "proof_credit": "NONE", "rows": rows, "diagnosis": diagnosis,
                  "slot_diagnoses": slot_diagnoses, "type_diagnoses": type_diagnoses,
                  "external_composition": {"status": "PENDING_REVIEW", "obligations": external_obligations},
                  "roster_matched": roster_matched, "roster_within_profile": within_profile,
                  "final_attestation_status": (attestation or {}).get("status", "NOT_STARTED"),
                  "setup": {key: (setup or {}).get(key) for key in ("status", "prepare_seconds", "first_step_elapsed_seconds")},
                  "limits": {key: spec.LIMITS[key] for key in ("pick_up_vt_seconds", "cold_wall_seconds", "singleton_kib")}}


def write_summary(artifact, data):
    limits = data["limits"]
    lines = [
        "# SmallSort REV2 N32 closure for general Wide and stable u64", "",
        f"Run {data['run_id']}, attempt {data['attempt']}, {data['platform']}/{data['arch']}.", "",
        f"Diagnostic proof credit is NONE. Offline result is `{data['diagnosis']}`. By type: "
        + ", ".join(f"{kind} `{status}`" for kind, status in data["type_diagnoses"].items()) + ".", "",
        f"Offline thresholds are {limits['pick_up_vt_seconds']} s VT, {limits['cold_wall_seconds']} s cold wall "
        f"and {limits['singleton_kib']} KiB group RSS. Setup and reaping are timed separately.", "",
        "| Slot | Profile | Expected | Observed outcome | Projected outcome | Expected result | Stdout delivery | Reason | Cold wall s | VT s | Group peak / same-sample CBMC RSS KiB | CBMC peak RSS KiB | CBMC PSS at group RSS peak or nearest | CBMC PSS at CBMC RSS peak or nearest | CNF variables / clauses | Last phase | Covers reached |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | ---: | ---: | --- | ---: | --- | --- | --- | --- | --- |",
    ]
    for row in data["rows"]:
        memory = row["memory_telemetry"] or {}
        covers = row["covers"] or {}
        expected_result = row.get("expected_result") or {}
        values = (row["id"], row["slot_status"], row.get("expected_outcome"), row.get("observed_outcome"), row["outcome"],
                  expected_result.get("status", "UNAVAILABLE"),
                  f"{row['profile']['delivery_route']} {row['profile']['stdout_delivery']}",
                  expected_result.get("reason") or row["reason"], row["cold_wall_seconds"], row["verification_seconds"],
                  memory_text(memory, "group_peak"), (memory.get("cbmc_peak") or {}).get("cbmc_rss_kib"),
                  pss_text(memory, "group_peak", "nearest_pss_to_group_peak"),
                  pss_text(memory, "cbmc_peak", "nearest_pss_to_cbmc_peak"), cnf_text(row["native_metrics"] or {}),
                  row["last_phase"], f"{len(covers.get('expected_reached_labels', ()))}/{covers['expected_labels_total']}"
                  if "expected_labels_total" in covers else None)
        lines.append("| " + " | ".join(map(cell, values)) + " |")
    lines += ["", "Three singletons close the native N32 roots: the exact left stable u64 S8 in V34/D48 on the stock "
              "pipe, the literal stable u64 control through the actual stable entry with an external D48 on the stock "
              "pipe, and the literal Wide control through the actual unstable entry behind the CBMC stdout relay. "
              "Each slot keeps its own measurement when the overall result is OPEN.",
              f"Frozen roster matched by outcome: `{data['roster_matched']}`. "
              f"Roster within profile: `{data['roster_within_profile']}`.",
              f"Setup status is {cell(data['setup']['status'])} at {cell(data['setup']['first_step_elapsed_seconds'])} s. "
              f"Final attestation is {data['final_attestation_status']}.", "", RSS_CAVEAT, "", REAP_SCOPE]
    lines += ["", "## External composition pending review", ""]
    lines.extend(f"- {obligation}" for obligation in data["external_composition"]["obligations"])
    for row in data["rows"]:
        relay = row.get("stdout_relay")
        if relay is not None:
            lines += ["", f"`{row['id']}` stdout delivery is {cell(relay['status'])}, relay outcome "
                      f"{cell(relay['outcome'])}, {cell(relay['replay_bytes'])} of {cell(relay['spill_bytes'])} bytes "
                      "replayed after the real CBMC was reaped."]
            if relay.get("spill_prefix_first_cnf"):
                cnf = relay["spill_prefix_first_cnf"]
                lines += ["", f"Its spill prefix after reap shows a first CNF of {cnf['variables']} variables / "
                          f"{cnf['clauses']} clauses. This observation does not replace regular or stock acceptance."]
            elif relay.get("spill_prefix_reason"):
                lines += ["", f"No spill-prefix CNF was recovered: {relay['spill_prefix_reason']}."]
        if row.get("censored"):
            lines += ["", f"`{row['id']}` was censored in phase `{row['last_phase']}`."]
    (artifact / "SUMMARY.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    dump(artifact / "SUMMARY.json", data | {"rss_caveat": RSS_CAVEAT, "reap_scope": REAP_SCOPE})


def mark_projection_missing(record, status):
    record.update(projection=None, projection_complete=False, projection_status=status)
    if record["outcome"] == "VERIFIED":
        record.update(outcome="INCOMPLETE", reason="VERIFIED_OBSERVATION_WITH_INCOMPLETE_PROJECTION")



def artifact_inventory(artifact):
    members = {}
    index_path = artifact / "index.json"
    for path in sorted(artifact.rglob("*")):
        spec.require(not path.is_symlink(), "artifact contains a symbolic link")
        if path.is_file() and path != index_path:
            size = path.stat().st_size
            if path.name == "projection.json":
                spec.require(size <= spec.LIMITS["projection_bytes"], "artifact projection cap exceeded")
            members[str(path.relative_to(artifact))] = {"bytes": size, "sha256": spec.sha256(path)}
    return members


def artifact_pins(request):
    return {
        "schema": spec.ARTIFACT_SCHEMA, "proof_credit": "NONE", "ledger_item": request["ledger_item"],
        "stdlib_base": request["base"], "overlay": request["overlay"], "tool": request["tool"],
        "source_bindings_sha256": spec.roster_digest(request["source_bindings"]),
        "roster_sha256": spec.roster_digest(request["roster"]),
        "overlay_bundle_sha256": request["overlay_bundle_sha256"],
        "pilot_overlay": request["pilot_overlay"],
        "pilot_fix1_overlay": request["pilot_fix1_overlay"],
        "close_overlay": request["close_overlay"],
        "wide_witness_overlay": request["wide_witness_overlay"],
        "n10_wide_witness_overlay": request["n10_wide_witness_overlay"],
        "n12_wide_witness_overlay": request["n12_wide_witness_overlay"],
        "stdout_relay_source_sha256": request["stdout_relay"]["source_sha256"],
        "frozen_request_sha256": spec.sha256(spec.HERE / "CI-REQUEST.json"),
    }


def validate_artifact_index(artifact, request):
    index_path = artifact / "index.json"
    spec.require(index_path.is_file() and not index_path.is_symlink()
                 and 0 < index_path.stat().st_size <= spec.MIB, "missing or oversized artifact index")
    index = spec.read(index_path)
    spec.require(isinstance(index, dict), "invalid artifact index")
    for key, expected in artifact_pins(request).items():
        spec.require(index.get(key) == expected, f"artifact index mismatch for {key}")
    members = artifact_inventory(artifact)
    required = {"request.json", "SUMMARY.md", "SUMMARY.json",
                *(f"slots/{slot}/receipt.json" for slot in spec.SLOT_IDS)}
    spec.require(required <= members.keys() and members == index.get("members"),
                 "artifact inventory differs from the index or lacks required files")
    spec.require(sum(member["bytes"] for member in members.values()) + index_path.stat().st_size
                 <= spec.LIMITS["artifact_bytes"], "artifact publication cap exceeded")
    spec.require(spec.read(artifact / "request.json") == request, "artifact request differs from frozen request")
    return index

def finish(state, request, system):
    artifact = state / "artifact"
    artifact.mkdir(exist_ok=True)
    boundaries = clocks(state) if (state / "epoch").is_file() else None
    source = read_optional(state / "source.json")
    setup = read_optional(state / "setup.json")
    end = read_optional(state / "end.json")
    attestation = read_optional(state / "attestation.json")
    discovery = read_optional(state / "discovery.json")
    failure = read_optional(state / "error.json")
    finalization = read_optional(state / "receipt-finalization.json") or {}
    timings = finalization.get("timings", {})
    pending = finalization.get("pending", {})
    for partial_path in artifact.glob("slots/*/*.tmp"):
        partial_path.unlink()
    records = []
    reason = (failure or {}).get("message") or (attestation or {}).get("error") or (
        (setup or {}).get("error") or ("SETUP_OR_DISCOVERY_FAILED" if not discovery else "MEASUREMENT_INTERRUPTED")
    )
    for slot in expected_slots(request):
        key = slot[0]
        record = read_optional(artifact / "slots" / key / "receipt.json")
        deferred = pending.get(key)
        if deferred is not None:
            record = deferred
            save_receipt(state, record)
            if record.get("receipt_write_deferred") and "child" in record:
                record_receipt_time(record, time.monotonic())
                record["receipt_deadline_exceeded"] = True
                save_receipt(state, record)
        elif record is None:
            record = receipt(slot, "NOT_STARTED", reason)
            if boundaries is not None:
                record["latest_start_monotonic"] = boundaries["latest_starts"][key]
            save_receipt(state, record)
        elif key in timings:
            record.update(timings[key])
            save_receipt(state, record)
        projection = artifact / "slots" / key / "projection.json"
        if record.get("projection_complete") is True and (
            record.get("projection") != str(projection.relative_to(artifact)) or not projection.is_file()
        ):
            mark_projection_missing(record, "MISSING")
            save_receipt(state, record)
        records.append(record)
    ids = {label: os.environ.get(variable, UNKNOWN) for label, variable in (
        ("run_id", "GITHUB_RUN_ID"), ("attempt", "GITHUB_RUN_ATTEMPT"), ("run_sha", "GITHUB_SHA"),
        ("arch", "RUNNER_ARCH"),
    )}

    def summary():
        return summarize(ids, records, system, setup, attestation)

    # Tool identity reports and ordered discovery are bounded, named evidence members.
    for name, data in (("source", source), ("setup", setup), ("end", end), ("attestation", attestation),
                       ("discovery", discovery), ("error", failure)):
        if data is not None:
            dump(artifact / f"{name}.json", data)
    dump(artifact / "request.json", request)
    write_summary(artifact, summary())
    members = artifact_inventory(artifact)
    dropped = []
    while sum(v["bytes"] for v in members.values()) > spec.LIMITS["artifact_bytes"] - spec.MIB:
        largest = max((p for p in members if p.endswith("/projection.json") or p.endswith("/timeline.json")),
                      key=lambda p: members[p]["bytes"], default=None)
        spec.require(largest is not None, "mandatory summaries and receipts exceed artifact limit")
        (artifact / largest).unlink()
        dropped.append(largest)
        record = next(row for row in records if row["id"] == largest.split("/")[1])
        record["projection" if largest.endswith("/projection.json") else "timeline"] = None
        if largest.endswith("/projection.json"):
            mark_projection_missing(record, "PUBLICATION_DROPPED")
        record["publication_truncated"] = True
        save_receipt(state, record)
        write_summary(artifact, summary())
        members = artifact_inventory(artifact)
    measured = bool(end and any(record.get("child", {}).get("sampler_valid") for record in records))
    index = ids | artifact_pins(request) | {
        "platform": system,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "calibration_status": "MEASURED" if measured else "INCOMPLETE",
        "job_status": os.environ.get("REV2_JOB_STATUS", UNKNOWN),
        "trigger": (source or {}).get("trigger") or read_optional(state / "trigger.json"),
        "cal1_overlay": request.get("cal1_overlay"), "cal2_overlay": request.get("cal2_overlay"),
        "fix3_overlay": request.get("fix3_overlay"), "binding_overlay": request.get("binding_overlay"),
        "geometries_overlay": request.get("geometries_overlay"), "consumer_overlay": request["consumer_overlay"],
        "composite_overlay": request["composite_overlay"], "n17_overlay": request["n17_overlay"],
        "merge_pair_fixed_overlay": request["merge_pair_fixed_overlay"],
        "n20_n21_consumer_overlay": request["n20_n21_consumer_overlay"],
        "n22_n25_providers_overlay": request["n22_n25_providers_overlay"],
        "u64_n26_n32_consumer_overlay": request["u64_n26_n32_consumer_overlay"],
        "n22_n25_consumer_overlay": request["n22_n25_consumer_overlay"],
        "halves_overlay": request["halves_overlay"],
        "merge_overlay": request["merge_overlay"],
        "n26_n31_consumer_overlay": request["n26_n31_consumer_overlay"],
        "copy_back_overlay": request["copy_back_overlay"],
        "u64_n13_overlay": request["u64_n13_overlay"],
        "machine": (source or {}).get("machine"), "version_first_lines": (setup or {}).get("version_first_lines"),
        "solver_versions_observed": sorted({r["solver_version"] for r in records if isinstance(r.get("solver_version"), str)}),
        "clocks": boundaries,
        "final_attestation_status": (attestation or {}).get("status", "NOT_STARTED"),
        "members": members, "dropped_optional_members": dropped,
        "summary": "SUMMARY.json", "slots": [slot_summary(row) for row in records],
    }
    dump(artifact / "index.json", index)
    spec.require(sum(v["bytes"] for v in members.values()) + (artifact / "index.json").stat().st_size
                 <= spec.LIMITS["artifact_bytes"], "artifact publication cap exceeded")
