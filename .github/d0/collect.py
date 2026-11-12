#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Collect only bounded, explicitly selected data for D0-A; raw evidence stays private."""
import argparse
from collections import Counter
import gzip
import hashlib
import json
import os
from pathlib import Path
import shutil

import inventory
from run import A, B, BASELINE, CANDIDATE, digest, manifest_tree, write

MAX_PACKET = 5 * 1024 * 1024
MAX_FILE = 384 * 1024
CONTROL_STAGES = {"unit", "prewarm-policy", "prewarm-begin", "prewarm-end", "normal-order", "actual-order", "harness-begin"}
REQUIRED_STAGES = {"unit", "prewarm-policy", "normal-order", "actual-order", "harness-begin",
                   "mir-original", "local-pass-before", "local-pass-after", "cache-write-local",
                   "cache-read", "codegen-consumed-mir", "raw-eq-operand"}


def load(path):
    return json.loads(path.read_text())


def bounded_write(path, data, cap=MAX_FILE):
    encoded = (json.dumps(data, indent=2) + "\n").encode()
    if len(encoded) > cap:
        raise ValueError(f"curated file cap: {path.name} ({len(encoded)} bytes)")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded)


def split_captures(paths, version):
    """The pinned driver also runs exactly `cbmc --version` before compiling."""
    solvers, probes, errors = [], [], []
    for meta in paths:
        data = load(meta)
        if not isinstance(data, dict) or data.get("argv") != ["cbmc", "--version"]:
            solvers.append(meta)
            continue
        raw = meta.with_name(meta.name.replace(".meta.json", ".json"))
        complete = (data.get("capture_state") == "COMPLETE" and data.get("captured_complete") is True
                    and type(data.get("dropped_bytes")) is int and data["dropped_bytes"] == 0
                    and type(data.get("child_exit")) is int and data["child_exit"] == 0
                    and data.get("child_signal") is None and data.get("wrapper_signal") is None
                    and raw.stat().st_size <= 4096 and data.get("retained_bytes") == raw.stat().st_size
                    and digest(raw) == data.get("original_stdout_sha256")
                    and raw.read_text().strip() == version)
        probes.append({"argv": data["argv"], "original_exit": data.get("child_exit"),
                       "capture_id": data.get("capture_id"), "meta_sha256": digest(meta),
                       "stdout_sha256": digest(raw), "complete": complete})
        if not complete:
            errors.append("CBMC version probe capture incomplete or tool identity mismatch")
    return solvers, probes, errors


def comparison_inventory(case_root):
    """Strict controls: normalize only the recorded checkout/output paths."""
    phases = load(case_root / "phases.json")
    checkout = str(Path(phases["verification"]["argv"][0]).parent.parent)
    replacements = ((str(case_root), "<CASE_OUTPUT>"), (checkout, "<CHECKOUT>"))

    def normalize(value):
        if isinstance(value, str):
            for old, new in replacements:
                value = value.replace(old, new)
            return value
        if isinstance(value, dict):
            return {key: normalize(item) for key, item in value.items()}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value

    result = {}
    for directory in sorted((case_root / "inventory").iterdir()):
        manifest = load(directory / "manifest.json")
        name = manifest["root"]["pretty_name"]
        if name in result:
            raise ValueError("duplicate harness in control inventory")
        properties = load(directory / "property-inventory.json")["properties"]
        props = [{key: row.get(key) for key in ("property_id", "description", "class", "source_location", "result_status")}
                 for row in properties]
        listing = load(directory / "goto-functions.inventory.json")
        encode = lambda value: json.dumps(normalize(value), sort_keys=True, separators=(",", ":")).encode()
        result[name] = {"property_ids": sorted(row["property_id"] for row in props),
                        "property_inventory_sha256": hashlib.sha256(encode(sorted(props, key=lambda row: row["property_id"]))).hexdigest(),
                        "goto_listing_sha256": hashlib.sha256(encode(listing)).hexdigest(),
                        "original_input_sha256": manifest["capture"]["input_sha256"]}
    if not result:
        raise ValueError("no solver inventories for comparison")
    mir = []
    for path in sorted((case_root / "model").rglob("*.mir")):
        if path.stat().st_size > 64 * 1024 * 1024:
            raise ValueError("emitted MIR comparison cap")
        mir.append({"file": str(path.relative_to(case_root / "model")),
                    "normalized_sha256": hashlib.sha256(normalize(path.read_text()).encode()).hexdigest()})
    return {"harnesses": result, "emitted_mir": mir or "NOT_RUN",
            "normalization": "recorded absolute checkout/output paths only; no alpha-renaming"}


def compare_controls(root):
    reports = []
    errors = []
    for candidate_case, baseline_case in (("A", "A"), ("B", "B"), ("D", "pair")):
        report = {"candidate_case": candidate_case, "baseline_case": baseline_case, "status": "UNKNOWN",
                  "full_original_final_consumed_MIR_equivalence": "UNKNOWN", "causal_claim": False}
        try:
            candidate = comparison_inventory(root / "candidate/cases" / candidate_case)
            baseline = comparison_inventory(root / "baseline/cases" / baseline_case)
            report.update(candidate=candidate, baseline=baseline)
            left, right = candidate["harnesses"], baseline["harnesses"]
            same_roots = set(left) == set(right)
            report["same_roots"] = same_roots
            report["property_inventories_equal"] = same_roots and all(left[name]["property_inventory_sha256"] == right[name]["property_inventory_sha256"] for name in left)
            report["goto_listings_equal"] = same_roots and all(left[name]["goto_listing_sha256"] == right[name]["goto_listing_sha256"] for name in left)
            report["emitted_mir_equal"] = candidate["emitted_mir"] == baseline["emitted_mir"] if isinstance(candidate["emitted_mir"], list) and isinstance(baseline["emitted_mir"], list) else "UNKNOWN"
            report["status"] = "INVENTORIES_MATCH" if report["property_inventories_equal"] and report["goto_listings_equal"] else "MISMATCH_STOP"
            if report["status"] == "MISMATCH_STOP" or report["emitted_mir_equal"] is False:
                errors.append(f"{candidate_case}/{baseline_case}: strict property/GOTO/MIR control mismatch; STOP comparison")
        except (OSError, ValueError, KeyError, TypeError) as error:
            report["error"] = str(error)[:256]
            errors.append(f"{candidate_case}/{baseline_case}: control inventory incomplete")
        reports.append(report)
    return reports, errors


def summarize_compiler(case, destination):
    directory = case / "compiler"
    index = manifest_tree(directory)
    compressed = gzip.compress((json.dumps(index, separators=(",", ":")) + "\n").encode(), mtime=0)
    if len(compressed) > MAX_FILE:
        raise ValueError("sidecar index exceeds packet cap")
    (destination / "sidecar-manifest.json.gz").write_bytes(compressed)
    counts = Counter()
    coverage = []
    selected = []
    dropped = 0
    selected_bytes = 0
    instances = {}
    for path in sorted(directory.glob("*.json")):
        row = load(path)
        if path.name.endswith("-coverage.json"):
            coverage.append(row)
            continue
        if row.get("schema") != "kani3300-d0/v1" or row.get("case") != case.name or row.get("unit") != 0 or row.get("cache") != 0:
            raise ValueError("sidecar source/stage/target mismatch")
        stage = row.get("stage")
        counts[stage] += 1
        key = (row.get("root", ""), row.get("instance") or "N/A", row.get("symbol") or "N/A", stage)
        instances[key] = instances.get(key, 0) + 1
        # Exact controls and root/spec_eq observations only; never full GOTO listings.
        target = any(name in (row.get("instance") or "") for name in (A, B, "SpecArrayEq", "spec_eq"))
        if stage in CONTROL_STAGES or target:
            data = {**row, "file": path.name, "sha256": digest(path),
                    "source_index": row["sequence"], "causal_claim": False}
            size = len(json.dumps(data).encode())
            if size <= 16 * 1024 and selected_bytes + size <= 192 * 1024 and len(selected) < 256:
                selected.append(data)
                selected_bytes += size
            else:
                dropped += 1
    errors = []
    if len(coverage) != 1 or not coverage[0].get("codegen_completed"):
        errors.append("missing/multiple/incomplete codegen coverage")
    for row in coverage:
        if any(row.get("counts", {}).get("dropped", {}).values()):
            errors.append("compiler sidecar cap reached")
    missing = sorted(REQUIRED_STAGES - set(counts))
    if missing:
        errors.append("required compiler stages missing: " + ", ".join(missing))
    if dropped:
        errors.append("targeted compiler observations exceed curated cap; request precise packet")
    result = {"source": CANDIDATE, "case": case.name, "stage": "compiler-sidecars",
              "coverage": coverage, "stage_counts": dict(counts), "selected_events": selected,
              "coverage_by_root_instance_stage": [dict(root=k[0], instance=k[1], symbol=k[2], stage=k[3], count=v)
                                                   for k, v in sorted(instances.items())],
              "emitted": len(selected), "dropped": dropped,
              "filtered": sum(counts.values()) - len(selected) - dropped,
              "causal_claim": False, "errors": errors,
              "sidecar_manifest_sha256": digest(destination / "sidecar-manifest.json.gz")}
    bounded_write(destination / "compiler.json", result)
    return result


def collect(root, output):
    output.mkdir(parents=True, exist_ok=True)
    errors = []
    rows = []
    identities = {"candidate": CANDIDATE, "baseline": BASELINE, "causal_claim": False,
                  "workflow_commit": os.environ.get("GITHUB_SHA", "UNKNOWN")}
    compiler_controls = {}
    for source, cases in (("candidate", ("A", "B", "AB", "BA", "D")), ("baseline", ("A", "B", "pair"))):
        private = root / source
        try:
            identity = load(private / "identity.json")
            # Large immutable manifests remain private, with exact hash/count references.
            public_identity = dict(identity)
            for key in ("rust_sysroot", "kani_sysroot", "effective_kani_sysroot"):
                if key in public_identity:
                    manifest = private / (key + ".json")
                    write(manifest, public_identity[key])
                    compressed = gzip.compress(manifest.read_bytes(), mtime=0)
                    target = output / source / (key + ".json.gz")
                    target.parent.mkdir(parents=True, exist_ok=True)
                    public_identity[key] = {"sha256": digest(manifest), "entries": len(identity[key]),
                                            "private_manifest": str(manifest.relative_to(root)),
                                            "manifest_bytes": manifest.stat().st_size}
                    if len(compressed) <= MAX_FILE:
                        target.write_bytes(compressed)
                        public_identity[key].update(curated_manifest=str(target.relative_to(output)), gzip_sha256=digest(target))
                    else:
                        public_identity[key]["curated_manifest"] = "HASH_REFERENCE_ONLY; full manifest retained privately"
            identities[source] = public_identity
            phases = load(private / "phases.json")
            errors.extend(source + ": " + str(x) for x in phases.get("errors", []))
            if phases.get("setup") != 0 or not isinstance(phases.get("build"), dict) or phases["build"].get("exit") != 0:
                errors.append(source + ": setup/build not complete")
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(source + ": " + str(error))
            identity = None
        for case in cases:
            case_root = private / "cases" / case
            destination = output / source / "cases" / case
            destination.mkdir(parents=True, exist_ok=True)
            report = {"source": source, "source_sha": CANDIDATE if source == "candidate" else BASELINE,
                      "case": case, "setup": "NOT_RUN", "compiler": "UNKNOWN", "verification": "NOT_RUN",
                      "solvers": [], "errors": [], "curation": 2, "causal_claim": False}
            try:
                phases = load(case_root / "phases.json")
                report.update(setup=phases["setup"], compiler=phases["compiler"], verification=phases["verification"],
                              explicit_environment=phases["explicit_environment"], actual_roots=phases.get("actual_roots", "UNKNOWN"))
                if phases.get("root_error") or not isinstance(phases.get("actual_roots"), list):
                    report["errors"].append("actual roots/model binding missing: " + str(phases.get("root_error")))
                if phases.get("compiler_ok") is not True:
                    report["errors"].append("actual compiler child exit missing/nonzero/signal")
                code = phases["verification"]["exit"]
                if type(code) is not int or code not in (0, 1):
                    report["errors"].append("verification did not reach ordinary terminal exit")
                if identity is None:
                    raise ValueError("missing source identity")
                captures = sorted((case_root / "cbmc-private").glob("*.meta.json"))
                captures, probes, probe_errors = split_captures(captures, identity["tools"]["cbmc"].get("version", "6.11.0"))
                report["version_probes"] = probes
                report["errors"].extend(probe_errors)
                expected = 1 if case in ("A", "B") else 2
                if len(captures) != expected:
                    report["errors"].append(f"expected {expected} solver captures, found {len(captures)}")
                for ordinal, meta in enumerate(captures):
                    raw = meta.with_name(meta.name.replace(".meta.json", ".json"))
                    solver_out = case_root / "inventory" / str(ordinal)
                    solver_out.mkdir(parents=True, exist_ok=True)
                    result = inventory.generate(raw, meta, identity["source"], case, code,
                                                identity["tools"]["cbmc"]["path"],
                                                identity["tools"]["goto-instrument"]["path"], solver_out)
                    report["solvers"].append(result)
                    # Explicit allowlist: never copy raw capture, full properties/GOTO/logs.
                    for name in ("manifest.json", "bindings.json", "property-inventory.json", "curated.json"):
                        path = solver_out / name
                        if path.exists():
                            if path.stat().st_size > MAX_FILE:
                                report["errors"].append(name + " exceeds curated cap")
                            else:
                                target = destination / str(ordinal) / name
                                target.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copyfile(path, target)
                    if result.get("status") != "COMPLETE":
                        report["errors"].append(f"solver {ordinal}: inventory/curation incomplete")
                if source == "candidate":
                    compiler = summarize_compiler(case_root, destination)
                    report["errors"].extend(compiler["errors"])
                    compiler_controls[case] = compiler
                report["curation"] = 2 if report["errors"] else 0
            except (OSError, ValueError, KeyError, TypeError, AssertionError) as error:
                report["errors"].append(str(error))
            errors.extend(f"{source}/{case}: {error}" for error in report["errors"])
            if (case_root / "phases.json").exists():
                original = load(case_root / "phases.json")
                original["curation"] = report["curation"]
                original["solver_inventory"] = report["solvers"]
                write(case_root / "phases.json", original)
            bounded_write(destination / "manifest.json", report)
            rows.append(report)
    # Compare observed prewarm, never infer it from selectors or forced loop order.
    prewarm = {}
    for case, report in compiler_controls.items():
        prewarm[case] = [event["payload"] for event in report["selected_events"] if event["stage"] == "prewarm-begin"]
    matched = bool(prewarm.get("AB")) and prewarm.get("AB") == prewarm.get("BA") == prewarm.get("D")
    controls = {"observed_prewarm": prewarm, "matched_candidate_prewarm": matched,
                "D_vs_baseline_model_equivalence": "UNKNOWN", "causal_claim": False,
                "reason": "Exact source/GOTO operand chains and normalized MIR/GOTO equivalence require independently checked bindings; no inference from names or suffixes."}
    controls["baseline_comparisons"], control_errors = compare_controls(root)
    errors.extend(control_errors)
    if not matched:
        errors.append("AB/BA/D prewarm missing or mismatched; STOP matched causal/cache inference")
    # Property inventories are exact input-bound; model equivalence is an explicit
    # unresolved gate, never upgraded from property IDs or a green infrastructure job.
    bounded_write(output / "controls.json", controls)
    bounded_write(output / "identities.json", identities)
    status = {"curation_exit": 2 if errors else 0, "errors": errors[:100], "error_count": len(errors),
              "causal_claim": False, "verification_success_claim": False}
    bounded_write(output / "status.json", status)
    summary = ["# D0 diagnostic collection", "", "Infrastructure status does not assert verification PASS.", "",
               "| source/case | compiler | verification exit | solver exits | curation |", "|---|---|---|---|---|"]
    for row in rows:
        compiler_exits = [entry.get("exit") if entry.get("signal") is None else f"signal:{entry['signal']}"
                          for entry in row["compiler"]] if isinstance(row["compiler"], list) else row["compiler"]
        summary.append(f"| {row['source']}/{row['case']} | {json.dumps(compiler_exits)} | {json.dumps(row['verification'].get('exit') if isinstance(row['verification'], dict) else row['verification'])} | {json.dumps([s.get('original_exits', {}).get('solver') for s in row['solvers']])} | {row['curation']} |")
    summary.extend(["", "Causal claim: UNKNOWN. Model equivalence: UNKNOWN. Missing/capped bindings require a targeted packet.", "", f"Curation errors: {len(errors)}."])
    summary.extend("- " + str(error)[:256] for error in errors[:30])
    (output / "SUMMARY.md").write_text("\n".join(summary) + "\n")
    bounded_write(output / "packet-manifest.json", {"files": manifest_tree(output), "byte_cap": MAX_PACKET,
                                                   "causal_claim": False}, cap=MAX_PACKET // 4)
    total = sum(p.stat().st_size for p in output.rglob("*") if p.is_file())
    if total > MAX_PACKET:
        # Retain a bounded error packet and its inventory, not a silently truncated success packet.
        emergency_packet(output, "packet cap exceeded", total)
        return 2
    return status["curation_exit"]


def emergency_packet(output, error, original_bytes=None):
    output.mkdir(parents=True, exist_ok=True)
    outcomes_path = output / "workflow-steps.json"
    outcomes = outcomes_path.read_bytes() if outcomes_path.exists() and outcomes_path.stat().st_size < MAX_FILE else None
    for path in output.iterdir():
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()
    if outcomes is not None:
        outcomes_path.write_bytes(outcomes)
    write(output / "status.json", {"curation_exit": 2, "error": str(error)[:1024],
                                   "original_bytes": original_bytes, "causal_claim": False})
    (output / "SUMMARY.md").write_text("# D0 INCOMPLETE\n" + str(error)[:1024] +
        "\nRequest a precise targeted packet; no raw fallback.\n")
    write(output / "packet-manifest.json", {"files": manifest_tree(output), "byte_cap": MAX_PACKET})


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("private", type=Path)
    ap.add_argument("curated", type=Path)
    args = ap.parse_args()
    try:
        code = collect(args.private.resolve(), args.curated.resolve())
    except Exception as error:
        emergency_packet(args.curated.resolve(), f"{type(error).__name__}: {error}")
        code = 2
    raise SystemExit(code)
