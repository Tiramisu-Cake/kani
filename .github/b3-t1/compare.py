#!/usr/bin/env python3
"""Fail-closed A1/B1/A2 model comparison for B3 T1.

Usage: compare.py ARTIFACT_ROOT REAL_GOTO_INSTRUMENT

The comparator performs no normalization and never runs a solver. Exit code 2
means invalid input, invalid control, or A1/A2 drift. Exit code 3 means the
control was detected and perf comparison completed, but coordinator review is
required. A detected control difference is never automatically credited as
the expected zero-width-wrapper change.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import LOCK_ROOTS, PERF_ROWS

ARMS = ("A1", "B1", "A2")
MODEL_KINDS = {"final", "linked", "symtab"}
DIFF_KINDS = MODEL_KINDS
HEX = re.compile(r"^[0-9a-f]{64}$")
EXCLUDED_AB_TOOLS = {"kani-driver", "kani-compiler"}
REQUIRED_TOOLS = {"cbmc", "goto-instrument", "goto-cc", "kissat", "rustc", "kani-driver", "kani-compiler"}
DUMP_TIMEOUT_SECONDS = 120
REQUIRED_ROWS = {"control", *PERF_ROWS}
REQUIRED_LOCKS = {str(Path(root) / "Cargo.lock") for root in LOCK_ROOTS} | {"kani-compiler/Cargo.lock"}


class Invalid(ValueError):
    pass


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Invalid(message)


def _hash(value: Any, where: str) -> None:
    _require(isinstance(value, str) and HEX.fullmatch(value) is not None,
             f"{where}: expected lowercase sha256 hex")


def _strings(value: Any, where: str, nonempty: bool = True, unique: bool = True) -> list[str]:
    _require(isinstance(value, list), f"{where}: expected array")
    _require(not nonempty or len(value) > 0, f"{where}: empty array")
    _require(all(isinstance(x, str) and x != "" for x in value),
             f"{where}: expected nonempty strings")
    if unique:
        _require(len(value) == len(set(value)), f"{where}: duplicate entries")
    return value


def _contained_file(root: Path, relative: Any, where: str) -> Path:
    _require(isinstance(relative, str) and relative != "", f"{where}: invalid path")
    rel = Path(relative)
    _require(not rel.is_absolute() and ".." not in rel.parts,
             f"{where}: path must be relative and contained")
    path = (root / rel).resolve()
    _require(path.is_relative_to(root.resolve()), f"{where}: path escapes arm")
    _require(path.is_file(), f"{where}: missing file {relative}")
    return path


def _object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise Invalid(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_arm(root: Path, arm: str) -> dict[str, Any]:
    arm_root = root / arm
    index_path = arm_root / "index.json"
    _require(index_path.is_file(), f"{arm}: missing index.json")
    try:
        data = json.loads(index_path.read_text(encoding="utf-8"), object_pairs_hook=_object_no_duplicates)
    except Exception as e:
        raise Invalid(f"{arm}: invalid index.json: {e}") from e
    _require(isinstance(data, dict), f"{arm}: index must be an object")
    _require(set(data) == {"complete", "records", "rows", "tools", "locks"},
             f"{arm}: missing or unexpected top-level fields")
    _require(data.get("complete") is True, f"{arm}: inventory incomplete")
    records, rows, tools, locks = (data.get(k) for k in ("records", "rows", "tools", "locks"))
    for name, value in (("records", records), ("rows", rows), ("tools", tools), ("locks", locks)):
        _require(isinstance(value, dict) and len(value) > 0, f"{arm}: {name} missing, empty, or wrong type")

    seen_paths = set()
    for key, rec in records.items():
        _require(isinstance(key, str) and key != "", f"{arm}: empty record key")
        w = f"{arm}.records.{key}"
        _require(isinstance(rec, dict), f"{w}: expected object")
        allowed = {"sha256", "path", "kind", "row", "harness"}
        if rec.get("kind") == "final":
            allowed |= {"argv", "cwd"}
        _require(set(rec) <= allowed, f"{w}: unexpected fields")
        _hash(rec.get("sha256"), f"{w}.sha256")
        path = _contained_file(arm_root, rec.get("path"), f"{w}.path")
        _require(rec["path"] not in seen_paths, f"{w}: duplicate record path")
        seen_paths.add(rec["path"])
        _require(sha256(path) == rec["sha256"], f"{w}: sha256 mismatch")
        _require(rec.get("kind") in {"final", "linked", "symtab", "metadata"}, f"{w}: invalid kind")
        _require(isinstance(rec.get("row"), str) and rec["row"] != "", f"{w}.row: invalid")
        _require("harness" not in rec or (isinstance(rec["harness"], str) and rec["harness"] != ""),
                 f"{w}.harness: invalid")
        if rec["kind"] == "final":
            _strings(rec.get("argv"), f"{w}.argv", unique=False)
            _require(isinstance(rec.get("cwd"), str) and os.path.isabs(rec["cwd"]), f"{w}.cwd: expected absolute path")

    for row, info in rows.items():
        _require(isinstance(row, str) and row != "", f"{arm}: empty row name")
        w = f"{arm}.rows.{row}"
        _require(isinstance(info, dict), f"{w}: expected object")
        _require(set(info) == {"expected_harnesses", "captured_harnesses", "exit"},
                 f"{w}: missing or unexpected fields")
        expected = _strings(info.get("expected_harnesses"), f"{w}.expected_harnesses")
        captured = _strings(info.get("captured_harnesses"), f"{w}.captured_harnesses")
        _require(set(expected) == set(captured), f"{w}: harness inventory mismatch")
        _require(type(info.get("exit")) is int and info["exit"] == 1,
                 f"{w}.exit: expected captured Kani failure exit 1")
    for name, value in tools.items():
        _require(isinstance(name, str) and name != "", f"{arm}: empty tool name")
        _hash(value, f"{arm}.tools.{name}")
    for path, value in locks.items():
        _require(isinstance(path, str) and path != "", f"{arm}: empty lock path")
        _hash(value, f"{arm}.locks.{path}")
    _require("control" in rows, f"{arm}: missing positive-control row")
    _require(set(rows) == REQUIRED_ROWS, f"{arm}: perf row inventory does not match common.PERF_ROWS plus control")
    for rec in records.values():
        _require(rec["row"] in rows, f"{arm}: record refers to unknown row {rec['row']}")
    _require(REQUIRED_TOOLS <= set(tools), f"{arm}: missing required tool hashes: {sorted(REQUIRED_TOOLS - set(tools))}")
    _require(REQUIRED_LOCKS <= set(locks), f"{arm}: missing required lock files: {sorted(REQUIRED_LOCKS - set(locks))}")
    finals = {row: [] for row in rows}
    kinds = {row: set() for row in rows}
    for key, rec in records.items():
        kinds[rec["row"]].add(rec["kind"])
        if rec["kind"] == "final":
            finals[rec["row"]].append((key, rec.get("harness")))
    for row, info in rows.items():
        expected = info["expected_harnesses"]
        actual = finals[row]
        _require(len(actual) == len(expected), f"{arm}.{row}: expected exactly one final record per harness")
        names = [harness for _, harness in actual]
        _require(None not in names and len(names) == len(set(names)), f"{arm}.{row}: missing/duplicate final harness record")
        _require(set(names) == set(expected), f"{arm}.{row}: final records do not match expected harness inventory")
        _require({"linked", "symtab", "metadata"} <= kinds[row], f"{arm}.{row}: missing linked/symtab/metadata evidence")
    return data


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def dump_model(tool: str, model: Path, mode: str, destination: Path, log_path: Path) -> None:
    """Run a single goto-instrument display command and retain output/log."""
    argv = [tool, f"--show-{mode}", str(model)]
    destination.parent.mkdir(parents=True, exist_ok=True)
    stderr_path = destination.with_suffix(destination.suffix + ".stderr.txt")
    start = time.monotonic()
    try:
        with destination.open("wb") as stdout, stderr_path.open("wb") as stderr:
            result = subprocess.run(argv, stdout=stdout, stderr=stderr,
                                    timeout=DUMP_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired:
        _write_json(log_path, {"argv": argv, "exit": None, "timed_out": True,
                               "timeout_seconds": DUMP_TIMEOUT_SECONDS,
                               "elapsed_seconds": round(time.monotonic() - start, 3),
                               "stdout": str(destination), "stderr": str(stderr_path)})
        raise Invalid(f"goto-instrument --show-{mode} timed out after {DUMP_TIMEOUT_SECONDS}s for {model}")
    except OSError as e:
        _write_json(log_path, {"argv": argv, "exit": None, "timed_out": False,
                               "error": repr(e), "stdout": str(destination), "stderr": str(stderr_path)})
        raise Invalid(f"goto-instrument failed to start: {e}") from e
    _write_json(log_path, {"argv": argv, "exit": result.returncode, "timed_out": False,
                           "elapsed_seconds": round(time.monotonic() - start, 3),
                           "stdout": str(destination), "stderr": str(stderr_path)})
    if result.returncode != 0:
        raise Invalid(f"goto-instrument --show-{mode} failed for {model}: exit {result.returncode}")


def _record_path(root: Path, arm: str, rec: dict[str, Any]) -> Path:
    return root / arm / rec["path"]


def _diff_file(left: Path, right: Path, dest: Path, left_label: str, right_label: str) -> None:
    """Stream a full unified diff to disk using GNU diff, never buffering dumps."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    stderr_path = dest.with_suffix(dest.suffix + ".stderr.txt")
    log_path = dest.with_suffix(dest.suffix + ".json")
    argv = ["diff", "-u", "--label", left_label, "--label", right_label, str(left), str(right)]
    start = time.monotonic()
    try:
        with dest.open("wb") as stdout, stderr_path.open("wb") as stderr:
            result = subprocess.run(argv, stdout=stdout, stderr=stderr,
                                    timeout=DUMP_TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired:
        _write_json(log_path, {"argv": argv, "exit": None, "timed_out": True,
                               "timeout_seconds": DUMP_TIMEOUT_SECONDS,
                               "elapsed_seconds": round(time.monotonic() - start, 3),
                               "stdout": str(dest), "stderr": str(stderr_path)})
        raise Invalid(f"GNU diff timed out after {DUMP_TIMEOUT_SECONDS}s for {left} and {right}")
    except OSError as e:
        _write_json(log_path, {"argv": argv, "exit": None, "timed_out": False,
                               "error": repr(e), "stdout": str(dest), "stderr": str(stderr_path)})
        raise Invalid(f"GNU diff failed to start: {e}") from e
    _write_json(log_path, {"argv": argv, "exit": result.returncode, "timed_out": False,
                           "elapsed_seconds": round(time.monotonic() - start, 3),
                           "stdout": str(dest), "stderr": str(stderr_path)})
    if result.returncode not in (0, 1):
        raise Invalid(f"GNU diff failed for {left} and {right}: exit {result.returncode}")


def _record_ident(key: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", key)
    return f"{slug}_{hashlib.sha256(key.encode('utf-8')).hexdigest()}"


def _dump_pair(root: Path, compare_dir: Path, left_arm: str, right_arm: str,
               left_records: dict[str, Any], right_records: dict[str, Any],
               keys: list[str], goto_instrument: str) -> list[str]:
    """Retain symbol/function dumps and diffs for named differing model records."""
    dumped = []
    for key in keys:
        left, right = left_records.get(key), right_records.get(key)
        if not left or not right or left.get("kind") not in DIFF_KINDS or right.get("kind") not in DIFF_KINDS:
            continue
        ident = _record_ident(key)
        pair_dir = compare_dir / f"{left_arm}-{right_arm}" / ident
        for arm, record in ((left_arm, left), (right_arm, right)):
            model = _record_path(root, arm, record)
            for mode in ("symbol-table", "goto-functions"):
                output = pair_dir / f"{arm}.{mode}.txt"
                log = pair_dir / f"{arm}.{mode}.json"
                dump_model(goto_instrument, model, mode, output, log)
        for mode in ("symbol-table", "goto-functions"):
            _diff_file(pair_dir / f"{left_arm}.{mode}.txt", pair_dir / f"{right_arm}.{mode}.txt",
                       pair_dir / f"{mode}.diff", f"{left_arm}/{key}", f"{right_arm}/{key}")
        dumped.append(key)
    return dumped


def _field_drift(left: Any, right: Any, path: str = "") -> list[str]:
    if isinstance(left, dict) and isinstance(right, dict):
        drift = []
        for key in sorted(set(left) | set(right)):
            child = f"{path}.{key}" if path else key
            if key not in left or key not in right:
                drift.append(child)
            else:
                drift.extend(_field_drift(left[key], right[key], child))
        return drift
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return [path]
        drift = []
        for i, (a, b) in enumerate(zip(left, right)):
            drift.extend(_field_drift(a, b, f"{path}[{i}]"))
        return drift
    return [] if left == right else [path]


def _record_drift_names(left: dict[str, Any], right: dict[str, Any]) -> list[str]:
    return sorted(set(left) ^ set(right))


def compare(root: Path, goto_instrument: str) -> dict[str, Any]:
    result_path = root / "compare" / "RESULT.json"
    result: dict[str, Any] = {"status": "INVALID", "perf_models_equal": False,
                              "control_gate": "INVALID", "diffs": [], "errors": []}
    try:
        arms = {name: load_arm(root, name) for name in ARMS}
        a1, b1, a2 = (arms[n] for n in ARMS)
        if a1 != a2:
            r1, r2 = a1.get("records", {}), a2.get("records", {})
            common = set(r1) & set(r2) if isinstance(r1, dict) and isinstance(r2, dict) else set()
            aa_hash_differences = sorted(
                key for key in common
                if isinstance(r1[key], dict) and isinstance(r2[key], dict)
                and r1[key].get("sha256") != r2[key].get("sha256")
                and r1[key].get("kind") in DIFF_KINDS and r2[key].get("kind") in DIFF_KINDS
            )
            dumped = _dump_pair(root, root / "compare", "A1", "A2", r1, r2,
                                aa_hash_differences, goto_instrument)
            result.update(status="INCONCLUSIVE_AA", control_gate="NOT_EVALUATED",
                          perf_models_equal=False,
                          errors=["A1 and A2 inventories or evidence differ; no B3 conclusion"],
                          metadata_drift=_field_drift(a1, a2),
                          record_name_drift=_record_drift_names(r1, r2),
                          a_a_hash_differences=aa_hash_differences,
                          differing_model_records=dumped,
                          diffs=[{"record": key, "classification": "A_A_MODEL_DRIFT_INCONCLUSIVE"}
                                 for key in aa_hash_differences])
            return result

        # A/B inventory and all non-model provenance must agree before interpreting models.
        for field in ("rows", "locks"):
            if a1[field] != b1[field]:
                raise Invalid(f"A1/B1 {field} inventory differs")
        ak = {k: v for k, v in a1["tools"].items() if k not in EXCLUDED_AB_TOOLS}
        bk = {k: v for k, v in b1["tools"].items() if k not in EXCLUDED_AB_TOOLS}
        if ak != bk:
            raise Invalid("A1/B1 backend tool hashes differ")

        ar, br = a1["records"], b1["records"]
        if set(ar) != set(br):
            raise Invalid("A1/B1 logical record names differ")
        control_differences = []
        perf_differences = []
        for key in sorted(ar):
            x, y = ar[key], br[key]
            if x["kind"] != y["kind"] or x["row"] != y["row"] or x.get("harness") != y.get("harness"):
                raise Invalid(f"A1/B1 record identity differs: {key}")
            if x["kind"] == "final" and (x["argv"] != y["argv"] or x["cwd"] != y["cwd"]):
                raise Invalid(f"A1/B1 backend argv/cwd differs: {key}")
            if x["sha256"] != y["sha256"]:
                (control_differences if x["row"] == "control" else perf_differences).append(key)

        if not control_differences:
            raise Invalid("INVALID_CONTROL: positive control did not distinguish A1 from B1")
        if not any(ar[k]["kind"] == "final" for k in control_differences):
            raise Invalid("INVALID_CONTROL: positive control final model is insensitive")

        dump_pairs = _dump_pair(root, root / "compare", "A1", "B1", ar, br,
                                sorted(set(control_differences + perf_differences)), goto_instrument)

        result.update(
            status="CONTROL_WRAPPER_REVIEW_REQUIRED",
            control_gate="CONTROL_WRAPPER_REVIEW_REQUIRED",
            control_expectation="tag-<union>::<arm>",
            coordinator_review_required=True,
            control_differences=control_differences,
            perf_differences=perf_differences,
            perf_models_equal=(len(perf_differences) == 0),
            differing_model_records=dump_pairs,
            diffs=[{"record": k, "classification": "control-wrapper-review-pending" if k in control_differences
                    else "perf-model-difference-review-pending"} for k in sorted(control_differences + perf_differences)],
        )
        return result
    except Invalid as e:
        result["errors"].append(str(e))
        if str(e).startswith("INVALID_CONTROL"):
            result["control_gate"] = "INVALID_CONTROL"
        elif "goto-instrument" in str(e):
            result["control_gate"] = "INVALID_DUMP"
        elif "GNU diff" in str(e):
            result["control_gate"] = "INVALID_DIFF"
        return result
    finally:
        _write_json(result_path, result)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: compare.py ARTIFACT_ROOT REAL_GOTO_INSTRUMENT", file=sys.stderr)
        return 2
    root = Path(argv[1]).resolve()
    try:
        root.mkdir(parents=True, exist_ok=True)
        result = compare(root, argv[2])
    except Exception as e:
        result = {"status": "INVALID", "perf_models_equal": False, "control_gate": "INVALID",
                  "diffs": [], "errors": [f"unexpected comparator error: {e}"]}
        _write_json(root / "compare" / "RESULT.json", result)
    brief = {"status": result.get("status"),
             "perf_models_equal": result.get("perf_models_equal", False),
             "control_gate": result.get("control_gate"),
             "diff_count": len(result.get("diffs", [])),
             "dumped_model_count": len(result.get("differing_model_records", [])),
             "error_count": len(result.get("errors", []))}
    print(json.dumps(brief, sort_keys=True))
    if result.get("status") in {"CONTROL_WRAPPER_REVIEW_REQUIRED", "INCONCLUSIVE_AA"}:
        return 3 if result["status"] == "CONTROL_WRAPPER_REVIEW_REQUIRED" else 2
    return 0 if result["status"] == "PERF_EQUAL" else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
