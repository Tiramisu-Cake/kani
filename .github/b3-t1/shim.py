#!/usr/bin/env python3
"""PATH shims: CBMC is NEVER delegated; cargo/goto-cc preserve original exits."""
import json
import os
from pathlib import Path
import sys

from common import PERF_ROWS, bind_harness, event, execute, metadata_harnesses, snapshot, write_json


def cargo(args):
    prefix = []
    if args and args[0].startswith("+"):
        prefix.append(args.pop(0))
    if not args:
        raise ValueError("cargo command required")
    if args[0] == "build-dev":
        # Expand the repository's exact alias so --locked is a Cargo run option,
        # not an argument to the build-kani executable.
        args = ["run", "--target-dir", "target/tools", "-p", "build-kani", "--", "build-dev", *args[1:]]
    if args[0] != "kani":
        # Version/locate-project calls do not accept --locked.
        if os.environ.get("T1_LOCKED") == "1" and args[0] in {"build", "run", "rustc", "metadata", "check", "fetch", "test"}:
            args.insert(1, "--locked")
        return execute([os.environ["T1_REAL_CARGO"], *prefix, *args]).returncode
    row = Path.cwd().relative_to(Path(os.environ["T1_SOURCE"]) / "tests/perf").as_posix()
    if row not in PERF_ROWS or args.count("--target-dir") != 1:
        raise ValueError(f"unexpected workload row: {row}: {args}")
    if "--tests" not in args or "--harness" in args:
        raise ValueError("perf selector drift")
    target = Path(args[args.index("--target-dir") + 1]).resolve()
    os.environ.update(T1_ROW=row, T1_TARGET=str(target))
    original = list(args)
    args.append("--keep-temps")  # Retention only; no codegen/backend option changes.
    event({"event": "row-start", "row": row, "original_argv": original, "actual_argv": args})
    result = execute([os.environ["T1_REAL_CARGO"], *prefix, *args])
    finish_row(row, target, result.returncode)
    return result.returncode


def finish_row(row, target, code):
    if code != 1:
        raise ValueError(f"expected Kani capture-only failure exit 1, got {code}: {row}")
    harnesses = metadata_harnesses(target)
    expected = [h["pretty_name"] for _, h, _ in harnesses]
    if not expected or len(expected) != len(set(expected)):
        raise ValueError(f"empty/duplicate metadata census: {row}")
    for path in sorted(set(p for p, _, _ in harnesses)):
        snapshot(path, "metadata")
    arm = Path(os.environ["T1_ARM_DIR"])
    captured = []
    for path in (arm / "records").glob("*.json"):
        r = json.loads(path.read_text())["record"]
        if r["row"] == row and r["kind"] == "final":
            captured.append(r["harness"])
    if sorted(expected) != sorted(captured):
        raise ValueError(f"incomplete harness capture: {row}: expected={expected}, actual={captured}")
    write_json(arm / "rows" / (row.replace("/", "__") + ".json"), {
        "row": row, "expected_harnesses": sorted(expected),
        "captured_harnesses": sorted(captured), "exit": code})


def cbmc(args):
    # kani-driver checks `cbmc --version` before each run; only that call reaches the real binary.
    if args == ["--version"]:
        return execute([os.environ["T1_REAL_CBMC"], *args]).returncode
    models = [Path(a) for a in args if a.endswith(".out") and Path(a).is_file()]
    if len(models) != 1 or "--json-ui" not in args:
        raise ValueError(f"unexpected CBMC invocation: {args}")
    name = bind_harness(models[0])
    record = snapshot(models[0], "final", name, args)
    event({"event": "cbmc-capture", "row": os.environ["T1_ROW"], "harness": name,
           "argv": args, "input_sha256": record["sha256"], "exit": 86, "sat": "NOT_RUN"})
    # Valid parser input, no result array/prover status. Kani reports Failure/Other(86)
    # and continues (stock perf has no --fail-fast). Never manufacture verification success.
    # Kani's CBMC output parser is line-based: "[" and "]" alone on a line, items closed by "  }".
    print(json.dumps([{"messageType": "ERROR", "messageText": "B3 T1 CAPTURE ONLY; SAT NOT_RUN; exit 86"}], indent=2))
    return 86


def goto_cc(args):
    result = execute([os.environ["T1_REAL_GOTO_CC"], *args])
    if result.returncode == 0 and os.environ.get("T1_ROW") and "--function" not in args:
        inputs = [Path(a) for a in args if a.endswith(".symtab.out") and Path(a).is_file()]
        if inputs:
            if len(inputs) != 1 or args.count("-o") != 1:
                raise ValueError("unexpected linking recipe")
            snapshot(inputs[0], "symtab")
            snapshot(args[args.index("-o") + 1], "linked")
    return result.returncode


def main():
    name = Path(sys.argv[0]).name
    try:
        if name == "cargo":
            return cargo(sys.argv[1:])
        if name == "cbmc":
            return cbmc(sys.argv[1:])
        if name == "goto-cc":
            return goto_cc(sys.argv[1:])
        if name == "goto-instrument":
            return execute([os.environ["T1_REAL_GOTO_INSTRUMENT"], *sys.argv[1:]]).returncode
        if name == "kissat":
            raise ValueError("solver invocation forbidden: SAT NOT_RUN")
        raise ValueError(f"unknown shim: {name}")
    except BaseException as error:
        event({"event": "capture-error", "tool": name, "error": repr(error), "exit": 87})
        print(f"B3 T1 capture error: {error}", file=sys.stderr)
        return 87


if __name__ == "__main__":
    sys.exit(main())
