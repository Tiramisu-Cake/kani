#!/usr/bin/env python3
"""CI-only observation of the unchanged full regression; no verifier policy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import shutil
import subprocess
import sys
import tomllib

MARK = b"\x1eKANI_GATE\0"
SUITES = "kani expected ui std-checks firecracker prusti smack cargo-kani cargo-ui script-based-pre coverage cargo-coverage kani-docs kani-fixme json-handler".split()
UNITS = "cprover_bindings kani-compiler kani-driver kani_metadata compiletest kani-cov kani kani_macros".split()
STAGES = ["cbmc", "kissat", "fmt", "build-dev"] + ["unit:" + p for p in UNITS] + ["compiletest-config", "build-cov"] + ["suite:" + s for s in SUITES] + ["firecracker-codegen", "cargo-smoke", "cargo-clean", "warnings-build"]
REQUIRED_FILES = ["scripts/kani-regression.sh", ".github/workflows/kani.yml", ".github/actions/setup/action.yml", "rust-toolchain.toml", "kani-dependencies", "Cargo.lock", "library/kani_core/src/mem_init.rs", "library/kani_core/src/mem.rs", "tests/json-handler/uninit-contract-oracles/oracles.json", "tests/json-handler/uninit-contract-mode-boundaries/roots.json"]
REQUIRED_FILES += ["tests/json-handler/uninit-part1-composition/roots.json", "tests/json-handler/uninit-part1-composition/ROOT-ORDER-MAP.json", "tests/json-handler/uninit-part1-composition/run.py", "tests/json-handler/uninit-part1-composition/compare.py"]
REQUIRED_TREES = ["kani-compiler", "kani-driver", "library", "tests", "tools", "scripts"]
HOOK = r'''if [[ $0 == scripts/kani-regression.sh ]]; then
trap 'printf "\036KANI_GATE\000%s\000%s\000%s\000%s\000%s\000%s\000%s\000" DEBUG "$?" "${BASH_SOURCE[0]}" "$LINENO" "$BASH_COMMAND" "${suite-}" "${mode-}"' DEBUG
trap 'printf "\036KANI_GATE\000%s\000%s\000%s\000%s\000%s\000%s\000%s\000" EXIT "$?" "${BASH_SOURCE[0]}" "$LINENO" "$BASH_COMMAND" "${suite-}" "${mode-}"' EXIT
fi
'''


def identify(command, suite):
    cmd = " ".join(command.split())
    if "check-cbmc-version.py" in cmd:
        return "cbmc"
    if cmd == "check_kissat_version.sh":
        return "kissat"
    if "kani-fmt.sh" in cmd:
        return "fmt"
    if cmd == "cargo build-dev":
        return "build-dev"
    if "cargo test -p " in cmd:
        package = cmd.split("cargo test -p ", 1)[1].split()[0]
        return "unit:" + package
    if "cargo run -p compiletest" in cmd:
        return "compiletest-config" if "--dry-run" in cmd else "suite:" + suite
    if cmd == "cargo build -p kani-cov":
        return "build-cov"
    if "codegen-firecracker.sh" in cmd:
        return "firecracker-codegen"
    if cmd.startswith("cargo kani --manifest-path"):
        return "cargo-smoke"
    if cmd.startswith("cargo clean --manifest-path"):
        return "cargo-clean"
    if cmd.startswith('RUSTFLAGS="-D warnings" cargo build'):
        return "warnings-build"
    return None


def summarize(data, returncode, termination=None):
    rows = {name: {"status": "NOT_RUN", "exit": None, "counts": []} for name in STAGES}
    problems, pending, seen = [], None, []
    pos = 0
    # Events and child output share one fd, so every completed command's output
    # is between its DEBUG event and the next event. Never guess missing exits.
    while True:
        start = data.find(MARK, pos)
        if start < 0:
            break
        fields, cursor = [], start + len(MARK)
        for _ in range(7):
            end = data.find(b"\0", cursor)
            if end < 0:
                problems.append("partial-event")
                break
            fields.append(data[cursor:end].decode("utf-8", "replace"))
            cursor = end + 1
        if len(fields) != 7:
            break
        kind, rc, source, line, command, suite, mode = fields
        if source != "scripts/kani-regression.sh" and not source.endswith("/scripts/kani-regression.sh"):
            pos = cursor
            continue
        if kind not in ("DEBUG", "EXIT") or not rc.isdecimal():
            problems.append("invalid-event")
            pos = cursor
            continue
        if pending:
            name, output_start = pending
            output = data[output_start:start].decode("utf-8", "replace")
            counts = re.findall(r"test result:.*", output)
            rows[name].update(status="EXIT_ZERO" if rc == "0" else "FAILED", exit=int(rc), counts=[c[:4096] for c in counts[:20]])
            rows[name]["count_fields"] = [dict((label, int(number)) for number, label in re.findall(r"(\d+) (passed|failed|ignored|measured|filtered out)", count)) for count in counts[:20]]
            rows[name]["expected_negative_policy"] = "Frozen test oracles accept intended verifier negatives; failed test counts are unexpected test/oracle failures. Exact negative property acceptance is separate."
            if rc != "0":
                rows[name]["failure_kind"] = "UNEXPECTED_TEST_OR_ORACLE_FAILURE" if counts else "UNCLASSIFIED_TEST_OR_INFRA_FAILURE"
                rows[name]["bounded_failure_tail"] = output[-4096:].splitlines()[-12:]
            if any(len(c) > 4096 for c in counts):
                problems.append(name + ":summary-line-overflow")
            if len(counts) > 20:
                problems.append(name + ":summary-overflow")
            if any("FAILED" in count or re.search(r"\b[1-9][0-9]* failed\b", count) for count in counts):
                problems.append(name + ":failed-count")
            if name.startswith(("suite:", "unit:")) and not counts:
                problems.append(name + ":counts-missing")
            pending = None
        if kind == "DEBUG":
            name = identify(command, suite)
            if name:
                if name not in rows or name in seen:
                    problems.append("unexpected-or-duplicate-stage:" + name)
                else:
                    seen.append(name)
                    rows[name].update(status="INCOMPLETE", command=command, source_line=line, mode=mode)
                    pending = (name, cursor)
        pos = cursor
    if pending:
        rows[pending[0]]["status"] = "INCOMPLETE"
    if seen != STAGES:
        problems.append("stage-order-or-presence")
    complete = returncode == 0 and not termination and not problems and all(r["status"] == "EXIT_ZERO" for r in rows.values())
    return {"schema": "kani3300-fullgate-receipt-v1", "status": "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW" if complete else "INCOMPLETE_OR_FAILED", "formal_proof_credit": "NOT_ESTABLISHED", "script_exit": returncode, "termination": termination, "problems": problems, "stages": rows}


def git(*args):
    return subprocess.check_output(["git", *args], text=True).strip()


def validate_binding(binding, source=True):
    if not isinstance(binding, dict) or binding.get("schema") != "kani3300-gate-binding-v1":
        raise ValueError("binding schema")
    if binding.get("state") != "C1_FROZEN" or binding.get("m3_accepted") is not True:
        raise ValueError("unbound C1/M3")
    for key in ("export_sha", "export_tree"):
        if not isinstance(binding.get(key), str) or not re.fullmatch("[0-9a-f]{40}", binding[key]):
            raise ValueError("invalid " + key)
    for field, required, width in (("files", REQUIRED_FILES, 64), ("subtrees", REQUIRED_TREES, 40)):
        values = binding.get(field)
        if not isinstance(values, dict) or not set(required).issubset(values):
            raise ValueError("missing identity set: " + field)
        if any(not isinstance(value, str) or not re.fullmatch("[0-9a-f]{%d}" % width, value) for value in values.values()):
            raise ValueError("invalid identity: " + field)
    if source:
        if git("rev-parse", "HEAD") != binding["export_sha"] or git("rev-parse", "HEAD^{tree}") != binding["export_tree"]:
            raise ValueError("source-stage-target mismatch")
        if git("status", "--porcelain", "--untracked-files=all"):
            raise ValueError("dirty export")
        for path, digest in binding["files"].items():
            if hashlib.sha256(Path(path).read_bytes()).hexdigest() != digest:
                raise ValueError("source hash mismatch: " + path)
        for path, tree in binding["subtrees"].items():
            if git("rev-parse", "HEAD:" + path) != tree:
                raise ValueError("subtree mismatch: " + path)


def runtime_identities():
    paths = {str(p): p for p in Path("target/kani").rglob("*") if p.is_file()}
    missing = []
    for name in ("kani-driver", "kani-compiler"):
        if not Path("target/kani/bin", name).is_file():
            missing.append(name)
    if not any("/lib/" in name for name in paths):
        missing.append("compiled runtime/model libraries")
    for name in ("cbmc", "kissat"):
        found = shutil.which(name)
        if found:
            paths[name] = Path(found).resolve()
        else:
            missing.append(name)
    channel = tomllib.loads(Path("rust-toolchain.toml").read_text())["toolchain"]["channel"]
    rustc = Path(subprocess.check_output(["rustup", "which", "--toolchain", channel, "rustc"], text=True).strip())
    paths["rustc:" + channel] = rustc
    rustc_version = subprocess.check_output([str(rustc), "-vV"], text=True).strip()
    hashes = {}
    for name, path in sorted(paths.items()):
        with path.open("rb") as stream:
            hashes[name] = {"resolved": str(path.resolve()), "sha256": hashlib.file_digest(stream, "sha256").hexdigest()}
    return {"files": hashes, "missing": missing, "toolchain_channel": channel, "rustc_version": rustc_version}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binding", required=True)
    ap.add_argument("--output", required=True)
    ap.add_argument("--timeout", type=int, default=20400)
    ap.add_argument("--preflight", action="store_true")
    args = ap.parse_args()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    report = {"status": "NOT_RUN", "script_exit": None, "formal_proof_credit": "NOT_ESTABLISHED"}
    child = None
    try:
        binding = json.loads(Path(args.binding).read_text())
        if os.getenv("GITHUB_ACTIONS") != "true" or os.getenv("GITHUB_REPOSITORY") != "Tiramisu-Cake/kani":
            raise ValueError("fork CI only")
        validate_binding(binding)
        forbidden = [key for key in ("KANI_REGRESSION_KEEP_GOING", "KANI_REGRESSION_TEST_TIMEOUT", "RUSTFLAGS", "KANI_FLAGS", "CBMC_FLAGS", "EXTRA_X_PY_BUILD_ARGS", "BASH_ENV", "SHELLOPTS", "BASHOPTS") if os.getenv(key)]
        if forbidden or args.timeout <= 0:
            raise ValueError("unexpected environment or timeout: " + repr(forbidden))
        if args.preflight:
            report.update(preflight="SOURCE_BOUND", binding=binding)
            return 0
        hook = out / "observe.bash"
        hook.write_text(HOOK)
        env = dict(os.environ, BASH_ENV=str(hook), KANI_REGRESSION_KEEP_GOING="", KANI_REGRESSION_TEST_TIMEOUT="2400")
        def interrupted(signum, frame):
            raise InterruptedError(signum)
        signal.signal(signal.SIGTERM, interrupted)
        termination = None
        with (out / "regression.events.log").open("xb") as log:
            child = subprocess.Popen(["bash", "scripts/kani-regression.sh"], stdout=log, stderr=subprocess.STDOUT, env=env, start_new_session=True)
            try:
                child.wait(timeout=args.timeout)
            except (subprocess.TimeoutExpired, InterruptedError, KeyboardInterrupt) as exc:
                termination = {"kind": type(exc).__name__, "signal": exc.args[0] if isinstance(exc, InterruptedError) else None}
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
        raw = out / "regression.events.log"
        if raw.stat().st_size > 256 * 1024 * 1024:
            report.update(status="INCOMPLETE_OR_FAILED", limitation="artifact exceeds parser 256MiB cap; stage coverage UNKNOWN", stages={name: {"status": "UNKNOWN", "exit": None} for name in STAGES}, script_exit=child.returncode)
        else:
            report = summarize(raw.read_bytes(), child.returncode, termination)
        report.update(binding=binding, argv=["bash", "scripts/kani-regression.sh"], timeout_seconds=args.timeout, clean_after=not bool(git("status", "--porcelain", "--untracked-files=all")))
        runtime = runtime_identities()
        runtime_file = out / "runtime-identities.json"
        runtime_file.write_text(json.dumps(runtime, indent=2) + "\n")
        report["runtime_identities"] = {"file": runtime_file.name, "sha256": hashlib.sha256(runtime_file.read_bytes()).hexdigest(), "file_count": len(runtime["files"]), "missing": runtime["missing"], "assurance": "CI_INVENTORY_FOR_SUBSEQUENT_REPLAY_BINDING"}
        with raw.open("rb") as stream:
            report["events_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        if not report["clean_after"] or report["runtime_identities"]["missing"]:
            report["status"] = "INCOMPLETE_OR_FAILED"
        return child.returncode if child.returncode and child.returncode > 0 else (0 if report["status"] == "COMPLETE_EXIT_ZERO_REQUIRES_REVIEW" else 1)
    except Exception as exc:
        report.update(status="INCOMPLETE_OR_FAILED" if child else "NOT_RUN", error=type(exc).__name__ + ": " + str(exc), script_exit=child.returncode if child else None)
        return 2
    finally:
        (out / "receipt.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    sys.exit(main())
