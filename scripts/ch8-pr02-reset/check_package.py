#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Offline checks for the CI-only package; never invokes Rust/Kani/CBMC."""
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import textwrap
import tempfile
import tomllib
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / "scripts/ch8-pr02-reset"


def main() -> int:
    req = json.loads((ROOT / "CI-REQUEST.json").read_text())
    patch = SCRIPTS / "reset.patch"
    assert hashlib.sha256(patch.read_bytes()).hexdigest() == req["patch"]["sha256"]
    for filename, expected in req["fixtures"].items():
        assert hashlib.sha256((SCRIPTS / "fixtures" / filename).read_bytes()).hexdigest() == expected
    assert not any("PENDING" in json.dumps(item) for item in req.values())
    assert req["runtime"] == "NOT_RUN"
    assert req["limits"]["job_timeout_minutes"] <= 120
    assert req["limits"]["max_parallel"] == 1
    assert req["limits"]["cargo_build_jobs"] == 2
    assert req["limits"]["rust_test_threads"] == 2

    workflow = ROOT / ".github/workflows/ch8-pr02-reset.yml"
    yaml.safe_load(workflow.read_text())
    text = workflow.read_text()
    assert "uninit-ci/ch8-pr02-reset-*" in text
    assert "fetch-depth: 2" in text
    assert "timeout-minutes: 120" in text
    assert "max-parallel: 1" in text
    assert "arm: [A, B]" in text
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if re.search(r"\$\{\{\s*runner\.[^}]+\}\}", line):
            assert lines[index - 1].strip() == "env:", "runner context must only appear in step env"
    assert len(list((ROOT / ".github/workflows").glob("*"))) == 1
    assert "REMOVE_FROM_CI_ONLY_COMMIT" in req["stock_workflows"]

    for script in SCRIPTS.glob("*.py"):
        ast.parse(script.read_text(), filename=str(script))
    for script in SCRIPTS.glob("*.sh"):
        subprocess.run(["bash", "-n", str(script)], check=True)
    arm_a = (SCRIPTS / "run_arm_a.sh").read_text()
    package = tomllib.loads((ROOT / "kani-compiler/Cargo.toml").read_text())
    assert package["package"]["name"] == "kani-compiler"
    # With no explicit [[bin]] section Cargo uses src/main.rs and the package name.
    assert not package.get("bin")
    assert (ROOT / "kani-compiler/src/main.rs").is_file()
    assert "./scripts/kani-fmt.sh --check" in arm_a
    assert "cargo fmt --all" not in arm_a
    assert "cargo test -p kani-compiler --bin kani-compiler" in arm_a
    assert "cargo test -p kani-compiler --lib" not in arm_a
    assert "kani_middle" not in arm_a
    inline_scripts = [textwrap.dedent(code) for code in re.findall(r"python3 - <<'PY'\n(.*?)\n\s+PY", text, re.S)]
    for inline in inline_scripts:
        ast.parse(inline)
    pin_script = next(code for code in inline_scripts if "req=json.load" in code)
    pin_sha = req["pins"]["pr02"]["sha"]
    with tempfile.TemporaryDirectory(prefix="ch8-pin-script-") as tmp:
        output = Path(tmp) / "github-output"
        env = {**os.environ, "GITHUB_OUTPUT": str(output), "ARM": "A"}
        subprocess.run([sys.executable, "-c", pin_script], cwd=ROOT, env=env, check=True)
        assert output.read_bytes() == f"sha={pin_sha}\n".encode(), "GITHUB_OUTPUT must contain one valid SHA line"

    fixed = Path(os.environ.get("CH8_PR02_FIXED_REPO", "/root/kani-fix-ch8-pr02-reset-w15"))
    expected_cases = {"seed_only", "argument_seed", "no_seed", "contract_seed",
                      "uninit_read", "initialized_read", "uninit_off"}
    fixture_root = fixed / "tests/script-based-pre/autoharness_entry_reset"
    assert {p.name for p in fixture_root.iterdir() if p.is_dir()} == expected_cases
    for case in expected_cases:
        for name in ("main.rs", "run.sh", "config.yml", "expected"):
            assert (fixture_root / case / name).is_file(), f"missing {case}/{name}"
    print("CI package static checks PASS; compiler/verifier/CI runtime NOT_RUN")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
