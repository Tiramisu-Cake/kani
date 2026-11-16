#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Run matched seeded autoharnesses on old PR-02 and require the known fatal."""
import argparse
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

FATAL = "immutable masks: reset is absent from this model"
CASES = ("seed_only", "argument_seed", "no_seed", "contract_seed",
         "uninit_read", "initialized_read", "uninit_off")
SEEDED_FATAL = {"seed_only", "argument_seed", "contract_seed"}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--old-repo", required=True, type=Path)
    parser.add_argument("--fixed-repo", required=True, type=Path)
    args = parser.parse_args()
    fixture_root = args.fixed_repo / "tests/script-based-pre"
    kani = args.old_repo / "scripts/kani"
    for case in CASES:
        case_dir = fixture_root / f"autoharness_entry_reset_{case}"
        source = case_dir / "main.rs"
        script = case_dir / "run.sh"
        if not source.is_file():
            raise SystemExit(f"missing matched fixture: {source}")
        if not script.is_file():
            raise SystemExit(f"missing matched runner: {script}")
        with tempfile.TemporaryDirectory(prefix=f"ch8-old-{case}-") as tmp:
            tmp_path = Path(tmp)
            shutil.copy2(source, tmp_path / "main.rs")
            script_text = script.read_text()
            command = next((line.strip() for line in script_text.splitlines()
                            if line.strip().startswith("kani ")), None)
            if command is None:
                raise SystemExit(f"missing Kani command in {script}")
            command = command.split("||", 1)[0].rstrip("\\ ")
            argv = shlex.split(command)
            argv[0] = str(kani)
            env = os.environ.copy()
            env["NO_COLOR"] = "1"
            result = subprocess.run(argv, cwd=tmp_path, env=env, text=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=600)
            if case in SEEDED_FATAL:
                valid = result.returncode == 1 and FATAL in result.stdout
            elif case == "uninit_read":
                success = (result.returncode == 0 and "Complete - 1 successfully verified functions, 0 failures, 1 total." in result.stdout)
                intended_failure = (result.returncode == 1 and "Undefined Behavior: Reading from an uninitialized pointer of type `u8`" in result.stdout
                                    and "Complete - 0 successfully verified functions, 1 failures, 1 total." in result.stdout)
                valid = success or intended_failure
            else:
                valid = (result.returncode == 0 and "Complete - 1 successfully verified functions, 0 failures, 1 total." in result.stdout)
            if not valid:
                print(result.stdout)
                raise SystemExit(f"old control {case}: unexpected result")
            outcome = "expected fatal observed" if case in SEEDED_FATAL else "expected completed outcome observed"
            print(f"old control {case}: {outcome}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
