#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Verify CI-REQUEST's source pin and patch digest, then apply the source delta."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
CONTROL = HERE.parents[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True, type=Path)
    parser.add_argument("--pin-key", choices=("A", "B"), required=True)
    args = parser.parse_args()
    req = json.loads((CONTROL / "CI-REQUEST.json").read_text())
    pin = req["pins"]["pr02" if args.pin_key == "A" else "sel1"]
    head = subprocess.check_output(["git", "-C", str(args.repo), "rev-parse", "HEAD"], text=True).strip()
    if head != pin["sha"]:
        raise SystemExit(f"unexpected source HEAD: expected {pin['sha']}, got {head}")
    base_tree = subprocess.check_output(["git", "-C", str(args.repo), "rev-parse", "HEAD^{tree}"], text=True).strip()
    if base_tree != pin["tree"]:
        raise SystemExit(f"unexpected source tree: expected {pin['tree']}, got {base_tree}")
    patch = CONTROL / req["patch"]["path"]
    digest = hashlib.sha256(patch.read_bytes()).hexdigest()
    expected = req["patch"]["sha256"]
    if expected.startswith("PENDING") or digest != expected:
        raise SystemExit(f"patch SHA mismatch: expected {expected}, got {digest}")
    subprocess.run(["git", "-C", str(args.repo), "apply", "--check", str(patch)], check=True)
    subprocess.run(["git", "-C", str(args.repo), "apply", str(patch)], check=True)
    with tempfile.TemporaryDirectory(prefix="ch8-index-") as temp_dir:
        env = {**os.environ, "GIT_INDEX_FILE": str(Path(temp_dir) / "index")}
        subprocess.run(["git", "-C", str(args.repo), "read-tree", "HEAD"], env=env, check=True)
        subprocess.run(["git", "-C", str(args.repo), "add", "--all"], env=env, check=True)
        patched_tree = subprocess.check_output(["git", "-C", str(args.repo), "write-tree"], env=env, text=True).strip()
    if patched_tree != pin["patched_tree"]:
        raise SystemExit(f"patched tree mismatch: expected {pin['patched_tree']}, got {patched_tree}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
