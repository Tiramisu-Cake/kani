#!/usr/bin/env bash
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

repo=${1:?patched source checkout required}
export KANI_REPO="$repo"
export PATH="$repo/scripts:$PATH"
cd "$repo"

run_gate() {
  local gate=$1
  shift
  python3 "$CONTROL_DIR/scripts/ch8-pr02-reset/bounded_step.py" \
    --id "$gate" --cwd "$repo" -- "$@"
}

run_gate fmt ./scripts/kani-fmt.sh --check
run_gate build cargo build-dev
run_gate clippy cargo clippy --workspace --tests -- -D warnings
run_gate compiler-units cargo test -p kani-compiler --bin kani-compiler
run_gate compiletest-build cargo build -p compiletest

compiletest="$repo/target/debug/compiletest"
run_slice() {
  local suite=$1 mode=$2 filter=$3
  run_gate "${suite}-${filter//\//_}" "$compiletest" --suite "$suite" --mode "$mode" --timeout 600 \
    --no-fail-fast --force-rerun --color never "$filter"
}

# Existing focused coverage around uninitialized memory and immutable seeds,
# plus function-contract processing. New autoharness fixtures live in their
# top-level script-based-pre directories and all seven run as separate expected cases.
run_slice expected expected 'uninit/'
run_slice expected expected 'function-contract/'
run_slice script-based-pre exec 'autoharness_entry_reset_'
run_slice script-based-pre exec 'autoharness'
