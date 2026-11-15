#!/usr/bin/env bash
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail

repo=${1:?patched source checkout required}
export KANI_REPO="$repo"
export PATH="$repo/scripts:$PATH"
cd "$repo"

./scripts/kani-fmt.sh --check
cargo build-dev
cargo clippy --workspace --tests -- -D warnings
cargo test -p kani-compiler --bin kani-compiler
cargo build -p compiletest

compiletest="$repo/target/debug/compiletest"
run_slice() {
  local suite=$1 mode=$2 filter=$3
  "$compiletest" --suite "$suite" --mode "$mode" --timeout 600 \
    --no-fail-fast --force-rerun --color never "$filter"
}

# Existing focused coverage around uninitialized memory and immutable seeds,
# plus function-contract processing. New autoharness fixtures live in their
# own script-based-pre subtree and all seven run as separate expected cases.
run_slice expected expected 'uninit/'
run_slice expected expected 'function-contract/'
run_slice script-based-pre exec 'autoharness_entry_reset/'
run_slice script-based-pre exec 'autoharness'
