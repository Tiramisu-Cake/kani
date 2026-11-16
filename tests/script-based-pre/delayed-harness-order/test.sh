#!/usr/bin/env bash
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -uo pipefail
unset CARGO_ENCODED_RUSTFLAGS 2>/dev/null || true
work=$(mktemp -d)
remove_lock=0
if [[ ! -e Cargo.lock ]]; then remove_lock=1; fi
cleanup() {
    rm -rf "$work"
    if [[ "$remove_lock" == 1 ]]; then rm -f Cargo.lock; fi
}
trap cleanup EXIT

run() {
    local label="$1"
    local mode="$2"
    shift 2
    local feature_args=()
    if [[ "$mode" == delayed_first ]]; then
        feature_args=(--features delayed-first)
    fi
    set +e
    timeout 120s env -u CARGO_ENCODED_RUSTFLAGS "CARGO_TARGET_DIR=$work/target-$label" cargo kani \
        -Z ghost-state -Z uninit-checks -Z export-json "${feature_args[@]}" \
        --export-json "$work/$label.json" "$@" >"$work/$label.stdout" 2>"$work/$label.stderr"
    local status=$?
    set -e
    cat "$work/$label.stdout" "$work/$label.stderr" >"$work/$label.log"
    printf '%s\n' "$status" >"$work/$label.status"
    printf '%s\0' timeout 120s env -u CARGO_ENCODED_RUSTFLAGS \
        "CARGO_TARGET_DIR=$work/target-$label" cargo kani -Z ghost-state -Z uninit-checks -Z export-json "${feature_args[@]}" \
        --export-json "$work/$label.json" "$@" >"$work/$label.argv"
    printf '%s\n' "${RUSTFLAGS-}" >"$work/$label.rustflags"
    printf '%s\n' "$work/target-$label" >"$work/$label.target-dir"
}

python3 compare.py --self-test >/dev/null || exit 2
for mode in delayed_first control_first; do
    run "${mode}-delayed-alone" "$mode" --harness delayed_harness
    run "${mode}-control-alone" "$mode" --harness initialized_control_harness
    run "${mode}-paired" "$mode" --harness delayed_harness --harness initialized_control_harness
done

python3 compare.py --runs-dir "$work"
