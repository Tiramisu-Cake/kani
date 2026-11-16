#!/usr/bin/env bash
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -u
output=$(RUSTFLAGS='--edition=2021' kani autoharness -Z autoharness -Z uninit-checks \
    --include-pattern '::read_(data|padding)$' --output-format=regular fixture.rs 2>&1)
code=$?
printf '%s\nKani exit: %s\n' "$output" "$code"

test "$code" -eq 1 &&
    grep -Fq 'Failed Checks: Undefined Behavior: Reading from an uninitialized pointer' <<< "$output" &&
    grep -Fq 'Complete - 1 successfully verified functions, 1 failures, 2 total.' <<< "$output"
