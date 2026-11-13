#!/bin/bash
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail
cd "$1"
test "$(git rev-parse HEAD)" = 4f64cc617cbe6ebd13e83c07cc62fcf245e0b53c
test "$(git rev-parse 'HEAD^{tree}')" = af28e22ec446b254cfa3a28b2882eafa58d5a458
git diff --exit-code
rustup toolchain install
GIT_LFS_SKIP_SMUDGE=1 git submodule update --init --depth 1
./scripts/setup/ubuntu/install_deps.sh
cbmc_version="$(cbmc --version)"
echo "cbmc --version: $cbmc_version"
case "$cbmc_version" in "6.11.0"|"6.11.0 (cbmc-6.11.0)") ;; *) echo "unexpected CBMC version" >&2; exit 1 ;; esac
