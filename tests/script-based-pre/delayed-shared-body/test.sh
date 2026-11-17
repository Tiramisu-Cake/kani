#!/usr/bin/env bash
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
F4_EVIDENCE_DIR="$work" python3 runner.py run
