#!/usr/bin/env bash
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
python3 "$SCRIPT_DIR/test_compare.py"
python3 "$SCRIPT_DIR/test_bindings.py"
exec python3 "$SCRIPT_DIR/run.py" "$@"
