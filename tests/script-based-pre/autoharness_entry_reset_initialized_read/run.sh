#!/usr/bin/env bash
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail
kani autoharness -Z uninit-checks -Z autoharness --include-pattern initialized_read --output-format=regular main.rs
