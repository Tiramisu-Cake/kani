#!/usr/bin/env bash
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT

set -euo pipefail
kani autoharness -Z uninit-checks -Z function-contracts -Z autoharness --include-pattern contract_seed --output-format=regular main.rs
