// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --default-unwind 8 --output-format=terse

// Keep every standalone positive control, grouped to leave manifest slots for
// all four isolated U3B PFC on/off controls.
#[path = "../compound-cmp1-call-positive/main.rs"]
mod call;
#[path = "../compound-cmp1-drop-positive/main.rs"]
mod drop;
#[path = "../compound-cmp1-fields-positive/main.rs"]
mod fields;
#[path = "../compound-cmp1-zero-zst-positive/main.rs"]
mod zero_zst;
