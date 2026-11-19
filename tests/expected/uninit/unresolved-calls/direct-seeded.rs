// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// kani-flags: -Z uninit-checks
// compile-flags: -D warnings

#[inline(never)]
fn direct(value: u8) -> u8 {
    value
}

#[path = "auxiliary/analysis_target.rs"]
mod analysis_target;

#[kani::proof]
fn check() {
    analysis_target::check_byte_copy();
    assert_eq!(direct(42), 42);
}
