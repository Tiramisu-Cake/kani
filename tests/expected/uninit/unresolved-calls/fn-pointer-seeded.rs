// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// kani-flags: -Z uninit-checks
// compile-flags: -D warnings

#[inline(never)]
fn indirect(f: fn(u8) -> u8, value: u8) -> u8 {
    f(value)
}

fn identity(value: u8) -> u8 {
    value
}

#[path = "auxiliary/analysis_target.rs"]
mod analysis_target;

#[kani::proof]
fn check() {
    analysis_target::check_byte_copy();
    assert_eq!(indirect(identity, 42), 42);
}
