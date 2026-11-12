// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// kani-flags: -Z uninit-checks
// compile-flags: -D warnings

#![feature(fn_traits)]

fn identity(value: u8) -> u8 {
    value
}

#[inline(never)]
fn indirect(f: fn(u8) -> u8) -> u8 {
    // The pinned source call is used to probe Fn-trait Shim lowering. CI must confirm whether
    // the resolved Shim is bodyless or bodyful before assigning a lowering-specific property.
    std::ops::Fn::call(&f, (42,))
}

#[kani::proof]
fn check() {
    assert_eq!(indirect(identity), 42);
}
