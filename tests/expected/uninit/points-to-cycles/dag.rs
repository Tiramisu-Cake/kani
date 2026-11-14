// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

// The shared leaf is called through a diamond and again with a different
// initial alias graph. Distinct input targets must never share a cached summary.
#[inline(never)]
fn leaf(value: *const u8) -> *const u8 {
    value
}

#[inline(never)]
fn left(value: *const u8) -> *const u8 {
    leaf(value)
}

#[inline(never)]
fn right(value: *const u8) -> *const u8 {
    leaf(value)
}

#[kani::proof]
fn diamond_two_inputs() {
    let a = MaybeUninit::new(17_u8);
    let b = MaybeUninit::new(29_u8);
    assert_eq!(unsafe { left(a.as_ptr()).read() }, 17);
    assert_eq!(unsafe { right(b.as_ptr()).read() }, 29);
    assert_eq!(unsafe { leaf(a.as_ptr()).read() }, 17);
    kani::cover!(true, "both distinct pointees consumed");
}

#[kani::proof]
fn repeated_callee_preserves_hole() {
    let a = MaybeUninit::new(17_u8);
    let b = MaybeUninit::<u8>::uninit();
    assert_eq!(unsafe { left(a.as_ptr()).read() }, 17);
    assert_eq!(unsafe { right(b.as_ptr()).read() }, 29);
}
