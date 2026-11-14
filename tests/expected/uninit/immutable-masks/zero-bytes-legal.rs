// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

// Both operands must bind to immutable Some(0), rather than physical zero fill.
#[kani::proof]
fn initialized_zero_bytes() {
    let left: &[MaybeUninit<u8>; 3] = &[MaybeUninit::new(0); 3];
    let right: &[MaybeUninit<u8>; 3] = &[MaybeUninit::new(0); 3];
    assert!(unsafe { raw_eq(left, right) });
}
