// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

// Required lowering: retained raw_eq over both promoted three-byte referents.
// Promotion, Some/None masks, operand checks and helper propagation require CI binding.
// Both MaybeUninit references are valid before raw_eq; no constant storage is mutated.
// Require the right operand byte check to fail and the other operand check to succeed.
// Earlier UB/Unsupported or an additional failure does not satisfy this control.
#[kani::proof]
fn promoted_direct_right_hole() {
    let left: &[MaybeUninit<u8>; 3] = &[MaybeUninit::new(7u8); 3];
    let right: &[MaybeUninit<u8>; 3] =
        &[MaybeUninit::new(7u8), MaybeUninit::new(7u8), MaybeUninit::uninit()];
    let _equal = unsafe { raw_eq(left, right) };
}
