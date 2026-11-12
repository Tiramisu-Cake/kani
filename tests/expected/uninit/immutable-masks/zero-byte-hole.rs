// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

// Required binding: left None byte fails, right Some(0) bytes remain legal.
#[kani::proof]
fn zero_and_uninitialized_are_distinct() {
    let left: &[MaybeUninit<u8>; 3] =
        &[MaybeUninit::new(0), MaybeUninit::uninit(), MaybeUninit::new(0)];
    let right: &[MaybeUninit<u8>; 3] = &[MaybeUninit::new(0); 3];
    let _equal = unsafe { raw_eq(left, right) };
}
