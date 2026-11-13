// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

const ALLOCATION: &[MaybeUninit<u8>; 3] =
    &[MaybeUninit::new(0), MaybeUninit::new(0), MaybeUninit::uninit()];
// Only this subrange origin is used at runtime: offset 1, extent 2, allocation size 3.
const SUBRANGE: &[MaybeUninit<u8>; 2] =
    unsafe { &*ALLOCATION.as_ptr().add(1).cast::<[MaybeUninit<u8>; 2]>() };

#[kani::proof]
fn immutable_subrange_hole() {
    let right: &[MaybeUninit<u8>; 2] = &[MaybeUninit::new(0); 2];
    let _equal = unsafe { raw_eq(SUBRANGE, right) };
}
