// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

#[kani::proof]
fn immutable_relocation_legal() {
    // Use three pointer-sized slots to avoid scalar transmute lowering in raw_eq.
    // Slot 0 has a relocation in BOTH cases; the hole is slot 1, not an invalid &u8.
    let left: &[MaybeUninit<&u8>; 3] = &[MaybeUninit::new(&0u8); 3];
    let right: &[MaybeUninit<&u8>; 3] = &[MaybeUninit::new(&0u8); 3];
    let _equal = unsafe { raw_eq(left, right) };
}
