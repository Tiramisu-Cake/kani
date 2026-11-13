// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

const ALLOCATION: &[MaybeUninit<u8>; 4] =
    &[MaybeUninit::new(0), MaybeUninit::new(0), MaybeUninit::new(0), MaybeUninit::new(0)];
// Use three bytes to avoid scalar transmute lowering; CI must confirm retained raw_eq.
// Only this subrange origin is used at runtime: offset 1, extent 3, allocation size 4.
const SUBRANGE: &[MaybeUninit<u8>; 3] =
    unsafe { &*ALLOCATION.as_ptr().add(1).cast::<[MaybeUninit<u8>; 3]>() };

// Known conservative limitation: immutable allocations are seeded only as whole
// allocations, so a constant subrange at a nonzero offset still starts uninitialized
// and this legal comparison reports a spurious uninitialized read.
#[kani::proof]
fn immutable_subrange_legal() {
    let right: &[MaybeUninit<u8>; 3] = &[MaybeUninit::new(0); 3];
    assert!(unsafe { raw_eq(SUBRANGE, right) });
}
