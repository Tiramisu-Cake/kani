// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

// Empty extents must not introduce a seed mask index or pointer-object query.
#[kani::proof]
fn empty_immutable_arrays() {
    let left: &[MaybeUninit<u8>; 0] = &[];
    let right: &[MaybeUninit<u8>; 0] = &[];
    assert!(unsafe { raw_eq(left, right) });
}
