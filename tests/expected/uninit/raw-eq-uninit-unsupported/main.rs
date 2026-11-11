// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

#[repr(C)]
struct Padded {
    tag: u8,
    value: u32,
}

#[kani::proof]
fn raw_eq_initialized_scalars_is_unsupported() {
    let left: u32 = kani::any();
    let right: u32 = kani::any();
    let equal = unsafe { raw_eq(&left, &right) };
    assert_eq!(equal, left == right);
}

#[kani::proof]
fn raw_eq_uninitialized_storage_is_unsupported() {
    // References to MaybeUninit are valid even when its data is uninitialized.
    let left = MaybeUninit::<u32>::uninit();
    let right = MaybeUninit::<u32>::uninit();
    let equal = unsafe { raw_eq(&left, &right) };
    kani::cover!(equal);
}

#[kani::proof]
fn raw_eq_padding_is_unsupported() {
    let left = Padded { tag: 7, value: 9 };
    let right = Padded { tag: 7, value: 9 };
    assert_eq!((left.tag, left.value), (right.tag, right.value));
    let equal = unsafe { raw_eq(&left, &right) };
    kani::cover!(equal);
}
