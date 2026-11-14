// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::{self, MaybeUninit};

// Three bytes cannot be simplified by rustc's InstSimplify into integer transmutes.
#[kani::proof]
fn raw_eq_initialized_arrays() {
    let left: [u8; 3] = kani::any();
    let mut right = left;
    assert!(unsafe { raw_eq(&left, &right) });
    right[2] ^= 1;
    assert!(!unsafe { raw_eq(&left, &right) });
}

#[inline(never)]
fn equal_referenced_arrays(left: &[u8; 3], right: &[u8; 3]) -> bool {
    unsafe { raw_eq(left, right) }
}

#[kani::proof]
fn raw_eq_initialized_array_references() {
    let left: [u8; 3] = kani::any();
    let mut right = left;
    assert!(equal_referenced_arrays(&left, &right));
    right[2] ^= 1;
    assert!(!equal_referenced_arrays(&left, &right));
}

#[kani::proof]
fn raw_eq_initialized_scalars() {
    let left: u32 = kani::any();
    let right: u32 = kani::any();
    let equal = unsafe { raw_eq(&left, &right) };
    assert_eq!(equal, left == right);
}

#[kani::proof]
fn raw_eq_initialized_storage() {
    let left = [MaybeUninit::new(7u8); 3];
    let right = [MaybeUninit::new(7u8); 3];
    assert!(unsafe { raw_eq(&left, &right) });
}

#[kani::proof]
fn raw_eq_left_uninitialized_byte() {
    let mut left = [MaybeUninit::new(7u8); 3];
    let right = [MaybeUninit::new(7u8); 3];
    left[0] = MaybeUninit::uninit();
    // The references are valid; the only invalid read is raw_eq's first byte.
    let _equal = unsafe { raw_eq(&left, &right) };
}

#[repr(C)]
struct Padded {
    tag: u8,
    value: [u32; 2],
}

#[kani::proof]
fn raw_eq_padding_is_uninitialized() {
    assert_eq!(mem::size_of::<Padded>(), 12);
    assert_eq!(mem::offset_of!(Padded, value), 4);
    // Typed transfers initialize data but leave padding uninitialized. Twelve bytes
    // also avoid the integer-transmute simplification used by the original fixture.
    let left: MaybeUninit<Padded> = unsafe { mem::transmute(Padded { tag: 7, value: [9, 9] }) };
    let right: MaybeUninit<Padded> = unsafe { mem::transmute(Padded { tag: 7, value: [9, 9] }) };
    let _equal = unsafe { raw_eq(&left, &right) };
}

#[kani::proof]
fn raw_eq_right_uninitialized_byte() {
    let left = [MaybeUninit::new(7u8); 3];
    let mut right = [MaybeUninit::new(7u8); 3];
    right[2] = MaybeUninit::uninit();
    // Distinct allocations and a hole at the end cover the second operand's extent.
    let _equal = unsafe { raw_eq(&left, &right) };
}

#[kani::proof]
fn raw_eq_zero_sized() {
    let left: [u8; 0] = [];
    let right: [u8; 0] = [];
    assert!(unsafe { raw_eq(&left, &right) });
}
