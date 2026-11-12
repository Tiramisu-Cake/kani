// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

// Required binding: anonymous None -> raw copy -> mutable target -> left raw_eq failure.
// The other operand must independently pass its byte-initialization check.
#[kani::proof]
fn copied_immutable_hole_remains_uninitialized() {
    let source: &[MaybeUninit<u8>; 3] =
        &[MaybeUninit::new(0), MaybeUninit::uninit(), MaybeUninit::new(0)];
    let mut target = [MaybeUninit::new(0u8); 3];
    unsafe {
        std::ptr::copy_nonoverlapping(source.as_ptr(), target.as_mut_ptr(), 3);
    }
    let right: &[MaybeUninit<u8>; 3] = &[MaybeUninit::new(0); 3];
    let _equal = unsafe { raw_eq(&target, right) };
}
