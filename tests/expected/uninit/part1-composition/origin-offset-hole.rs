// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

const IMMUTABLE: [MaybeUninit<u8>; 5] = [
    MaybeUninit::new(7),
    MaybeUninit::new(7),
    MaybeUninit::uninit(),
    MaybeUninit::new(7),
    MaybeUninit::new(7),
];

#[inline(never)]
unsafe fn copy_window(source: *const MaybeUninit<u8>, destination: *mut MaybeUninit<u8>) {
    // Source offset 1, destination offset 2, extent 3; both arrays remain in bounds.
    unsafe { std::ptr::copy_nonoverlapping(source.add(1), destination.add(2), 3) };
}

#[inline(never)]
unsafe fn compare_window(left: *const MaybeUninit<u8>, right: *const MaybeUninit<u8>) -> bool {
    unsafe { raw_eq(&*left.cast::<[MaybeUninit<u8>; 3]>(), &*right.cast::<[MaybeUninit<u8>; 3]>()) }
}

#[kani::proof]
fn origin_offset_hole() {
    // Select an allocation, not a reference to initialized payload over a hole.
    let promoted = &IMMUTABLE;
    let mut stack = [MaybeUninit::<u8>::uninit(); 5];
    stack[0].write(7);
    stack[1].write(7);
    // Leave source[2] unwritten.
    stack[3].write(7);
    stack[4].write(7);
    let source = if kani::any() { promoted.as_ptr() } else { stack.as_ptr() };
    let alias = source;
    // Preinitialized destination must acquire source false at source[2] -> destination[3].
    let mut destination = [MaybeUninit::new(7_u8); 6];
    let expected = [MaybeUninit::new(7_u8); 5];
    unsafe {
        copy_window(alias, destination.as_mut_ptr());
        let actual = destination.as_ptr().add(2);
        let companion = expected.as_ptr().add(1);
        let same = if kani::any() {
            compare_window(actual, companion)
        } else {
            compare_window(companion, actual)
        };
        assert!(same);
    }
}
