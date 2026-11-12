// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

// Both references are valid; the first payload read is in the Assert postcondition.
// Require the left operand's byte check to fail and the initialized companion to pass.
#[kani::ensures(|result: &&[MaybeUninit<u8>; 3]| unsafe {
    raw_eq(*result, &[MaybeUninit::new(7u8); 3])
})]
fn promoted_hole() -> &'static [MaybeUninit<u8>; 3] {
    // Evaluate uninit() in a const item, then borrow the immutable constant value.
    const HOLE: [MaybeUninit<u8>; 3] =
        [MaybeUninit::uninit(), MaybeUninit::new(7u8), MaybeUninit::new(7u8)];
    &HOLE
}

#[kani::proof]
fn ensures_left_hole() {
    let _unread = promoted_hole();
}
