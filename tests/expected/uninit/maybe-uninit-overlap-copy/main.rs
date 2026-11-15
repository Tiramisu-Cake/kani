// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::{mem::MaybeUninit, ptr};

#[kani::proof]
fn overlap_copy_right() {
    let mut slots = [MaybeUninit::new(1u8), MaybeUninit::uninit(), MaybeUninit::new(3)];
    let p = slots.as_mut_ptr();
    unsafe {
        ptr::copy(p, p.add(1), 2);
        let _value = slots[2].assume_init();
    }
}

#[kani::proof]
fn overlap_copy_left() {
    let mut slots = [MaybeUninit::new(1u8), MaybeUninit::uninit(), MaybeUninit::new(3)];
    let p = slots.as_mut_ptr();
    unsafe {
        ptr::copy(p.add(1), p, 2);
        let _value = slots[0].assume_init();
    }
}
