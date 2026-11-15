// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{MaybeUninit, offset_of, size_of};

#[repr(C)]
struct Pair {
    head: u8,
    value: u32,
    tail: u8,
}

#[kani::proof]
fn raw_field_legal() {
    assert_eq!(offset_of!(Pair, value), 4);
    assert_eq!(offset_of!(Pair, tail), 8);
    assert_eq!(size_of::<Pair>(), 12);
    let mut storage = MaybeUninit::<Pair>::uninit();
    let pointer = storage.as_mut_ptr();
    let alias = pointer;
    // Raw address formation never constructs an initialized reference to Pair.
    unsafe {
        (*alias).value = 0x1234_5678u32;
        assert_eq!(std::ptr::read_volatile(std::ptr::addr_of!((*pointer).value)), 0x1234_5678);
    }
}
