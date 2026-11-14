// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[repr(C)]
struct Padded {
    tag: u8,
    word: u32,
}

#[inline(never)]
fn read_padding(value: Padded) -> u8 {
    // repr(C) byte 1 is padding, independently of its unspecified actual value.
    // The ordinary parameter entry mask must leave that byte false.
    kani::cover!(true, "padded parameter reached byte read");
    unsafe { std::ptr::addr_of!(value).cast::<u8>().add(1).read() }
}

#[kani::proof]
#[kani::unwind(8)]
fn ordinary_parameter_does_not_bless_padding() {
    let mut storage = MaybeUninit::<Padded>::uninit();
    let ptr = storage.as_mut_ptr();
    unsafe {
        std::ptr::addr_of_mut!((*ptr).tag).write(7);
        std::ptr::addr_of_mut!((*ptr).word).write(42);
    }
    // This typed value is valid: padding is allowed to be uninitialized.
    let value = unsafe { storage.assume_init() };
    let byte = read_padding(value);
    kani::cover!(byte == 0, "padding result consumed");
}
