// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

use std::marker::PhantomData;

struct Packet {
    slot: MaybeUninit<u8>,
}

#[inline(never)]
fn ordinary(value: (u8, [u8; 2], PhantomData<MaybeUninit<u8>>)) -> (u8, [u8; 2]) {
    (value.0, value.1)
}

#[inline(never)]
fn through_ref(value: &Packet) -> u8 {
    unsafe { value.slot.assume_init() }
}

#[inline(never)]
fn through_raw(value: *const Packet) -> bool {
    // Classification of the pointer value does not require aggregate pointee reads.
    value.is_null()
}

#[kani::proof]
fn ordinary_and_pointers_legal() {
    assert_eq!(ordinary((23, [1, 2], PhantomData)), (23, [1, 2]));
    let value = Packet { slot: MaybeUninit::new(42) };
    assert_eq!(through_ref(&value), 42);
    assert!(through_raw(std::ptr::null()));
}
