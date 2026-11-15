// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, ManuallyDrop, MaybeUninit};
use std::ptr;

#[inline(never)]
fn carry(slot: MaybeUninit<u8>) -> MaybeUninit<u8> {
    slot
}

#[kani::proof]
fn reset_through_another_alias() {
    let mut slot = MaybeUninit::new(7u8);
    let writer = ptr::addr_of_mut!(slot);
    let reader = writer.cast_const();
    unsafe {
        assert_eq!((*reader).assume_init_read(), 7);
        *writer = MaybeUninit::uninit();
        let copied = carry(*reader);
        let wrapped: ManuallyDrop<u8> = mem::transmute(copied);
        assert_eq!(ManuallyDrop::into_inner(wrapped), 7);
    }
}
