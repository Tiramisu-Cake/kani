// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular
use std::{
    mem::{self, ManuallyDrop, MaybeUninit},
    ptr,
};
#[repr(C)]
struct Padded {
    a: u8,
    b: u64,
}
#[kani::proof]
fn incomplete_padded_transmute() {
    let mut slot = MaybeUninit::<Padded>::uninit();
    unsafe {
        ptr::addr_of_mut!((*slot.as_mut_ptr()).a).write(7);
    }
    let _value: ManuallyDrop<Padded> = unsafe { mem::transmute(slot) };
}
