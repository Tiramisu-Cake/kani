// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular
use std::{mem::MaybeUninit, ptr};
#[kani::proof]
fn repeat_local() {
    let mut source = MaybeUninit::<u64>::uninit();
    let mut slots = [MaybeUninit::new(9u64); 3];
    unsafe {
        ptr::addr_of_mut!(source).write(MaybeUninit::uninit());
    }
    slots = [source; 3];
    let _value = unsafe { slots[2].assume_init() };
}
