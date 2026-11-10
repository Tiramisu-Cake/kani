// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};
use std::ptr;

#[kani::proof]
fn partial_write_then_assume_init() {
    let mut slot = MaybeUninit::<(u8, u8)>::uninit();
    let pair = slot.as_mut_ptr();
    unsafe {
        ptr::addr_of_mut!((*pair).0).write(7);
        let value: (u8, u8) = mem::transmute(slot);
        assert_eq!(value.0, 7);
        assert_eq!(value.1, 8);
    }
}
