// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;
use std::ptr;

#[kani::proof]
fn forming_a_raw_address_leaves_the_byte_uninitialized() {
    let mut slot = MaybeUninit::<(u8, u8)>::uninit();
    let pair = slot.as_mut_ptr();
    unsafe {
        ptr::addr_of_mut!((*pair).0).write(7);
        let second = ptr::addr_of!((*pair).1);
        assert_eq!(*second, 8);
    }
}
