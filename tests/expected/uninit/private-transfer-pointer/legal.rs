// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;
use std::ptr::{addr_of, addr_of_mut};

// No Copy, Clone or Drop: require CI to bind the actual Move and return path.
#[repr(C)]
struct Payload {
    first: u8,
    second: u8,
    third: u8,
}

#[inline(never)]
fn transfer(source: MaybeUninit<Payload>) -> MaybeUninit<Payload> {
    source
}

#[kani::proof]
fn nonzero_offset_move_return_legal() {
    let mut source = MaybeUninit::<Payload>::uninit();
    let data = source.as_mut_ptr();
    unsafe {
        addr_of_mut!((*data).first).write(11u8);
        addr_of_mut!((*data).second).write(22u8);
        addr_of_mut!((*data).third).write(33u8);
    }

    let returned = transfer(source);
    let data = returned.as_ptr();
    unsafe {
        assert_eq!(addr_of!((*data).first).read(), 11u8);
        assert_eq!(addr_of!((*data).second).read(), 22u8);
        assert_eq!(addr_of!((*data).third).read(), 33u8);
    }
}
