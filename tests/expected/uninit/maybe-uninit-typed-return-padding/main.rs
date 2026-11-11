// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};

#[derive(Clone, Copy)]
#[repr(C)]
struct Padded {
    tag: u8,
    value: u32,
}

fn check_layout() {
    assert_eq!(mem::offset_of!(Padded, tag), 0);
    assert_eq!(mem::offset_of!(Padded, value), 4);
    assert_eq!(mem::size_of::<Padded>(), 8);
    assert_eq!(mem::size_of::<MaybeUninit<Padded>>(), 8);
}

#[inline(never)]
fn return_slot() -> MaybeUninit<Padded> {
    let mut slot = MaybeUninit::<Padded>::uninit();
    unsafe { slot.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 8) };
    assert_eq!(unsafe { slot.as_ptr().cast::<u8>().add(1).read() }, 0x5a);
    slot
}

#[kani::proof]
fn typed_return_discards_written_padding() {
    check_layout();
    let destination = return_slot();
    let _padding = unsafe { destination.as_ptr().cast::<u8>().add(1).read() };
}
