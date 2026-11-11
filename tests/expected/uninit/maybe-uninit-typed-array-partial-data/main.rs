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

#[kani::proof]
fn typed_array_preserves_second_slot_unwritten_data() {
    check_layout();
    let mut source = [MaybeUninit::<Padded>::uninit(); 2];
    assert_eq!(mem::size_of_val(&source), 16);
    unsafe {
        // Slot 0 is completely written; offset 15 is slot 1's final data byte.
        source.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 15);
    }
    let destination = source;
    assert_eq!(unsafe { (*destination[0].as_ptr()).value }, 0x5a5a5a5a);
    assert_eq!(unsafe { destination[1].as_ptr().cast::<u8>().read() }, 0x5a);
    let _data = unsafe { destination[1].as_ptr().cast::<u8>().add(7).read() };
}
