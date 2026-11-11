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
fn typed_array_discards_second_slot_padding() {
    check_layout();
    let mut source = [MaybeUninit::<Padded>::uninit(); 2];
    assert_eq!(mem::size_of_val(&source), 16);
    unsafe {
        assert_eq!(
            source.as_ptr().add(1).cast::<u8>().offset_from(source.as_ptr().cast::<u8>()),
            8
        );
        source.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 16);
    }
    assert_eq!(unsafe { source[1].as_ptr().cast::<u8>().add(1).read() }, 0x5a);
    let destination = source;
    assert_eq!(unsafe { (*destination[0].as_ptr()).value }, 0x5a5a5a5a);
    assert_eq!(unsafe { (*destination[1].as_ptr()).value }, 0x5a5a5a5a);
    let _padding = unsafe { destination[1].as_ptr().cast::<u8>().add(1).read() };
}
