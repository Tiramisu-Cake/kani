// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};

#[repr(C)]
#[derive(Clone, Copy)]
struct Padded {
    tag: u8,
    value: u32,
}

fn layout() {
    assert_eq!(mem::size_of::<Padded>(), 8);
    assert_eq!(mem::offset_of!(Padded, value), 4);
    assert_eq!(mem::size_of::<MaybeUninit<Padded>>(), 8);
}

#[kani::proof]
fn typed_padding_hole() {
    layout();
    let mut source = [MaybeUninit::<Padded>::uninit(); 2];
    unsafe { source.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 16) };
    let mut destination = [MaybeUninit::<Padded>::uninit(); 2];
    unsafe { std::ptr::copy_nonoverlapping(source.as_ptr(), destination.as_mut_ptr(), 2) };
    assert_eq!(unsafe { destination[1].as_ptr().cast::<u8>().add(1).read() }, 0x5a);
    // Typed overwrite resets padding despite the previous raw full-extent transfer.
    destination = source;
    assert_eq!(unsafe { (*destination[1].as_ptr()).value }, 0x5a5a5a5a);
    let _padding = unsafe { destination[1].as_ptr().cast::<u8>().add(1).read() };
}
