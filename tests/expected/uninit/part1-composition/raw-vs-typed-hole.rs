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
fn raw_vs_typed_hole() {
    layout();
    // Flat two-slot carrier; slot 1 stride is 8, final data byte is offset 15.
    let mut source = [MaybeUninit::<Padded>::uninit(); 2];
    // Initialized old data must be replaced, including by a source-following false byte.
    let mut destination = [MaybeUninit::new(Padded { tag: 0x11, value: 0x11111111 }); 2];
    unsafe { source.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 15) };
    if kani::any() {
        unsafe { std::ptr::copy_nonoverlapping(source.as_ptr(), destination.as_mut_ptr(), 2) };
        assert_eq!(unsafe { destination[1].as_ptr().cast::<u8>().add(1).read() }, 0x5a);
    } else {
        destination = source;
    }
    assert_eq!(unsafe { (*destination[0].as_ptr()).value }, 0x5a5a5a5a);
    assert_eq!(unsafe { (*destination[1].as_ptr()).tag }, 0x5a);
    // Required last data byte follows source even on the typed path.
    assert_eq!(unsafe { destination[1].as_ptr().cast::<u8>().add(7).read() }, 0x5a);
}
