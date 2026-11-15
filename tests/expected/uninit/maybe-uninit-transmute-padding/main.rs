// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};

#[repr(C)]
struct Padded {
    tag: u8,
    value: u64,
}

#[kani::proof]
fn typed_padding_is_not_initialized() {
    let source = Padded { tag: 7, value: 9 };
    let destination: MaybeUninit<Padded> = unsafe { mem::transmute(source) };
    // Byte 1 is padding on the pinned x86_64 layout, not an initialized data byte.
    assert_eq!(mem::offset_of!(Padded, value), 8);
    let _padding = unsafe { destination.as_ptr().cast::<u8>().add(1).read() };
}
