// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};
use std::ptr;

#[derive(Clone, Copy)]
#[repr(C, u8)]
enum Different {
    A(u32, u8),
    B(u32),
}

#[repr(C)]
struct Nested {
    prefix: [u8; 16],
    value: Different,
}

#[kani::proof]
fn nested_enum_different_padding_is_unsupported() {
    assert_eq!(mem::size_of::<Different>(), 12);
    assert_eq!(mem::offset_of!(Nested, value), 16);
    assert_eq!(mem::size_of::<Nested>(), 28);
    let second: bool = kani::any();
    let value = if second { Different::B(7) } else { Different::A(7, 9) };
    let mut source = MaybeUninit::<Nested>::uninit();
    unsafe {
        ptr::addr_of_mut!((*source.as_mut_ptr()).prefix).write([9; 16]);
        ptr::addr_of_mut!((*source.as_mut_ptr()).value).write(value);
    }
    // The preserve mask must reject the whole Nested payload: offset 16 exceeds
    // the enum's size 12, which used to clip both variant masks to all-false.
    let destination = source;
    let actual = unsafe { ptr::addr_of!((*destination.as_ptr()).value).read() };
    match actual {
        Different::A(number, byte) => {
            assert_eq!(number, 7);
            assert_eq!(byte, 9);
        }
        Different::B(number) => assert_eq!(number, 7),
    }
}
