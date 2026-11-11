// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};
use std::ptr;

#[derive(Clone, Copy)]
#[repr(C, u8)]
enum Same {
    A(u32),
    B(u32),
}

#[repr(C)]
struct Nested {
    prefix: [u8; 16],
    value: Same,
}

#[kani::proof]
fn nested_enum_equal_layouts_preserve_data() {
    assert_eq!(mem::size_of::<Same>(), 8);
    assert_eq!(mem::offset_of!(Nested, value), 16);
    assert_eq!(mem::size_of::<Nested>(), 24);
    let second: bool = kani::any();
    let number: u32 = kani::any();
    let value = if second { Same::B(number) } else { Same::A(number) };
    let mut source = MaybeUninit::<Nested>::uninit();
    unsafe {
        ptr::addr_of_mut!((*source.as_mut_ptr()).prefix).write([9; 16]);
        ptr::addr_of_mut!((*source.as_mut_ptr()).value).write(value);
    }
    let destination = source;
    unsafe {
        assert_eq!((*destination.as_ptr()).prefix, [9; 16]);
        match ptr::addr_of!((*destination.as_ptr()).value).read() {
            Same::A(actual) => {
                assert!(!second);
                assert_eq!(actual, number);
            }
            Same::B(actual) => {
                assert!(second);
                assert_eq!(actual, number);
            }
        }
    }
}
