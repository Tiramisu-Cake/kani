// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};
use std::ptr;

#[repr(C)]
struct Padded {
    tag: u8,
    value: u64,
}

#[kani::proof]
fn scalar_copy() {
    let source: u64 = kani::any();
    let destination: MaybeUninit<u64> = unsafe { mem::transmute(source) };
    assert_eq!(unsafe { destination.assume_init() }, source);
    // Copy retains the source witness as well as the destination witness.
    assert_eq!(unsafe { ptr::addr_of!(source).read() }, source);
}

#[kani::proof]
fn exact_usize_array_copy() {
    let source: [usize; 2] = kani::any();
    let destination: [MaybeUninit<usize>; 2] = unsafe { mem::transmute(source) };
    assert_eq!(unsafe { destination[0].assume_init() }, source[0]);
    assert_eq!(unsafe { destination[1].assume_init() }, source[1]);
    assert_eq!(unsafe { ptr::addr_of!(source).read() }, source);
}

#[kani::proof]
fn empty_array() {
    let source: [usize; 0] = [];
    let destination: [MaybeUninit<usize>; 0] = unsafe { mem::transmute(source) };
    assert_eq!(destination.len(), 0);
}

#[kani::proof]
fn zst_array() {
    let source = [(); 2];
    let destination: [MaybeUninit<()>; 2] = unsafe { mem::transmute(source) };
    unsafe {
        destination[0].assume_init();
        destination[1].assume_init();
    }
}

#[kani::proof]
fn padded_move() {
    let source = Padded { tag: 7, value: 9 };
    let destination: MaybeUninit<Padded> = unsafe { mem::transmute(source) };
    let result = unsafe { destination.assume_init() };
    assert_eq!((result.tag, result.value), (7, 9));
}

#[kani::proof]
fn padded_array_move() {
    let source = [Padded { tag: 7, value: 9 }, Padded { tag: 11, value: 13 }];
    let destination: [MaybeUninit<Padded>; 2] = unsafe { mem::transmute(source) };
    // Borrow the non-Copy elements instead of moving out of an indexed array place.
    let first = unsafe { destination[0].assume_init_ref() };
    let second = unsafe { destination[1].assume_init_ref() };
    assert_eq!((first.tag, first.value), (7, 9));
    assert_eq!((second.tag, second.value), (11, 13));
}
