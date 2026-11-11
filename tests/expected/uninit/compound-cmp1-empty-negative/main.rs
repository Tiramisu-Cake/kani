// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=terse

use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
struct C {
    marker: usize,
    slots: [MaybeUninit<usize>; 2],
}

#[kani::proof]
fn empty_source_slot_read() {
    let value = C { marker: 11, slots: [MaybeUninit::new(7), MaybeUninit::uninit()] };
    assert_eq!(value.marker, 11);
    assert_eq!(unsafe { value.slots[0].assume_init() }, 7);
    kani::cover!(true);
    unsafe {
        value.slots[1].assume_init();
    }
}

#[kani::proof]
fn empty_copy_destination_slot_read() {
    let value = C { marker: 13, slots: [MaybeUninit::new(17), MaybeUninit::uninit()] };
    let copy = value;
    assert_eq!(value.marker, 13);
    assert_eq!(unsafe { value.slots[0].assume_init() }, 17);
    assert_eq!(copy.marker, 13);
    assert_eq!(unsafe { copy.slots[0].assume_init() }, 17);
    kani::cover!(true);
    unsafe {
        copy.slots[1].assume_init();
    }
}
