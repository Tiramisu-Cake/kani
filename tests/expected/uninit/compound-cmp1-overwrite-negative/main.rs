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
fn overwrite_full_destination_with_empty_source_copy() {
    let source = C { marker: 3, slots: [MaybeUninit::new(5), MaybeUninit::uninit()] };
    let mut destination = C { marker: 7, slots: [MaybeUninit::new(11), MaybeUninit::new(13)] };
    destination = source;
    assert_eq!(destination.marker, 3);
    assert_eq!(unsafe { destination.slots[0].assume_init() }, 5);
    kani::cover!(true);
    unsafe {
        destination.slots[1].assume_init();
    }
}

struct M {
    marker: usize,
    slots: [MaybeUninit<usize>; 2],
}

#[kani::proof]
fn overwrite_full_destination_with_empty_source_move() {
    let source = M { marker: 17, slots: [MaybeUninit::new(19), MaybeUninit::uninit()] };
    let mut destination = M { marker: 23, slots: [MaybeUninit::new(29), MaybeUninit::new(31)] };
    destination = source;
    assert_eq!(destination.marker, 17);
    assert_eq!(unsafe { destination.slots[0].assume_init() }, 19);
    kani::cover!(true);
    unsafe {
        destination.slots[1].assume_init();
    }
}

#[kani::proof]
fn shifted_empty_source_slot_does_not_reuse_destination_witness() {
    let source = C { marker: 37, slots: [MaybeUninit::uninit(), MaybeUninit::new(41)] };
    let mut destination = C { marker: 43, slots: [MaybeUninit::new(47), MaybeUninit::new(53)] };
    destination = source;
    assert_eq!(destination.marker, 37);
    assert_eq!(unsafe { destination.slots[1].assume_init() }, 41);
    kani::cover!(true);
    unsafe {
        destination.slots[0].assume_init();
    }
}
