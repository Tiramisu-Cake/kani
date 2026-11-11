// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular --default-unwind 8

use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
struct C {
    marker: usize,
    slots: [MaybeUninit<usize>; 1],
}

#[kani::proof]
fn empty_standard_usize_into_iter() {
    let values: [usize; 0] = [];
    let mut iter = IntoIterator::into_iter(values);
    assert_eq!(iter.next(), None);
    assert_eq!(iter.len(), 0);

    kani::cover!(true);
}

#[kani::proof]
fn zst_standard_into_iter_payload_and_len() {
    let mut iter = IntoIterator::into_iter([(), ()]);
    assert_eq!(iter.len(), 2);
    assert_eq!(iter.next(), Some(()));
    assert_eq!(iter.len(), 1);
    assert_eq!(iter.next(), Some(()));
    assert_eq!(iter.next(), None);

    kani::cover!(true);
}

#[kani::proof]
fn zero_extent_does_not_change_adjacent_storage() {
    let value = C { marker: 31, slots: [MaybeUninit::new(37)] };
    let zero: [MaybeUninit<()>; 0] = [];
    let copy = value;
    assert_eq!(zero.len(), 0);
    assert_eq!(copy.marker, 31);
    assert_eq!(unsafe { copy.slots[0].assume_init() }, 37);

    kani::cover!(true);
}
