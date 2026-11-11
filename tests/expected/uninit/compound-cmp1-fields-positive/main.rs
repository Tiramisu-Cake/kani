// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{ManuallyDrop, MaybeUninit};

#[derive(Clone, Copy)]
struct C {
    marker: usize,
    slots: [MaybeUninit<usize>; 2],
}
#[derive(Clone, Copy)]
struct Generic<T> {
    marker: T,
    slots: [MaybeUninit<usize>; 2],
}
#[derive(Clone, Copy)]
struct Nested {
    inner: C,
}
#[derive(Clone, Copy)]
struct Reordered {
    slots: [MaybeUninit<usize>; 2],
    marker: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CBefore {
    slots: [MaybeUninit<usize>; 2],
    marker: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct CAfter {
    marker: usize,
    slots: [MaybeUninit<usize>; 2],
}

#[kani::proof]
fn copied_partial_product_and_manually_drop() {
    let value = C { marker: 11, slots: [MaybeUninit::new(7), MaybeUninit::uninit()] };
    let copy = value;
    let wrapped = ManuallyDrop::new(value);
    assert_eq!(copy.marker, 11);
    assert_eq!(unsafe { copy.slots[0].assume_init() }, 7);
    assert_eq!(wrapped.marker, 11);
    assert_eq!(unsafe { wrapped.slots[0].assume_init() }, 7);
    assert_eq!(value.marker, 11);
    assert_eq!(unsafe { value.slots[0].assume_init() }, 7);

    kani::cover!(true);
}

#[kani::proof]
fn nested_product_copy() {
    let value =
        Nested { inner: C { marker: 13, slots: [MaybeUninit::new(17), MaybeUninit::uninit()] } };
    let copy = value;
    assert_eq!(copy.inner.marker, 13);
    assert_eq!(unsafe { copy.inner.slots[0].assume_init() }, 17);

    kani::cover!(true);
}

#[kani::proof]
fn reordered_repr_rust_fields() {
    let value = Reordered { slots: [MaybeUninit::new(19), MaybeUninit::uninit()], marker: 23 };
    let copy = value;
    assert_eq!(copy.marker, 23);
    assert_eq!(unsafe { copy.slots[0].assume_init() }, 19);

    kani::cover!(true);
}

#[kani::proof]
fn repr_c_storage_before_ordinary_field() {
    let value = CBefore { slots: [MaybeUninit::new(29), MaybeUninit::new(31)], marker: 37 };
    let copy = value;
    assert_eq!(copy.marker, 37);
    assert_eq!(unsafe { copy.slots[0].assume_init() }, 29);
    assert_eq!(unsafe { copy.slots[1].assume_init() }, 31);

    kani::cover!(true);
}

#[kani::proof]
fn repr_c_storage_after_ordinary_field() {
    let value = CAfter { marker: 41, slots: [MaybeUninit::new(43), MaybeUninit::new(47)] };
    let copy = value;
    assert_eq!(copy.marker, 41);
    assert_eq!(unsafe { copy.slots[0].assume_init() }, 43);
    assert_eq!(unsafe { copy.slots[1].assume_init() }, 47);

    kani::cover!(true);
}

#[kani::proof]
fn generic_usize_marker_product() {
    let value = Generic { marker: 53usize, slots: [MaybeUninit::new(59), MaybeUninit::uninit()] };
    let copy = value;
    assert_eq!(copy.marker, 53);
    assert_eq!(unsafe { copy.slots[0].assume_init() }, 59);

    kani::cover!(true);
}
