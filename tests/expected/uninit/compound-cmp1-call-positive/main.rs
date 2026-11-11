// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
struct C {
    marker: usize,
    slots: [MaybeUninit<usize>; 2],
}

#[inline(never)]
fn id(value: C) -> C {
    value
}
#[inline(never)]
fn nested(value: C) -> C {
    id(id(value))
}
#[inline(never)]
fn pair(a: C, b: C, first: bool) -> C {
    assert_eq!(a.marker, a.marker);
    assert_eq!(b.marker, b.marker);
    unsafe {
        a.slots[0].assume_init_ref();
        b.slots[0].assume_init_ref();
    }
    if first { a } else { b }
}

#[kani::proof]
fn id_and_nested_id_preserve_partial_storage() {
    let value = C { marker: 11, slots: [MaybeUninit::new(7), MaybeUninit::uninit()] };
    let returned = nested(id(value));
    assert_eq!(returned.marker, 11);
    assert_eq!(unsafe { returned.slots[0].assume_init() }, 7);

    kani::cover!(true);
}

#[kani::proof]
fn pair_first_argument_and_read_nonreturned_second_in_callee() {
    let a = C { marker: 13, slots: [MaybeUninit::new(17), MaybeUninit::uninit()] };
    let b = C { marker: 19, slots: [MaybeUninit::new(23), MaybeUninit::new(29)] };
    let returned = pair(a, b, true);
    assert_eq!(returned.marker, 13);
    assert_eq!(unsafe { returned.slots[0].assume_init() }, 17);

    kani::cover!(true);
}

#[kani::proof]
fn pair_second_argument_and_read_nonreturned_first_in_callee() {
    let a = C { marker: 31, slots: [MaybeUninit::new(37), MaybeUninit::new(41)] };
    let b = C { marker: 43, slots: [MaybeUninit::new(47), MaybeUninit::uninit()] };
    let returned = pair(a, b, false);
    assert_eq!(returned.marker, 43);
    assert_eq!(unsafe { returned.slots[0].assume_init() }, 47);

    kani::cover!(true);
}

#[kani::proof]
fn repeated_calls_clear_stale_return_buffer() {
    let first = id(C { marker: 53, slots: [MaybeUninit::new(59), MaybeUninit::new(61)] });
    assert_eq!(unsafe { first.slots[1].assume_init() }, 61);
    let second = id(C { marker: 67, slots: [MaybeUninit::new(71), MaybeUninit::uninit()] });
    assert_eq!(second.marker, 67);
    assert_eq!(unsafe { second.slots[0].assume_init() }, 71);

    kani::cover!(true);
}
