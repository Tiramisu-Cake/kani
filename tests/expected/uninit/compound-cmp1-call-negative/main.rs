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
    if first { a } else { b }
}
#[inline(never)]
fn pair_reads_nonreturned_empty_slot(a: C, b: C, first: bool) -> C {
    if first {
        kani::cover!(true);
        unsafe {
            b.slots[1].assume_init_read();
        }
        a
    } else {
        kani::cover!(true);
        unsafe {
            a.slots[0].assume_init_read();
        }
        b
    }
}

#[kani::proof]
fn empty_slot_read_in_caller_after_return() {
    let value = C { marker: 11, slots: [MaybeUninit::new(7), MaybeUninit::uninit()] };
    let returned = nested(value);
    assert_eq!(returned.marker, 11);
    assert_eq!(unsafe { returned.slots[0].assume_init() }, 7);
    kani::cover!(true);
    unsafe {
        returned.slots[1].assume_init();
    }
}

#[kani::proof]
fn first_argument_empty_at_distinct_slot_after_return() {
    let a = C { marker: 13, slots: [MaybeUninit::uninit(), MaybeUninit::new(17)] };
    let b = C { marker: 19, slots: [MaybeUninit::new(23), MaybeUninit::new(29)] };
    let returned = pair(a, b, true);
    assert_eq!(unsafe { returned.slots[1].assume_init() }, 17);
    kani::cover!(true);
    unsafe {
        returned.slots[0].assume_init();
    }
}

#[kani::proof]
fn second_argument_empty_at_distinct_slot_after_return() {
    let a = C { marker: 31, slots: [MaybeUninit::new(37), MaybeUninit::new(41)] };
    let b = C { marker: 43, slots: [MaybeUninit::new(47), MaybeUninit::uninit()] };
    let returned = pair(a, b, false);
    assert_eq!(returned.marker, 43);
    assert_eq!(unsafe { returned.slots[0].assume_init() }, 47);
    kani::cover!(true);
    unsafe {
        returned.slots[1].assume_init();
    }
}

#[kani::proof]
fn initialized_return_does_not_bless_later_empty_return() {
    let initialized = id(C { marker: 53, slots: [MaybeUninit::new(59), MaybeUninit::new(61)] });
    assert_eq!(unsafe { initialized.slots[1].assume_init() }, 61);
    let partial = id(C { marker: 67, slots: [MaybeUninit::new(71), MaybeUninit::uninit()] });
    assert_eq!(unsafe { partial.slots[0].assume_init() }, 71);
    kani::cover!(true);
    unsafe {
        partial.slots[1].assume_init();
    }
}

#[kani::proof]
fn callee_read_of_nonreturned_second_argument_empty_slot_fails() {
    let a = C { marker: 73, slots: [MaybeUninit::new(79), MaybeUninit::uninit()] };
    let b = C { marker: 83, slots: [MaybeUninit::new(89), MaybeUninit::uninit()] };
    let returned = pair_reads_nonreturned_empty_slot(a, b, true);
    assert_eq!(returned.marker, 73);
}

#[kani::proof]
fn callee_read_of_nonreturned_first_argument_empty_slot_fails() {
    let a = C { marker: 97, slots: [MaybeUninit::uninit(), MaybeUninit::new(101)] };
    let b = C { marker: 103, slots: [MaybeUninit::new(107), MaybeUninit::uninit()] };
    let returned = pair_reads_nonreturned_empty_slot(a, b, false);
    assert_eq!(returned.marker, 103);
}

#[kani::proof]
fn caller_reads_original_nonreturned_second_argument_copy() {
    let a = C { marker: 109, slots: [MaybeUninit::new(113), MaybeUninit::new(127)] };
    let b = C { marker: 131, slots: [MaybeUninit::new(137), MaybeUninit::uninit()] };
    let returned = pair(a, b, true);
    assert_eq!(returned.marker, 109);
    assert_eq!(unsafe { returned.slots[0].assume_init() }, 113);
    kani::cover!(true);
    unsafe {
        b.slots[1].assume_init();
    }
}

#[kani::proof]
fn caller_reads_original_nonreturned_first_argument_copy() {
    let a = C { marker: 139, slots: [MaybeUninit::uninit(), MaybeUninit::new(149)] };
    let b = C { marker: 151, slots: [MaybeUninit::new(157), MaybeUninit::new(163)] };
    let returned = pair(a, b, false);
    assert_eq!(returned.marker, 151);
    assert_eq!(unsafe { returned.slots[1].assume_init() }, 163);
    kani::cover!(true);
    unsafe {
        a.slots[0].assume_init();
    }
}
