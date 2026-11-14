// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::mem::{self, MaybeUninit};

#[repr(C)]
#[derive(Clone, Copy)]
struct Padded {
    tag: u8,
    word: u32,
}

#[inline(never)]
fn select<T>(condition: bool, a: T, b: T) -> T {
    core::intrinsics::select_unpredictable(condition, a, b)
}

#[kani::proof]
fn selected_true_maybe_uninit_fields_are_legal() {
    assert_eq!(mem::size_of::<Padded>(), 8);
    let a = MaybeUninit::new(Padded { tag: 7, word: 0x1122_3344 });
    let b = MaybeUninit::new(Padded { tag: 9, word: 0x5566_7788 });
    let selected = select(true, a, b);
    let value = unsafe { &*selected.as_ptr() };
    kani::assert(
        value.tag == 7 && value.word == 0x1122_3344,
        "true-arm MaybeUninit fields remain initialized"
    );
}

#[kani::proof]
fn selected_false_maybe_uninit_fields_are_legal() {
    assert_eq!(mem::size_of::<Padded>(), 8);
    let a = MaybeUninit::new(Padded { tag: 7, word: 0x1122_3344 });
    let b = MaybeUninit::new(Padded { tag: 9, word: 0x5566_7788 });
    let selected = select(false, a, b);
    let value = unsafe { &*selected.as_ptr() };
    kani::assert(
        value.tag == 9 && value.word == 0x5566_7788,
        "false-arm MaybeUninit fields remain initialized"
    );
}

#[kani::proof]
fn selected_true_padding_stays_uninitialized() {
    assert_eq!(mem::size_of::<Padded>(), 8);
    let a = MaybeUninit::new(Padded { tag: 13, word: 0x1020_3040 });
    let b = MaybeUninit::new(Padded { tag: 17, word: 0x5060_7080 });
    let selected = select(true, a, b);
    let value = unsafe { &*selected.as_ptr() };
    kani::assert(
        value.tag == 13 && value.word == 0x1020_3040,
        "true-arm typed fields are readable before padding check"
    );
    let _padding = unsafe { selected.as_ptr().cast::<u8>().add(1).read_volatile() };
}

#[kani::proof]
fn selected_false_padding_stays_uninitialized() {
    assert_eq!(mem::size_of::<Padded>(), 8);
    let a = MaybeUninit::new(Padded { tag: 19, word: 0x90A0_B0C0 });
    let b = MaybeUninit::new(Padded { tag: 23, word: 0xD0E0_F001 });
    let selected = select(false, a, b);
    let value = unsafe { &*selected.as_ptr() };
    kani::assert(
        value.tag == 23 && value.word == 0xD0E0_F001,
        "false-arm typed fields are readable before padding check"
    );
    let _padding = unsafe { selected.as_ptr().cast::<u8>().add(1).read_volatile() };
}
