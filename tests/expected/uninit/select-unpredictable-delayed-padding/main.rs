// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::{mem, ptr};

#[inline(never)]
fn select<T>(condition: bool, a: T, b: T) -> T {
    core::intrinsics::select_unpredictable(condition, a, b)
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
struct Padded {
    byte: u8,
    word: u32,
}

const _: () = assert!(mem::size_of::<Padded>() == 8);

#[kani::proof]
fn write_through_selected_pointer_leaves_true_source_padding_hole() {
    let mut x = 0u64;
    let mut y = 0u64;
    let condition: bool = kani::any();
    let selected = select(condition, ptr::addr_of_mut!(x), ptr::addr_of_mut!(y));
    kani::assert(
        selected == if condition { ptr::addr_of_mut!(x) } else { ptr::addr_of_mut!(y) },
        "selected alias points to the condition's source"
    );
    unsafe { selected.cast::<Padded>().write(Padded { byte: 1, word: 2 }) };
    kani::cover!(condition);
    let value = x; // intended failure when condition is true
    std::hint::black_box(value);
}

#[kani::proof]
fn write_through_selected_pointer_leaves_false_source_padding_hole() {
    let mut x = 0u64;
    let mut y = 0u64;
    let condition: bool = kani::any();
    let selected = select(condition, ptr::addr_of_mut!(x), ptr::addr_of_mut!(y));
    kani::assert(
        selected == if condition { ptr::addr_of_mut!(x) } else { ptr::addr_of_mut!(y) },
        "selected alias points to the condition's source"
    );
    unsafe { selected.cast::<Padded>().write(Padded { byte: 1, word: 2 }) };
    kani::cover!(!condition);
    let value = y; // intended failure when condition is false
    std::hint::black_box(value);
}
