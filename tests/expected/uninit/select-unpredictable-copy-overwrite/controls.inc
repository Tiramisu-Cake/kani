// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::mem::MaybeUninit;

#[inline(never)]
fn select<T: Copy>(condition: bool, a: T, b: T) -> T {
    core::intrinsics::select_unpredictable(condition, a, b)
}

#[kani::proof]
fn copy_sources_remain_initialized() {
    let a = MaybeUninit::new(31u8);
    let b = MaybeUninit::new(37u8);
    let selected = select(true, a, b);
    kani::assert(
        unsafe { selected.assume_init() } == 31
            && unsafe { a.assume_init() } == 31
            && unsafe { b.assume_init() } == 37,
        "Copy operands retain selected and source values"
    );
}

#[kani::proof]
fn overwriting_selected_hole_reinitializes_result() {
    let hole = MaybeUninit::<u8>::uninit();
    let initialized = MaybeUninit::new(41u8);
    let mut selected = select(true, hole, initialized);
    selected.write(43);
    kani::assert(unsafe { selected.assume_init() } == 43, "overwrite initializes selected result");
}

#[kani::proof]
fn overwriting_initialized_destination_with_selected_hole_does_not_retain_true() {
    let hole = MaybeUninit::<u8>::uninit();
    let initialized = MaybeUninit::new(47u8);
    let mut destination = MaybeUninit::new(43u8);
    kani::assert(unsafe { destination.assume_init() } == 43, "destination starts initialized");
    destination = select(true, hole, initialized);
    kani::cover!(true);
    std::hint::black_box(unsafe { destination.assume_init() });
}
