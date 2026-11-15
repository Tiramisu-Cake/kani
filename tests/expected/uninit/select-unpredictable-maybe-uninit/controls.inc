// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::mem::MaybeUninit;

#[inline(never)]
fn select<T>(condition: bool, a: T, b: T) -> T {
    core::intrinsics::select_unpredictable(condition, a, b)
}

#[inline(never)]
fn select_copy<T: Copy>(condition: bool, a: T, b: T) -> T {
    core::intrinsics::select_unpredictable(condition, a, b)
}

#[kani::proof]
fn legal_selected_true_arm_with_unselected_hole() {
    let initialized = MaybeUninit::new(19u8);
    let hole = MaybeUninit::<u8>::uninit();
    let selected = select(true, initialized, hole);
    kani::assert(
        unsafe { selected.assume_init() } == 19,
        "selected true MaybeUninit arm is initialized",
    );
}

#[kani::proof]
fn legal_selected_false_arm_with_unselected_hole() {
    let hole = MaybeUninit::<u8>::uninit();
    let initialized = MaybeUninit::new(23u8);
    let selected = select(false, hole, initialized);
    kani::assert(
        unsafe { selected.assume_init() } == 23,
        "selected false MaybeUninit arm is initialized",
    );
}

#[kani::proof]
fn copied_unselected_false_hole_remains_false() {
    let initialized = MaybeUninit::new(29u8);
    let hole = MaybeUninit::<u8>::uninit();
    let selected = select_copy(true, initialized, hole);
    kani::assert(
        unsafe { selected.assume_init() } == 29,
        "selected true value remains initialized",
    );
    std::hint::black_box(unsafe { hole.assume_init() });
}

#[kani::proof]
fn copied_unselected_true_hole_remains_false() {
    let hole = MaybeUninit::<u8>::uninit();
    let initialized = MaybeUninit::new(31u8);
    let selected = select_copy(false, hole, initialized);
    kani::assert(
        unsafe { selected.assume_init() } == 31,
        "selected false value remains initialized",
    );
    std::hint::black_box(unsafe { hole.assume_init() });
}

#[kani::proof]
fn selected_true_hole_fails() {
    let hole = MaybeUninit::<u8>::uninit();
    let initialized = MaybeUninit::new(23u8);
    let selected = select_copy(true, hole, initialized);
    kani::assert(
        unsafe { initialized.assume_init() } == 23,
        "unselected Copy arm remains initialized",
    );
    std::hint::black_box(unsafe { selected.assume_init() });
}

#[kani::proof]
fn selected_false_hole_fails() {
    let initialized = MaybeUninit::new(19u8);
    let hole = MaybeUninit::<u8>::uninit();
    let selected = select_copy(false, initialized, hole);
    kani::assert(
        unsafe { initialized.assume_init() } == 19,
        "unselected Copy arm remains initialized",
    );
    std::hint::black_box(unsafe { selected.assume_init() });
}
