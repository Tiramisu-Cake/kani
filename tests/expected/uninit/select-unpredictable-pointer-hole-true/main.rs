// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::mem::MaybeUninit;

#[inline(never)]
fn select<T>(condition: bool, a: T, b: T) -> T {
    core::intrinsics::select_unpredictable(condition, a, b)
}

#[kani::proof]
fn selected_hole_in_true_arm_fails() {
    let hole = MaybeUninit::<u8>::uninit();
    let initialized = MaybeUninit::new(13u8);
    let condition: bool = kani::any();
    let selected = select(condition, hole.as_ptr(), initialized.as_ptr());
    kani::cover!(condition);
    kani::assert(
        selected == if condition { hole.as_ptr() } else { initialized.as_ptr() },
        "selected raw pointer names the condition's arm"
    );
    let _value = unsafe { selected.read_volatile() }; // True selects the hole.
}
