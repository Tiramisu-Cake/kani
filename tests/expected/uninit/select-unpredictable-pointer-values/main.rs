// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::{mem::MaybeUninit, ptr};

#[inline(never)]
fn select<T>(condition: bool, a: T, b: T) -> T {
    core::intrinsics::select_unpredictable(condition, a, b)
}

#[kani::proof]
fn selected_initialized_pointer_values() {
    let a = MaybeUninit::new(11u8);
    let b = MaybeUninit::new(13u8);
    let condition: bool = kani::any();
    let selected = select(condition, a.as_ptr(), b.as_ptr());
    assert_eq!(unsafe { selected.read() }, if condition { 11 } else { 13 });
    kani::cover!(condition);
    kani::cover!(!condition);
}

#[kani::proof]
fn selected_null_or_dangling_without_dereference() {
    let condition: bool = kani::any();
    let null = ptr::null::<u8>();
    let dangling = ptr::NonNull::<u8>::dangling().as_ptr().cast_const();
    let selected = select(condition, null, dangling);
    assert_eq!(selected, if condition { null } else { dangling });
    kani::cover!(condition);
    kani::cover!(!condition);
}
