// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

#[inline(never)]
fn select<T>(condition: bool, a: T, b: T) -> T {
    core::intrinsics::select_unpredictable(condition, a, b)
}

#[kani::proof]
fn selected_scalar_values() {
    let condition: bool = kani::any();
    let a: u64 = kani::any();
    let b: u64 = kani::any();
    assert_eq!(select(condition, a, b), if condition { a } else { b });
    assert_eq!(select(true, 11u64, 13), 11);
    assert_eq!(select(false, 11u64, 13), 13);
    assert_eq!(select(condition, true, false), condition);
    assert_eq!(select(condition, 'a', 'z'), if condition { 'a' } else { 'z' });
    // Both paths resolve to the same core definition, irrespective of its printed name.
    let core_value = core::intrinsics::select_unpredictable(condition, 7u8, 9u8);
    let std_value = std::intrinsics::select_unpredictable(condition, 7u8, 9u8);
    kani::assert(
        core_value == (if condition { 7 } else { 9 }) && std_value == core_value,
        "core and std select paths preserve the chosen value",
    );
    kani::cover!(condition);
    kani::cover!(!condition);
}
