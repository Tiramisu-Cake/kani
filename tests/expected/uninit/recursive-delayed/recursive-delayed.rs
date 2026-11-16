// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// edition: 2021
// kani-flags: -Z ghost-state -Z uninit-checks

//! Checks points-to analysis when a delayed-UB harness reaches a recursive function.

#[inline(never)]
fn recurse(value: *mut u8, depth: u8) {
    if depth != 0 {
        unsafe {
            *value = depth;
        }
        recurse(value, depth - 1);
    }
}

#[kani::proof]
fn recursive_call_reached_from_delayed_ub() {
    unsafe {
        let mut value: u128 = 0;
        recurse((&mut value as *mut u128).cast(), 0);
        let tuple = (&mut value as *mut u128).cast::<(u8, u32, u64)>();
        *tuple = (1, 2, 3);
        let _read = value;
    }
}
