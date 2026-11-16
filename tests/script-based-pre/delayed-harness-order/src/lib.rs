// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// kani-flags: -Z ghost-state -Z uninit-checks

#[inline(never)]
fn read_value(value: &u128) -> u128 {
    *value
}

#[inline(never)]
fn delayed_path_1(value: &u128) -> u128 {
    read_value(value)
}

#[inline(never)]
fn delayed_path_2(value: &u128) -> u128 {
    delayed_path_1(value)
}

#[inline(never)]
fn delayed_path_3(value: &u128) -> u128 {
    delayed_path_2(value)
}

#[kani::proof]
#[cfg(feature = "delayed-first")]
fn delayed_harness() {
    unsafe {
        let mut value: u128 = 0;
        let tuple = (&mut value as *mut u128).cast::<(u8, u32, u64)>();
        *tuple = (1, 2, 3);
        let _read = delayed_path_3(&value);
    }
}

#[kani::proof]
#[cfg(not(feature = "delayed-first"))]
fn delayed_harness() {
    unsafe {
        let mut value: u128 = 0;
        let tuple = (&mut value as *mut u128).cast::<(u8, u32, u64)>();
        *tuple = (1, 2, 3);
        let _read = read_value(&value);
    }
}

#[kani::proof]
#[cfg(feature = "delayed-first")]
fn initialized_control_harness() {
    let value: u128 = 7;
    assert_eq!(read_value(&value), 7);
}

#[kani::proof]
#[cfg(not(feature = "delayed-first"))]
fn initialized_control_harness() {
    let value: u128 = 7;
    assert_eq!(delayed_path_3(&value), 7);
}
