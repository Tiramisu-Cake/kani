// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Outcomes for unclaimed modes are collected without an invented failure golden.
use std::mem::MaybeUninit;

#[inline(never)]
fn relay(value: MaybeUninit<u8>) -> MaybeUninit<u8> {
    value
}

// Every caller must establish initialized storage before taking this branch.
#[inline(never)]
fn payload_is_42(value: &MaybeUninit<u8>) -> bool {
    unsafe { value.assume_init_read() == 42 }
}

fn input(initialized: bool) -> MaybeUninit<u8> {
    if initialized { MaybeUninit::new(42) } else { MaybeUninit::uninit() }
}

#[kani::requires(!initialized || payload_is_42(&value))]
#[kani::ensures(|result: &MaybeUninit<u8>| !initialized || payload_is_42(result))]
fn passthrough(value: MaybeUninit<u8>, initialized: bool) -> MaybeUninit<u8> {
    relay(value)
}

// A real caller/return path surrounding the selected contract replacement.
#[inline(never)]
fn through_helper(value: MaybeUninit<u8>, initialized: bool) -> MaybeUninit<u8> {
    passthrough(relay(value), initialized)
}

#[kani::proof]
#[kani::stub_verified(passthrough)]
#[kani::unwind(8)]
fn replace_transfer() {
    let initialized: bool = kani::any();
    let value = input(initialized);
    let result = through_helper(value, initialized);
    if initialized {
        assert!(payload_is_42(&result));
        kani::cover!(true, "initialized return consumed");
    } else {
        // Transferring uninitialized storage is legal; do not read its payload.
        kani::cover!(true, "uninitialized storage returned");
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn replace_ordinary() {
    let initialized: bool = kani::any();
    let value = input(initialized);
    let result = through_helper(value, initialized);
    if initialized {
        assert!(payload_is_42(&result));
        kani::cover!(true, "initialized return consumed");
    } else {
        // Transferring uninitialized storage is legal; do not read its payload.
        kani::cover!(true, "uninitialized storage returned");
    }
}

#[kani::proof_for_contract(passthrough)]
#[kani::unwind(8)]
fn replace_simple_check() {
    let initialized: bool = kani::any();
    let value = input(initialized);
    let result = through_helper(value, initialized);
    if initialized {
        assert!(payload_is_42(&result));
        kani::cover!(true, "initialized return consumed");
    } else {
        // Transferring uninitialized storage is legal; do not read its payload.
        kani::cover!(true, "uninitialized storage returned");
    }
}
