// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Coordinator-only CC4 diagnostic fixture; no invented Unsupported golden.
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --cbmc-args --object-bits 12
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

#[kani::requires(depth <= 1)]
#[kani::requires(!initialized || payload_is_42(&value))]
#[kani::ensures(|result: &MaybeUninit<u8>| !initialized || payload_is_42(result))]
#[kani::recursion]
fn recursive_transfer(value: MaybeUninit<u8>, initialized: bool, depth: u8) -> MaybeUninit<u8> {
    if depth == 0 {
        kani::cover!(true, "base body reached");
        relay(value)
    } else {
        kani::cover!(true, "recursive body edge reached");
        recursive_transfer(relay(value), initialized, depth - 1)
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn recursive_ordinary() {
    let initialized: bool = kani::any();
    let depth: u8 = if kani::any() { 0 } else { 1 };
    let result = recursive_transfer(input(initialized), initialized, depth);
    if initialized {
        assert!(payload_is_42(&result));
        kani::cover!(true, "initialized return consumed");
    } else {
        kani::cover!(true, "uninitialized storage returned");
    }
}
