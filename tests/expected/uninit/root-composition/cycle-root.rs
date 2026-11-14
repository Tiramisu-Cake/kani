// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn repeated_relay(value: MaybeUninit<u8>) -> MaybeUninit<u8> {
    value
}

#[inline(never)]
fn payload_is_53(value: &MaybeUninit<u8>) -> bool {
    unsafe { value.assume_init_read() == 53 }
}

#[kani::requires(depth <= 1)]
#[kani::requires(!initialized || payload_is_53(&value))]
#[kani::ensures(|result: &MaybeUninit<u8>| !initialized || payload_is_53(result))]
#[kani::recursion]
fn cycle_relay(value: MaybeUninit<u8>, initialized: bool, depth: u8) -> MaybeUninit<u8> {
    if depth == 0 {
        repeated_relay(value)
    } else {
        cycle_relay(repeated_relay(value), initialized, depth - 1)
    }
}

#[kani::proof_for_contract(cycle_relay)]
fn cycle_root() {
    cycle_relay(MaybeUninit::new(53), true, 1);
}
