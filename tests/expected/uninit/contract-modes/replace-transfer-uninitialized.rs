// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z stubbing -Z unstable-options --output-format=regular --harness-timeout 120 --harness replace_transfer_uninitialized --exact --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn relay(value: MaybeUninit<u8>) -> MaybeUninit<u8> {
    value
}

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

#[inline(never)]
fn through_helper(value: MaybeUninit<u8>, initialized: bool) -> MaybeUninit<u8> {
    passthrough(relay(value), initialized)
}

#[kani::proof]
#[kani::stub_verified(passthrough)]
#[kani::unwind(8)]
fn replace_transfer_uninitialized() {
    let initialized: bool = kani::any();
    // Select only the uninitialized-return alternative of the full harness.
    kani::assume(!initialized);
    let value = input(initialized);
    let result = through_helper(value, initialized);
    assert!(!initialized || payload_is_42(&result));
    kani::cover!(true, "uninitialized storage returned");
}

// A verified stub needs its contract proof in the same crate. The flags select
// only the caller; the SimpleCheck oracle is exercised in its own fixture.
#[kani::proof_for_contract(passthrough)]
#[kani::unwind(8)]
fn replace_simple_check() {
    let initialized: bool = kani::any();
    let value = input(initialized);
    let result = through_helper(value, initialized);
    if initialized {
        assert!(payload_is_42(&result));
    }
}
