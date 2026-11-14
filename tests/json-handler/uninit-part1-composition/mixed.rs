// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
//! Small mixed-root inputs for export/inventory isolation checks.
use std::mem::MaybeUninit;

static IMMUTABLE_LEGAL: MaybeUninit<u8> = MaybeUninit::new(17);
static IMMUTABLE_HOLE: MaybeUninit<u8> = MaybeUninit::uninit();

#[inline(never)]
fn repeated_relay(value: MaybeUninit<u8>) -> MaybeUninit<u8> {
    value
}

#[kani::proof]
fn immutable_legal() {
    // Immutable named static, read only after its initialized construction.
    let value = unsafe { IMMUTABLE_LEGAL.assume_init_read() };
    assert_eq!(value, 17);
}

#[kani::proof]
fn immutable_hole_negative() {
    // Deliberate invalid read, isolated to this root.
    let _ = unsafe { IMMUTABLE_HOLE.assume_init_read() };
}

#[kani::ensures(|result: &MaybeUninit<u8>| unsafe { result.assume_init_read() == 23 })]
fn ordinary_contract(value: MaybeUninit<u8>) -> MaybeUninit<u8> {
    repeated_relay(value)
}

#[kani::proof]
fn ordinary_ensures_legal() {
    let result = ordinary_contract(MaybeUninit::new(23));
    assert_eq!(unsafe { result.assume_init_read() }, 23);
}

#[kani::requires(value == 31)]
#[kani::ensures(|result: &MaybeUninit<u8>| unsafe { result.assume_init_read() == 31 })]
fn pfc_contract(value: u8) -> MaybeUninit<u8> {
    let _ = value;
    MaybeUninit::new(31)
}

#[kani::proof_for_contract(pfc_contract)]
fn pfc_legal() {
    pfc_contract(31);
}

#[kani::requires(value == 41)]
#[kani::ensures(|result: &MaybeUninit<u8>| unsafe { result.assume_init_read() == 41 })]
fn pfc_negative_contract(value: u8) -> MaybeUninit<u8> {
    let _ = value;
    MaybeUninit::uninit()
}

#[kani::proof_for_contract(pfc_negative_contract)]
fn pfc_negative() {
    pfc_negative_contract(41);
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

#[kani::proof]
fn unrelated_legal_after_cycle() {
    let left = repeated_relay(MaybeUninit::new(59));
    let right = repeated_relay(MaybeUninit::new(61));
    assert_eq!(unsafe { left.assume_init_read() }, 59);
    assert_eq!(unsafe { right.assume_init_read() }, 61);
}
