// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks -Z function-contracts --output-format=regular

use std::mem::MaybeUninit;

#[inline(never)]
fn choose(a: MaybeUninit<u16>, b: MaybeUninit<u16>, first: bool) -> MaybeUninit<u16> {
    if first { a } else { b }
}

#[inline(never)]
fn relay(a: MaybeUninit<u16>, b: MaybeUninit<u16>, first: bool) -> MaybeUninit<u16> {
    choose(a, b, first)
}

#[kani::proof]
fn plain_roundtrip_and_stale_control() {
    // Consume an uninitialized value without reading it, then make a fresh initialized call.
    let _discarded = relay(MaybeUninit::uninit(), MaybeUninit::new(7), kani::any());
    let first = kani::any();
    let value = relay(MaybeUninit::new(11), MaybeUninit::new(13), first);
    assert_eq!(unsafe { value.assume_init() }, if first { 11 } else { 13 });
}

#[kani::modifies(out)]
fn contracted_roundtrip(out: &mut u16) {
    let _discarded = relay(MaybeUninit::uninit(), MaybeUninit::new(7), kani::any());
    let value = relay(MaybeUninit::new(11), MaybeUninit::new(13), kani::any());
    *out = unsafe { value.assume_init() };
}

#[kani::proof_for_contract(contracted_roundtrip)]
fn contracted_roundtrip_harness() {
    let mut out = 0;
    contracted_roundtrip(&mut out);
}

#[inline(never)]
fn choose_clause(a: MaybeUninit<u16>, b: MaybeUninit<u16>) -> MaybeUninit<u16> {
    let _first_argument = a;
    b
}

#[inline(never)]
fn relay_clause(a: MaybeUninit<u16>, b: MaybeUninit<u16>) -> MaybeUninit<u16> {
    choose_clause(a, b)
}

fn clause_helper() -> bool {
    let input = MaybeUninit::new(17u16);
    unsafe { relay_clause(input, input).assume_init() == 17 }
}

#[kani::requires(clause_helper())]
fn clause_target() {}

#[kani::proof]
fn clause_plain_positive() {
    clause_target();
}

#[kani::proof_for_contract(clause_target)]
fn clause_pfc_positive() {
    clause_target();
}
