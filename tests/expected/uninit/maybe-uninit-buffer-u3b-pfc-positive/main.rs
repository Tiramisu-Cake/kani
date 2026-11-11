// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks -Z function-contracts --output-format=terse --harness contracted_roundtrip_harness --exact

use std::mem::MaybeUninit;

#[inline(never)]
fn choose(a: MaybeUninit<u16>, b: MaybeUninit<u16>, first: bool) -> MaybeUninit<u16> {
    if first { a } else { b }
}

#[inline(never)]
fn relay(a: MaybeUninit<u16>, b: MaybeUninit<u16>, first: bool) -> MaybeUninit<u16> {
    choose(a, b, first)
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
