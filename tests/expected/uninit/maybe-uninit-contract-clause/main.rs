// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks -Z function-contracts --output-format=regular

use std::mem::MaybeUninit;

#[inline(never)]
fn choose(a: MaybeUninit<u16>, b: MaybeUninit<u16>) -> MaybeUninit<u16> {
    let _first_argument = a;
    b
}

#[inline(never)]
fn relay(a: MaybeUninit<u16>, b: MaybeUninit<u16>) -> MaybeUninit<u16> {
    choose(a, b)
}

fn clause_helper() -> bool {
    let input = MaybeUninit::<u16>::uninit();
    unsafe { relay(input, input).assume_init() == 17 }
}

#[kani::requires(clause_helper())]
fn clause_target() {}

#[kani::proof_for_contract(clause_target)]
fn clause_pfc_negative() {
    clause_target();
}
