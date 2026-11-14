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

#[kani::modifies(out)]
fn frame_target(out: &mut u16, outside: &mut u16) {
    let value = relay(MaybeUninit::new(23), MaybeUninit::new(29));
    *outside = unsafe { value.assume_init() };
    *out = 1;
}

#[kani::proof_for_contract(frame_target)]
fn frame_negative() {
    let mut out = 0;
    let mut outside = 0;
    frame_target(&mut out, &mut outside);
}
