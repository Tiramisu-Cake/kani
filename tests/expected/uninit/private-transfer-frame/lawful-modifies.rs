// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// This test exceeds the CI memory limit with 16 object bits because of the
// contract write-set tables. Reducing the number of object bits to 12.
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

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
#[kani::ensures(|result: &u16| *result == 29 && *out == 29)]
fn frame_target(out: &mut u16, outside: &mut u16) -> u16 {
    let value = relay(MaybeUninit::new(*outside), MaybeUninit::new(29));
    let scalar = unsafe { value.assume_init() };
    *out = scalar;
    scalar
}

#[kani::proof_for_contract(frame_target)]
fn lawful_modifies_preserves_outside() {
    let mut out = 0u16;
    let mut outside = 41u16;
    assert_eq!(frame_target(&mut out, &mut outside), 29);
    assert_eq!(out, 29);
    assert_eq!(outside, 41);
}
