// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12
use std::mem::MaybeUninit;

#[kani::modifies(out)]
fn write(out: &mut MaybeUninit<u16>) {
    *out = MaybeUninit::new(7);
}

#[kani::proof_for_contract(write)]
fn generated_modifies_no_shadow() {
    let mut out = MaybeUninit::uninit();
    write(&mut out);
    assert_eq!(unsafe { out.assume_init() }, 7);
}
