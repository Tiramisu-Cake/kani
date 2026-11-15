// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

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
