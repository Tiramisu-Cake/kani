// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Candidate only, NOT_RUN. Intended flags: -Z function-contracts -Z uninit-checks.
use std::mem::MaybeUninit;

#[kani::modifies(std::ptr::slice_from_raw_parts_mut(out.as_mut_ptr().cast::<u8>(), 2))]
fn initialize(out: &mut [MaybeUninit<u8>; 2]) {
    out[0].write(1);
    out[1].write(2);
}

#[kani::proof_for_contract(initialize)]
fn check_body() {
    let mut out = [MaybeUninit::uninit(); 2];
    initialize(&mut out);
}

#[kani::proof]
#[kani::stub_verified(initialize)]
fn check_slice_havoc() {
    let mut out = [MaybeUninit::uninit(); 2];
    initialize(&mut out);
}
