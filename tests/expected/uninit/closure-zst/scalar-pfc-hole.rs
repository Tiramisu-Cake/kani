// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn select(a: MaybeUninit<u8>, b: MaybeUninit<u8>, first: bool) -> MaybeUninit<u8> {
    if first { a } else { b }
}

// The returned MU value is valid. Its first payload read is in the postcondition.
#[kani::ensures(|result: &MaybeUninit<u8>| unsafe { result.assume_init_read() == 17 })]
fn postcondition_target() -> MaybeUninit<u8> {
    select(MaybeUninit::new(17), MaybeUninit::uninit(), false)
}

#[kani::proof_for_contract(postcondition_target)]
fn postcondition_reads_returned_hole() {
    let _unread = postcondition_target();
}
