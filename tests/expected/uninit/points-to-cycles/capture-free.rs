// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

// No upvars in the contract predicate or body closure (no function arguments).
// Partial correctness does not require termination of the nondeterministic branch.
#[inline(never)]
#[kani::ensures(|_result: &MaybeUninit<u8>| true)]
#[kani::recursion]
fn recursive_control() -> MaybeUninit<u8> {
    if kani::any() { recursive_control() } else { MaybeUninit::new(42) }
}

#[kani::proof_for_contract(recursive_control)]
#[kani::unwind(4)]
fn capture_free_recursive_check() {
    let _value = recursive_control();
    kani::cover!(true, "legal recursive mode returned storage");
}
