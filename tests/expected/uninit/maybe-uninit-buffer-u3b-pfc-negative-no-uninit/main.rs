// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z function-contracts --output-format=terse --harness contracted_uninit_read_harness --exact

use std::mem::MaybeUninit;

#[inline(never)]
fn return_second(a: MaybeUninit<u16>, b: MaybeUninit<u16>) -> MaybeUninit<u16> {
    let _keep_two_argument_path = a;
    b
}

#[inline(never)]
fn nested_return(a: MaybeUninit<u16>, b: MaybeUninit<u16>) -> MaybeUninit<u16> {
    return_second(a, b)
}

#[kani::modifies(out)]
fn contracted_uninit_read(out: &mut u16) {
    let value = nested_return(MaybeUninit::new(5), MaybeUninit::uninit());
    *out = unsafe { value.assume_init() };
}

#[kani::proof_for_contract(contracted_uninit_read)]
fn contracted_uninit_read_harness() {
    let mut out = 0;
    contracted_uninit_read(&mut out);
}
