// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks -Z function-contracts --output-format=regular

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

#[kani::proof]
fn nested_two_argument_return_reads_uninit() {
    let value = nested_return(MaybeUninit::new(5), MaybeUninit::uninit());
    let _read = unsafe { value.assume_init() };
}
