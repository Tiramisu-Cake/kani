// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn transfer(value: MaybeUninit<u8>, depth: u8) -> MaybeUninit<u8> {
    if depth == 0 { value } else { other(value, depth - 1) }
}

#[inline(never)]
fn other(value: MaybeUninit<u8>, depth: u8) -> MaybeUninit<u8> {
    transfer(value, depth)
}

#[kani::proof]
#[kani::unwind(4)]
fn mutual_cycle() {
    let value = transfer(MaybeUninit::new(42), 1);
    assert_eq!(unsafe { value.assume_init() }, 42);
}
