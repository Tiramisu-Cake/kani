// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn transfer(value: MaybeUninit<u8>, depth: u8) -> MaybeUninit<u8> {
    if depth == 0 { value } else { transfer(value, depth - 1) }
}

#[kani::proof]
#[kani::unwind(4)]
fn self_cycle() {
    let value = transfer(MaybeUninit::new(42), 1);
    assert_eq!(unsafe { value.assume_init() }, 42);
}

#[kani::proof]
fn independent_nonrecursive() {
    let value = MaybeUninit::new(29_u8);
    assert_eq!(unsafe { value.assume_init() }, 29);
    kani::cover!(true, "independent root reached useful assertion");
}
