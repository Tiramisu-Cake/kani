// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn repeated_relay(value: MaybeUninit<u8>) -> MaybeUninit<u8> {
    value
}

#[kani::ensures(|result: &MaybeUninit<u8>| unsafe { result.assume_init_read() == 23 })]
fn ordinary_contract(value: MaybeUninit<u8>) -> MaybeUninit<u8> {
    repeated_relay(value)
}

#[kani::proof]
fn ordinary_ensures_legal() {
    let result = ordinary_contract(MaybeUninit::new(23));
    assert_eq!(unsafe { result.assume_init_read() }, 23);
}
