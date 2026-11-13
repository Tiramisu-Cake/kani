// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn relay(value: MaybeUninit<u8>) -> MaybeUninit<u8> {
    value
}

#[inline(never)]
fn array(value: [MaybeUninit<u8>; 2]) -> [MaybeUninit<u8>; 2] {
    value
}

#[inline(never)]
fn slice(value: &[MaybeUninit<u8>]) -> u8 {
    unsafe { value[1].assume_init() }
}

#[kani::proof]
fn flat_carriers_legal() {
    assert_eq!(unsafe { relay(MaybeUninit::new(42)).assume_init() }, 42);
    let value = array([MaybeUninit::new(23); 2]);
    assert_eq!(unsafe { value[0].assume_init() }, 23);
    assert_eq!(slice(&value), 23);
}
