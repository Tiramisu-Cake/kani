// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn repeated_relay(value: MaybeUninit<u8>) -> MaybeUninit<u8> {
    value
}

#[kani::proof]
fn unrelated_legal_after_cycle() {
    let left = repeated_relay(MaybeUninit::new(59));
    let right = repeated_relay(MaybeUninit::new(61));
    assert_eq!(unsafe { left.assume_init_read() }, 59);
    assert_eq!(unsafe { right.assume_init_read() }, 61);
}
