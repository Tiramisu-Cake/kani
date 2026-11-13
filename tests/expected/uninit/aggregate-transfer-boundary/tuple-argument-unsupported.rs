// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn consume(value: (MaybeUninit<u8>, u8)) -> u8 {
    value.1
}

#[kani::proof]
fn tuple_argument_unsupported() {
    assert_eq!(consume((MaybeUninit::new(42), 23)), 23);
}
