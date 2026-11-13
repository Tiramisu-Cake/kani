// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn consume(value: [(MaybeUninit<u8>, u8); 2]) -> u8 {
    value[1].1
}

#[kani::proof]
fn array_tuple_unsupported() {
    assert_eq!(consume([(MaybeUninit::new(42), 23); 2]), 23);
}
