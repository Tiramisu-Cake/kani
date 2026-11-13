// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[inline(never)]
fn read(source: &mut [MaybeUninit<u8>]) -> u8 {
    unsafe { source[1].assume_init() }
}

#[kani::proof]
fn dst_by_reference_legal() {
    let mut source = [MaybeUninit::new(0u8), MaybeUninit::new(0u8)];
    assert_eq!(read(&mut source), 0);
}
