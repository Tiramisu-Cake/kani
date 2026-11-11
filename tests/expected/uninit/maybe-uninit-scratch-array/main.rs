// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[kani::proof]
fn scratch_array_layout() {
    let value: u8 = kani::any();
    let mut scratch = [MaybeUninit::<u8>::uninit(); 20];
    scratch[0].write(value);
    // SAFETY: the same slot was initialized immediately above.
    let got = unsafe { scratch[0].assume_init() };
    assert_eq!(got, value);
}
