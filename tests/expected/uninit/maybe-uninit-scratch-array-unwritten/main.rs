// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[kani::proof]
fn scratch_array_unwritten_neighbor() {
    let value: u8 = kani::any();
    let mut scratch = [MaybeUninit::<u8>::uninit(); 20];
    scratch[0].write(value);
    assert_eq!(unsafe { scratch[0].assume_init() }, value);
    // Intentionally read the neighboring slot, which has never been written.
    let got = unsafe { scratch[1].assume_init() };
    assert_eq!(got, value);
}
