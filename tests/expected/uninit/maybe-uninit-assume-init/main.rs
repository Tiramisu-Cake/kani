// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[kani::proof]
fn assume_init_empty() {
    let slot = MaybeUninit::<u8>::uninit();
    let value = unsafe { slot.assume_init() };
    assert_eq!(value, 7);
}
