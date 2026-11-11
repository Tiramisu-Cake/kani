// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;
use std::ptr;

#[kani::proof]
fn volatile_read_empty() {
    let slot = MaybeUninit::<u8>::uninit();
    // Intentionally violate initialization and retain an observable use of the read.
    let value = unsafe { ptr::read_volatile(slot.as_ptr()) };
    assert_eq!(value, 7);
}
