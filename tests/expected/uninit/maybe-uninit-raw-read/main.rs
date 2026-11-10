// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;
use std::ptr;

#[kani::proof]
fn raw_read_empty() {
    let slot = MaybeUninit::<u8>::uninit();
    let raw = ptr::addr_of!(slot);
    let moved = unsafe { raw.read() };
    let value = unsafe { moved.assume_init_read() };
    assert_eq!(value, 7);
}
