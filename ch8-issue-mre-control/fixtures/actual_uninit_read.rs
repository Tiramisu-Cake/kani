// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
use std::mem::MaybeUninit;

#[kani::proof]
fn actual_uninit_read() {
    let out = MaybeUninit::<u8>::uninit();
    let value = unsafe { std::ptr::read_volatile(out.as_ptr()) };
    assert_eq!(value, 0);
}
