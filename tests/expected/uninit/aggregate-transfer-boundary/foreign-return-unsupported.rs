// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

extern "Rust" {
    fn produce() -> (MaybeUninit<u8>, u8);
}

#[kani::proof]
fn foreign_return_unsupported() {
    let value = unsafe { produce() };
    assert_eq!(unsafe { value.0.assume_init() }, 42);
}
