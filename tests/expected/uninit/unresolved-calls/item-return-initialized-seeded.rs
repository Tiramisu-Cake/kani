// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[inline(never)]
fn invoke_once<F>(function: F) -> MaybeUninit<u16>
where
    F: FnOnce() -> MaybeUninit<u16>,
{
    function()
}

// Ordinary-byte copy creates a delayed-UB target without raw_eq seeding.
#[inline(never)]
fn seed() {
    let source = 7u8;
    let mut destination = 0u8;
    unsafe { std::ptr::copy_nonoverlapping(&source, &mut destination, 1) };
    assert_eq!(destination, source);
}

// Initialized companion of the Item-return uninit negative.
// Preserve true initialization state through the same noinline generic call.
#[kani::proof]
fn item_return_preserves_initialized_value() {
    seed();
    let result = invoke_once(|| MaybeUninit::new(7u16));
    assert_eq!(unsafe { result.assume_init() }, 7);
}
