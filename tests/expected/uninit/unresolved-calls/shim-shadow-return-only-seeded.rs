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

#[kani::proof]
fn bodyful_shim_shadow_return_only_is_unsupported() {
    seed();
    let result = invoke_once(|| MaybeUninit::uninit());
    let _read = unsafe { result.assume_init() };
}
