// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[inline(never)]
fn invoke_once<F>(function: F, value: MaybeUninit<u16>)
where
    F: FnOnce(MaybeUninit<u16>),
{
    function(value);
}

// Ordinary-byte copy creates a delayed-UB target without raw_eq seeding.
#[inline(never)]
fn seed() {
    let source = 7u8;
    let mut destination = 0u8;
    unsafe { std::ptr::copy_nonoverlapping(&source, &mut destination, 1) };
    assert_eq!(destination, source);
}

// This source is only a lowering probe. FnOnce's tuple ABI may keep the
// MaybeUninit argument inside a tuple, so this does not establish that the
// direct-shadow-argument guard is reached. Required guard coverage needs a
// compiler-level visitor control if the pinned MIR does not expose it directly.
// The golden is a provisional direct-shadow guard contract, not established
// coverage: CI must confirm a direct argument reaches a bodyful Shim, or use
// the separate compiler-level control specified in the B1I manifest.
#[kani::proof]
fn bodyful_shim_shadow_argument_only_is_unsupported() {
    seed();
    invoke_once(|_value| {}, MaybeUninit::uninit());
}
