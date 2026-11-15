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

// FnOnce wraps the MaybeUninit argument in a compound tuple.
// Expect the tuple-layout Unsupported before any direct-shadow Shim guard.
// This does not cover the direct-shadow-argument guard.
#[kani::proof]
fn tuple_maybe_uninit_layout_is_unsupported() {
    invoke_once(|_value| {}, MaybeUninit::uninit());
}
