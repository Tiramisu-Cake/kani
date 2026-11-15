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

// The closure call was reported as Item in the pinned Quick. Returning false
// initialization state must preserve the reached assume_init read failure.
#[kani::proof]
fn item_return_preserves_uninitialized_read() {
    let result = invoke_once(|| MaybeUninit::uninit());
    let _read = unsafe { result.assume_init() };
}
