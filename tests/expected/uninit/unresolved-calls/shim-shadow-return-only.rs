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

#[kani::proof]
fn bodyful_shim_shadow_return_only_is_unsupported() {
    let result = invoke_once(|| MaybeUninit::uninit());
    let _read = unsafe { result.assume_init() };
}
