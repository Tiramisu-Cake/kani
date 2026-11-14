// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular --cbmc-args --object-bits 12
use std::mem::MaybeUninit;
#[inline(never)]
fn hole() -> MaybeUninit<u16> { MaybeUninit::uninit() }
#[inline(never)]
fn invoke<F: FnOnce() -> MaybeUninit<u16>>(f: F) -> MaybeUninit<u16> { f() }
#[kani::proof]
fn fn_item_shadow_return() {
    let result = invoke(hole);
    let _payload = unsafe { result.assume_init_read() };
}
