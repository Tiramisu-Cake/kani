// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

extern "Rust" {
    fn foreign_echo(value: MaybeUninit<u16>) -> MaybeUninit<u16>;
}

fn make_echo() -> impl Fn(MaybeUninit<u16>) -> MaybeUninit<u16> {
    |value| value
}

#[inline(never)]
fn invoke_once<F>(function: F, value: MaybeUninit<u16>) -> MaybeUninit<u16>
where
    F: FnOnce(MaybeUninit<u16>) -> MaybeUninit<u16>,
{
    function(value)
}

#[kani::proof]
fn bodyless_foreign_argument_and_return_are_unsupported() {
    let value = unsafe { foreign_echo(MaybeUninit::uninit()) };
    let _read = unsafe { value.assume_init() };
}

#[kani::proof]
fn fn_once_shim_argument_and_return_are_unsupported() {
    let value = invoke_once(make_echo(), MaybeUninit::uninit());
    let _read = unsafe { value.assume_init() };
}
