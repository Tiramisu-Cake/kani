// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular
use std::mem::MaybeUninit;
#[inline(never)]
fn select(a: MaybeUninit<u16>, b: MaybeUninit<u16>, first: bool) -> MaybeUninit<u16> {
    if first { a } else { b }
}
#[kani::proof]
fn argument_return() {
    let value = select(MaybeUninit::new(9), MaybeUninit::uninit(), kani::any());
    let _value = unsafe { value.assume_init() };
}
