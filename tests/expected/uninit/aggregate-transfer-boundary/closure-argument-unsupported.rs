// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn touch<T>(_: &T) {}

#[inline(never)]
fn consume<F: FnOnce() -> u8>(callback: F) -> u8 {
    callback()
}

#[kani::proof]
fn closure_argument_unsupported() {
    let slot = MaybeUninit::new(42u8);
    let callback = move || {
        touch(&slot);
        unsafe { slot.assume_init() }
    };
    assert_eq!(consume(callback), 42);
}
