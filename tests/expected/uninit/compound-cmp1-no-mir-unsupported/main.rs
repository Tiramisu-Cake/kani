// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=terse

use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
struct C {
    marker: usize,
    slots: [MaybeUninit<usize>; 2],
}
extern "Rust" {
    fn opaque(value: C) -> C;
}

#[kani::proof]
fn bodyless_shadow_carrying_argument_is_unsupported_before_call() {
    let value = C { marker: 11, slots: [MaybeUninit::new(7), MaybeUninit::uninit()] };
    unsafe {
        let _ = opaque(value);
    }
}
