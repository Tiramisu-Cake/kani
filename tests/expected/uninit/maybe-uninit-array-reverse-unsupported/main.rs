// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};

#[kani::proof]
fn initialized_array_reverse_is_unsupported() {
    let source = [MaybeUninit::new(7_u32), MaybeUninit::new(9_u32)];
    let destination: [u32; 2] = unsafe { mem::transmute(source) };
    assert_eq!(destination[0], 7);
    assert_eq!(destination[1], 9);
}

#[kani::proof]
fn partial_array_reverse_is_unsupported() {
    let source = [MaybeUninit::new(7_u32), MaybeUninit::uninit()];
    let destination: [u32; 2] = unsafe { mem::transmute(source) };
    assert_eq!(destination[0], 7);
    assert_eq!(destination[1], 9);
}
