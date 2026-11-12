// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

// A const item borrowed below, not a named static. Actual allocation requires MIR binding.
const PROMOTED: [MaybeUninit<u8>; 3] =
    [MaybeUninit::new(7u8), MaybeUninit::new(0u8), MaybeUninit::new(9u8)];

// Required: tracked flat stack array and anonymous immutable referent.
// Actual origins, masks, retained operation and both byte checks require CI binding.
#[kani::proof]
fn mixed_raw_mu_stack_left_legal() {
    let mut storage = [MaybeUninit::<u8>::uninit(); 3];
    let data = storage.as_mut_ptr().cast::<u8>();
    unsafe {
        data.write(7);
        data.add(1).write(0);
        data.add(2).write(9);
        // All three payload bytes are initialized before borrowing the flat stack array.
        let stack = &storage;
        let promoted: &'static [MaybeUninit<u8>; 3] = &PROMOTED;
        assert!(raw_eq(stack, promoted));
    }
}
