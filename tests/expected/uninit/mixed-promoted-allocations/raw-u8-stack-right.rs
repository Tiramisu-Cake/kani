// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

// Required: tracked stack/assume_init temporary and anonymous immutable referent.
// Actual origins, masks, retained operation and both byte checks require CI binding.
#[kani::proof]
fn mixed_raw_u8_stack_right() {
    let mut storage = MaybeUninit::<[u8; 3]>::uninit();
    let data = storage.as_mut_ptr().cast::<u8>();
    unsafe {
        data.write(7);
        data.add(1).write(0);
        data.add(2).write(9);
        // All three bytes are initialized before constructing this stack value.
        let stack = &storage.assume_init();
        let promoted: &'static [u8; 3] = &[7u8, 0u8, 9u8];
        assert!(raw_eq(promoted, stack));
    }
}
