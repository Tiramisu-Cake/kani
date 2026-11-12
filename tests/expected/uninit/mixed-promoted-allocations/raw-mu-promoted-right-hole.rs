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
    [MaybeUninit::new(7u8), MaybeUninit::new(0u8), MaybeUninit::uninit()];

// Required: tracked stack/assume_init temporary and anonymous immutable referent.
// Actual origins, masks, retained operation and both byte checks require CI binding.
// Only the promoted right raw_eq byte read may fail; the stack check must succeed.
// MaybeUninit references are valid; no hole is converted to a typed u8 value.
#[kani::proof]
fn mixed_raw_mu_promoted_right_hole() {
    let mut storage = MaybeUninit::<[MaybeUninit<u8>; 3]>::uninit();
    let data = storage.as_mut_ptr().cast::<u8>();
    unsafe {
        data.write(7);
        data.add(1).write(0);
        data.add(2).write(9);
        // All three bytes are initialized before constructing this stack value.
        let stack = &storage.assume_init();
        let promoted: &'static [MaybeUninit<u8>; 3] = &PROMOTED;
        let _equal = raw_eq(stack, promoted);
    }
}
