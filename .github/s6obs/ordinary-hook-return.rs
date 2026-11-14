// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular --cbmc-args --object-bits 12
use std::mem::MaybeUninit;

#[kani::proof]
fn ordinary_hook_return() {
    let mut source = MaybeUninit::<u16>::uninit();
    // Runtime-seeded storage. This is the actual public internal function,
    // not a mock carrying a copied marker or matching name.
    unsafe { source.as_mut_ptr().cast::<u8>().write(7) };
    let destination = kani::internal::untracked_deref(&source);
    let _payload = unsafe { destination.assume_init_read() };
}
