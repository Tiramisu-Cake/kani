// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

// compile-flags: --edition 2021
// Loading an uninhabited ZST requires a safety diagnostic.
#![feature(core_intrinsics)]

enum Empty {}

#[kani::proof]
fn uninhabited_zst() {
    let src = std::ptr::NonNull::<Empty>::dangling().as_ptr();
    let _ = unsafe { std::intrinsics::volatile_load(src) };
}
