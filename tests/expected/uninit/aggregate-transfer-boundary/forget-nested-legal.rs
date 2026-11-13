// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::mem::MaybeUninit;

#[kani::proof]
fn forget_nested_legal() {
    // Deliberate no-transfer intrinsic, with no payload read or return.
    std::intrinsics::forget((MaybeUninit::<u8>::uninit(), 23u8));
}
