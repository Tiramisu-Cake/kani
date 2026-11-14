// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

static IMMUTABLE_HOLE: MaybeUninit<u8> = MaybeUninit::uninit();

#[kani::proof]
fn immutable_hole_negative() {
    // Deliberate invalid read, isolated to this root.
    let _ = unsafe { IMMUTABLE_HOLE.assume_init_read() };
}
