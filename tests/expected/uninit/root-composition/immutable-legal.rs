// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

static IMMUTABLE_LEGAL: MaybeUninit<u8> = MaybeUninit::new(17);

#[kani::proof]
fn immutable_legal() {
    // Immutable named static, read only after its initialized construction.
    let value = unsafe { IMMUTABLE_LEGAL.assume_init_read() };
    assert_eq!(value, 17);
}
