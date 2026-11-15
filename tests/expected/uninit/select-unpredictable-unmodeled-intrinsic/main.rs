// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[kani::proof]
fn unmodeled_shadow_intrinsic_stays_unsupported() {
    let value = MaybeUninit::<u8>::uninit();
    let selected = std::hint::black_box(value);
    let _pointer = selected.as_ptr();
}
