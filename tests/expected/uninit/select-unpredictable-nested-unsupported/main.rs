// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
struct Nested {
    bytes: [MaybeUninit<u8>; 2],
}

#[kani::proof]
fn nested_shadow_layout_remains_unsupported() {
    let initialized =
        MaybeUninit::new(Nested { bytes: [MaybeUninit::new(1), MaybeUninit::new(2)] });
    let hole = MaybeUninit::<Nested>::uninit();
    let selected = core::intrinsics::select_unpredictable(true, initialized, hole);
    let _result_pointer = std::hint::black_box(selected.as_ptr());
}
