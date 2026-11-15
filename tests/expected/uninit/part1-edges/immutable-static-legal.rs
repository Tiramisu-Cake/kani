// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::raw_eq;
use std::mem::MaybeUninit;

static SOURCE: [MaybeUninit<u8>; 3] =
    [MaybeUninit::new(0), MaybeUninit::new(0), MaybeUninit::new(0)];

#[kani::proof]
fn immutable_static_legal() {
    let right: &[MaybeUninit<u8>; 3] = &[MaybeUninit::new(0); 3];
    assert!(unsafe { raw_eq(&SOURCE, right) });
}
