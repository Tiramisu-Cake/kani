// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(unsized_fn_params)]

use std::mem::MaybeUninit;

trait ReadSlot {
    fn read(self) -> u8;
}

impl ReadSlot for [MaybeUninit<u8>] {
    #[inline(never)]
    fn read(self) -> u8 {
        unsafe { self[1].assume_init() }
    }
}

#[kani::proof]
fn dst_by_value_legal() {
    // Same source form as tests/kani/UnsizedFnParams: the ARGUMENT is *source,
    // not the Box/fat pointer. Require actual by-value Slice/Move binding in CI.
    let source: Box<[MaybeUninit<u8>]> = Box::new([MaybeUninit::new(0u8), MaybeUninit::new(0u8)]);
    let _read = (*source).read();
}
