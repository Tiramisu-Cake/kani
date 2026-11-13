// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
struct Packet {
    slot: MaybeUninit<u8>,
}

#[inline(never)]
fn consume(value: [Packet; 2]) -> u8 {
    unsafe { value[1].slot.assume_init() }
}

#[kani::proof]
fn array_struct_unsupported() {
    assert_eq!(consume([Packet { slot: MaybeUninit::new(42) }; 2]), 42);
}
