// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

enum Packet {
    Plain(u8),
    Shadow(MaybeUninit<u8>),
}

#[inline(never)]
fn consume(value: Packet) -> u8 {
    match value {
        Packet::Plain(x) => x,
        Packet::Shadow(x) => unsafe { x.assume_init() },
    }
}

#[kani::proof]
fn enum_inactive_unsupported() {
    // Construct both variants in source; always pass the inactive-shadow variant.
    let _shadow = Packet::Shadow(MaybeUninit::new(42));
    assert_eq!(consume(Packet::Plain(23)), 23);
}
