// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

struct Packet {
    slot: MaybeUninit<u8>,
}

#[inline(never)]
fn produce() -> Packet {
    Packet { slot: MaybeUninit::new(42) }
}

#[kani::proof]
fn struct_return_unsupported() {
    assert_eq!(unsafe { produce().slot.assume_init() }, 42);
}
