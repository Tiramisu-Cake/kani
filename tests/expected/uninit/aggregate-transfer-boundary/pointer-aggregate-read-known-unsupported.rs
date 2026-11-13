// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

struct Packet {
    slot: MaybeUninit<u8>,
}

#[inline(never)]
unsafe fn read(value: *const Packet) -> u8 {
    unsafe { (*value).slot.assume_init() }
}

#[kani::proof]
fn pointer_aggregate_read_known_unsupported() {
    let value = Packet { slot: MaybeUninit::new(42) };
    // Pointer admission does not add support for the existing aggregate pointee layout.
    assert_eq!(unsafe { read(&raw const value) }, 42);
}
