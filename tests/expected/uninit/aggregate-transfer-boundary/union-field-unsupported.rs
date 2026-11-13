// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

#[derive(Clone, Copy)]
union Slot {
    byte: u8,
}
struct Packet {
    slot: Slot,
}

#[inline(never)]
fn consume(value: Packet) -> u8 {
    unsafe { value.slot.byte }
}

#[kani::proof]
fn union_field_unsupported() {
    assert_eq!(consume(Packet { slot: Slot { byte: 42 } }), 42);
}
