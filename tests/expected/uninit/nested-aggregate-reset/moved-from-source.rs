// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

#![feature(custom_mir, core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::mir::*;

#[derive(Clone, Copy)]
union Slot {
    byte: u8,
    #[allow(dead_code)]
    hole: (),
}

#[repr(C)]
struct Nested {
    payload: Slot,
    #[allow(dead_code)]
    marker: u8,
}

#[inline(never)]
unsafe fn read_payload(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}

#[inline(never)]
#[custom_mir(dialect = "runtime", phase = "optimized")]
fn consume_nested(_value: Nested) {
    mir! {
        { Return() }
    }
}

// Keep the actual source allocation live after Call(Move(source)). The saved
// u8 pointer is formed before the Move, without a pointer to the parent Nested
// or a layout-changing cast that would seed the delayed whole-aggregate guard.
#[inline(never)]
#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn read_moved_from_source(seed: Slot) -> u8 {
    mir! {
        type RET = u8;
        let source: Nested;
        let saved: *const u8;
        let _unit: ();

        {
            source.payload = Move(seed);
            source.marker = 3;
            saved = std::ptr::addr_of!(source.payload.byte);
            Call(_unit = consume_nested(Move(source)), ReturnTo(after_move), UnwindUnreachable())
        }
        after_move = {
            Call(RET = read_payload(saved), ReturnTo(done), UnwindUnreachable())
        }
        done = { Return() }
    }
}

#[kani::proof]
fn moved_from_nested_payload_read_is_rejected() {
    std::hint::black_box(unsafe { read_moved_from_source(Slot { byte: 42 }) });
}
