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
fn make_nested(payload: Slot) -> Nested {
    mir! {
        type RET = Nested;
        {
            RET.payload = Move(payload);
            RET.marker = 0;
            Return()
        }
    }
}

#[inline(never)]
#[custom_mir(dialect = "runtime", phase = "optimized")]
fn consume_nested(_value: Nested) {
    mir! {
        { Return() }
    }
}

#[inline(never)]
unsafe fn write_payload(pointer: *mut u8, byte: u8) {
    unsafe { *pointer = byte };
}

#[inline(never)]
#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn repair_destination(seed: Slot, hole: Slot, repair: u8) -> u8 {
    mir! {
        type RET = u8;
        let destination: Nested;
        let saved: *mut u8;
        let _unit: ();

        {
            destination.payload = Move(seed);
            destination.marker = 1;
            saved = std::ptr::addr_of_mut!(destination.payload.byte);
            Call(destination = make_nested(Move(hole)), ReturnTo(after_return), UnwindUnreachable())
        }
        after_return = {
            Call(_unit = write_payload(saved, repair), ReturnTo(read), UnwindUnreachable())
        }
        read = {
            Call(RET = read_payload(saved), ReturnTo(done), UnwindUnreachable())
        }
        done = { Return() }
    }
}

#[inline(never)]
#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn repair_moved_source(seed: Slot, repair: u8) -> u8 {
    mir! {
        type RET = u8;
        let source: Nested;
        let saved: *mut u8;
        let _unit: ();

        {
            source.payload = Move(seed);
            source.marker = 3;
            saved = std::ptr::addr_of_mut!(source.payload.byte);
            Call(_unit = consume_nested(Move(source)), ReturnTo(after_move), UnwindUnreachable())
        }
        after_move = {
            Call(_unit = write_payload(saved, repair), ReturnTo(read), UnwindUnreachable())
        }
        read = {
            Call(RET = read_payload(saved), ReturnTo(done), UnwindUnreachable())
        }
        done = { Return() }
    }
}

#[kani::proof]
fn nested_reset_allows_later_destination_and_source_writes() {
    let destination_value = unsafe { repair_destination(Slot { byte: 11 }, Slot { hole: () }, 55) };
    let source_value = unsafe { repair_moved_source(Slot { byte: 42 }, 77) };
    assert_eq!(destination_value, 55);
    assert_eq!(source_value, 77);
}
