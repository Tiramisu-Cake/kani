// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

#![feature(custom_mir, core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::mir::*;
use std::mem::MaybeUninit;

#[repr(C)]
struct Nested {
    payload: MaybeUninit<u8>,
    marker: u8,
}

#[inline(never)]
#[custom_mir(dialect = "runtime", phase = "optimized")]
fn relay(value: Nested) -> Nested {
    mir! {
        type RET = Nested;
        let payload: MaybeUninit<u8>;
        let marker: u8;

        {
            payload = Move(value.payload);
            marker = value.marker;
            RET.payload = Move(payload);
            RET.marker = marker;
            Return()
        }
    }
}

#[inline(never)]
unsafe fn read_payload(value: *const MaybeUninit<u8>) -> u8 {
    unsafe { (*value).assume_init() }
}

#[inline(never)]
unsafe fn write_payload(value: *mut MaybeUninit<u8>, byte: u8) {
    unsafe { (*value).write(byte) };
}

#[inline(never)]
fn consume_nested(value: Nested) {
    std::hint::black_box(value.marker);
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn repair_destination(hole: MaybeUninit<u8>, repair: MaybeUninit<u8>) -> u8 {
    mir! {
        type RET = u8;
        let destination: Nested;
        let source: Nested;
        let pointer: *const MaybeUninit<u8>;
        let observed: u8;

        {
            source.payload = Move(hole);
            source.marker = 1;
            Call(destination = relay(Move(source)), ReturnTo(after_return), UnwindUnreachable())
        }

        after_return = {
            destination.payload = Move(repair);
            pointer = std::ptr::addr_of!(destination.payload);
            Call(observed = read_payload(pointer), ReturnTo(done), UnwindUnreachable())
        }

        done = {
            RET = observed;
            Return()
        }
    }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn repair_moved_source(seed: MaybeUninit<u8>, repair: u8) -> u8 {
    mir! {
        type RET = u8;
        let source: Nested;
        let saved: *mut MaybeUninit<u8>;
        let observed: u8;
        let _unit: ();

        {
            source.payload = Move(seed);
            source.marker = 3;
            saved = std::ptr::addr_of_mut!(source.payload);
            Call(_unit = consume_nested(Move(source)), ReturnTo(after_move), UnwindUnreachable())
        }

        after_move = {
            Call(_unit = write_payload(saved, repair), ReturnTo(after_repair), UnwindUnreachable())
        }

        after_repair = {
            Call(observed = read_payload(saved), ReturnTo(done), UnwindUnreachable())
        }

        done = {
            RET = observed;
            Return()
        }
    }
}

#[kani::proof]
fn nested_reset_allows_later_destination_and_source_writes() {
    let destination_value =
        unsafe { repair_destination(MaybeUninit::uninit(), MaybeUninit::new(55)) };
    let source_value = unsafe { repair_moved_source(MaybeUninit::new(42), 77) };
    assert_eq!(destination_value, 55);
    assert_eq!(source_value, 77);
}
