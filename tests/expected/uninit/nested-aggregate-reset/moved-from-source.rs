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
    #[allow(dead_code)]
    marker: u8,
}

#[inline(never)]
#[custom_mir(dialect = "runtime", phase = "optimized")]
fn relay(_value: Nested) {
    mir! {
        { Return() }
    }
}

#[inline(never)]
unsafe fn read_payload(value: *const MaybeUninit<u8>) -> u8 {
    unsafe { (*value).assume_init() }
}

// Assemble source field-by-field so the nested aggregate assignment guard does
// not stop the test before Call(Move(source)). Keep source storage live through
// the saved-pointer read. A scalar black_box retains the observed payload.
#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn read_moved_from_source(seed: MaybeUninit<u8>) -> u8 {
    mir! {
        type RET = u8;
        let source: Nested;
        let saved: *const MaybeUninit<u8>;
        let _unit: ();
        let observed: u8;

        {
            source.payload = Move(seed);
            source.marker = 3;
            saved = std::ptr::addr_of!(source.payload);
            Call(_unit = relay(Move(source)), ReturnTo(after_move), UnwindUnreachable())
        }

        after_move = {
            Call(observed = read_payload(saved), ReturnTo(done), UnwindUnreachable())
        }

        done = {
            RET = observed;
            Return()
        }
    }
}

#[kani::proof]
fn moved_from_nested_payload_read_is_rejected() {
    std::hint::black_box(unsafe { read_moved_from_source(MaybeUninit::new(42)) });
}
