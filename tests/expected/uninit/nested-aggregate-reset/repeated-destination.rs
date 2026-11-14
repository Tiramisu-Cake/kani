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

// The pointer addresses only the u8 union field. Save it while the destination
// is initialized, before either Call: no address-taking setter may follow reset.
// No pointer casts or copy intrinsics seed delayed whole-Nested instrumentation.
#[inline(never)]
#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn reuse_destination(seed: Slot, initialized: Slot, hole: Slot) -> u8 {
    mir! {
        type RET = u8;
        let destination: Nested;
        let saved: *const u8;

        {
            destination.payload = Move(seed);
            destination.marker = 1;
            saved = std::ptr::addr_of!(destination.payload.byte);
            Call(destination = make_nested(Move(initialized)), ReturnTo(second_call), UnwindUnreachable())
        }
        second_call = {
            Call(destination = make_nested(Move(hole)), ReturnTo(read), UnwindUnreachable())
        }
        read = {
            Call(RET = read_payload(saved), ReturnTo(done), UnwindUnreachable())
        }
        done = { Return() }
    }
}

#[kani::proof]
fn repeated_destination_hole_return_is_rejected() {
    std::hint::black_box(unsafe {
        reuse_destination(Slot { byte: 11 }, Slot { byte: 23 }, Slot { hole: () })
    });
}
