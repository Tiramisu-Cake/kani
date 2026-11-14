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
fn relay(value: Nested) -> Nested {
    mir! {
        type RET = Nested;
        let payload: MaybeUninit<u8>;

        {
            payload = Move(value.payload);
            RET.payload = Move(payload);
            RET.marker = 0;
            Return()
        }
    }
}

#[inline(never)]
unsafe fn read_payload(value: *const MaybeUninit<u8>) -> u8 {
    unsafe { (*value).assume_init() }
}

// Keep both the destination object and its nested payload slot identical across
// the two calls. Only the second returned aggregate contains a payload hole.
#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn reuse_destination(
    seed: MaybeUninit<u8>,
    initialized_payload: MaybeUninit<u8>,
    hole_payload: MaybeUninit<u8>,
) -> u8 {
    mir! {
        type RET = u8;
        let destination: Nested;
        let initialized: Nested;
        let hole: Nested;
        let pointer: *const MaybeUninit<u8>;
        let observed: u8;

        {
            destination.payload = Move(seed);
            destination.marker = 1;
            initialized.payload = Move(initialized_payload);
            initialized.marker = 2;
            hole.payload = Move(hole_payload);
            hole.marker = 3;
            Call(destination = relay(Move(initialized)), ReturnTo(second_call), UnwindUnreachable())
        }

        second_call = {
            Call(destination = relay(Move(hole)), ReturnTo(read), UnwindUnreachable())
        }

        read = {
            pointer = std::ptr::addr_of!(destination.payload);
            Call(observed = read_payload(pointer), ReturnTo(done), UnwindUnreachable())
        }

        done = {
            RET = observed;
            Return()
        }
    }
}

#[kani::proof]
fn repeated_destination_hole_return_is_rejected() {
    std::hint::black_box(unsafe {
        reuse_destination(MaybeUninit::new(11), MaybeUninit::new(23), MaybeUninit::uninit())
    });
}
