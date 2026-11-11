// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// kani-flags: -Z uninit-checks
// compile-flags: --edition 2021 -D warnings

#![feature(core_intrinsics, custom_mir)]
#![allow(internal_features)]

use core::intrinsics::mir::*;

fn identity(value: u8) -> u8 {
    value
}

// The dereference is an operand of the Call terminator, so super_terminator
// collects its Check before resolution fails. It must precede Unsupported.
#[custom_mir(dialect = "runtime", phase = "optimized")]
#[inline(never)]
unsafe fn indirect(f: fn(u8) -> u8, pointer: *const u8) -> u8 {
    mir! {
        { Call(RET = f(*pointer), ReturnTo(done), UnwindUnreachable()) }
        done = { Return() }
    }
}

// A copy intrinsic creates a delayed-UB analysis target without introducing UB.
#[inline(never)]
fn seed() {
    let source = 7u8;
    let mut destination = 0u8;
    unsafe { std::ptr::copy_nonoverlapping(&source, &mut destination, 1) };
    assert_eq!(destination, source);
}

#[kani::proof]
fn check() {
    seed();
    let value = std::mem::MaybeUninit::<u8>::uninit();
    let _ = unsafe { indirect(identity, value.as_ptr()) };
}
