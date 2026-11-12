// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// kani-flags: -Z uninit-checks
// compile-flags: --edition 2021 -D warnings

#![feature(core_intrinsics, custom_mir)]
#![allow(internal_features)]

use core::intrinsics::mir::*;

union Word {
    word: u32,
}
fn identity(value: u32) -> u32 {
    value
}

// The first MIR block is empty: entry LoadArgument and the u32 union-field
// read share the unresolved Call target. The aggregate is runtime symbolic
// input, not an ordinary-union constant.
#[custom_mir(dialect = "runtime", phase = "optimized")]
#[inline(never)]
unsafe fn indirect(value: Word, f: fn(u32) -> u32) -> u32 {
    mir! {
        { Call(RET = f(value.word), ReturnTo(done), UnwindUnreachable()) }
        done = { Return() }
    }
}

// An ordinary initialized-byte copy creates a delayed-UB analysis target.
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
    let _ = unsafe { indirect(Word { word: kani::any() }, identity) };
}
