// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(custom_mir, core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::mir::*;

#[derive(Clone, Copy)]
#[allow(dead_code)]
union Byte {
    byte: u8,
    empty: (),
}

#[inline(never)]
fn consume(value: Byte) -> u8 {
    unsafe { value.byte }
}

// Require CI binding to Operand::Copy of an ordinary union.
#[custom_mir(dialect = "runtime", phase = "optimized")]
fn transfer(source: Byte) -> u8 {
    mir! {
        {
            Call(RET = consume(source), ReturnTo(done), UnwindUnreachable())
        }
        done = { Return() }
    }
}

#[kani::proof]
fn union_variable_legal() {
    assert_eq!(transfer(Byte { byte: 0 }), 0);
}
