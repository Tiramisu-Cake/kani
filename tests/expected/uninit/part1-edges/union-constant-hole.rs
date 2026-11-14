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

const VALUE: Byte = Byte { empty: () };

// Require CI binding to Operand::Constant of an ordinary union.
#[custom_mir(dialect = "runtime", phase = "optimized")]
fn transfer() -> u8 {
    mir! {
        {
            Call(RET = consume(VALUE), ReturnTo(done), UnwindUnreachable())
        }
        done = { Return() }
    }
}

#[kani::proof]
fn union_constant_hole() {
    let _read = transfer();
}
