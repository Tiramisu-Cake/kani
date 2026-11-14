// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular --harness copy_same_source_to_arg0_hole --exact -Z unstable-options --cbmc-args --object-bits 12

#![feature(custom_mir, core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::mir::*;
use std::mem::MaybeUninit;

#[inline(never)]
fn read_first(first: MaybeUninit<u32>, _second: MaybeUninit<u32>) -> u32 {
    unsafe { std::ptr::read(first.as_ptr()) }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
fn copy_same_source_to_arg0(source: MaybeUninit<u32>) -> u32 {
    mir! {
        type RET = u32;
        let selected: u32;
        {
            Call(selected = read_first(Copy(source), Copy(source)), ReturnTo(done), UnwindUnreachable())
        }
        done = {
            RET = Move(selected);
            Return()
        }
    }
}

#[kani::proof]
fn copy_same_source_to_arg0_hole() {
    let initialized = MaybeUninit::<u16>::new(0xABCD);
    assert_eq!(unsafe { initialized.assume_init() }, 0xABCD);
    let source = MaybeUninit::<u32>::uninit();
    let _read = copy_same_source_to_arg0(source);
}
