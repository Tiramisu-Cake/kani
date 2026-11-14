// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular --harness copy_same_source_to_arg0_initialized --exact -Z unstable-options --cbmc-args --object-bits 12

#![feature(custom_mir, core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::mir::*;
use std::mem::MaybeUninit;

#[inline(never)]
fn read_first(first: MaybeUninit<u32>, _second: MaybeUninit<u32>) -> u32 {
    unsafe { first.assume_init() }
}

#[inline(never)]
unsafe fn read_original(pointer: *const MaybeUninit<u32>) -> u32 {
    unsafe { (*pointer).assume_init() }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
fn copy_same_source_to_arg0(source: MaybeUninit<u32>) -> (u32, u32) {
    mir! {
        type RET = (u32, u32);
        let pointer: *const MaybeUninit<u32>;
        let selected: u32;
        let original: u32;
        {
            pointer = std::ptr::addr_of!(source);
            Call(selected = read_first(Copy(source), Copy(source)), ReturnTo(after_call), UnwindUnreachable())
        }
        after_call = {
            Call(original = read_original(pointer), ReturnTo(done), UnwindUnreachable())
        }
        done = {
            RET.0 = Move(selected);
            RET.1 = Move(original);
            Return()
        }
    }
}

#[kani::proof]
fn copy_same_source_to_arg0_initialized() {
    let source = MaybeUninit::<u32>::new(0x1234);
    let (selected, original_after_call) = copy_same_source_to_arg0(source);
    assert_eq!(selected, 0x1234);
    assert_eq!(original_after_call, 0x1234);
}
