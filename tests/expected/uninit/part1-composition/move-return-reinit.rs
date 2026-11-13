// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(custom_mir, core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::mir::*;
use std::mem::MaybeUninit;

#[inline(never)]
fn relay(value: MaybeUninit<u8>) -> MaybeUninit<u8> {
    value
}

#[inline(never)]
unsafe fn repair(pointer: *mut MaybeUninit<u8>) {
    unsafe {
        (*pointer).write(23);
    }
}

#[inline(never)]
unsafe fn read_source(pointer: *const MaybeUninit<u8>) -> u8 {
    unsafe { (*pointer).assume_init() }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn handoff(source: MaybeUninit<u8>, reinit: bool) -> (MaybeUninit<u8>, u8) {
    mir! {
        type RET = (MaybeUninit<u8>, u8);
        let pointer: *mut MaybeUninit<u8>;
        let returned: MaybeUninit<u8>;
        let observed: u8;
        let _unit: ();
        {
            pointer = std::ptr::addr_of_mut!(source);
            Call(returned = relay(Move(source)), ReturnTo(after_return), UnwindUnreachable())
        }
        after_return = {
            match reinit { true => do_repair, _ => do_read }
        }
        do_repair = {
            Call(_unit = repair(pointer), ReturnTo(do_read), UnwindUnreachable())
        }
        do_read = {
            Call(observed = read_source(pointer), ReturnTo(done), UnwindUnreachable())
        }
        done = {
            RET.0 = Move(returned);
            RET.1 = observed;
            Return()
        }
    }
}

// Known false positive: semantically this must be SUCCESS. Nested aggregate
// shadow transfer is not implemented for the tuple returned by handoff.
// The pinned failure is a regression observation, not detection of UB here.
#[kani::proof]
fn move_return_reinit_legal() {
    let (returned, source) = unsafe { handoff(MaybeUninit::new(42), true) };
    assert_eq!(unsafe { returned.assume_init() }, 42);
    assert_eq!(source, 23);
}

#[kani::proof]
fn move_return_source_hole() {
    let (returned, _source) = unsafe { handoff(MaybeUninit::new(42), false) };
    assert_eq!(unsafe { returned.assume_init() }, 42);
}
