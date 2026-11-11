// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular
#![feature(custom_mir, core_intrinsics)]
#![allow(internal_features)]

use std::intrinsics::mir::*;
use std::mem::MaybeUninit;

#[inline(never)]
fn consume(value: MaybeUninit<u8>) -> u8 {
    unsafe { value.assume_init() }
}

#[inline(never)]
fn consume_and_write(mut value: MaybeUninit<u8>) -> u8 {
    value.write(0xA7);
    unsafe { value.assume_init() }
}

#[inline(never)]
unsafe fn read_payload(pointer: *const MaybeUninit<u8>) -> u8 {
    unsafe { (*pointer).assume_init() }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn move_call(source: MaybeUninit<u8>) -> (u8, u8) {
    mir! {
        type RET = (u8, u8);
        let pointer: *const MaybeUninit<u8>;
        let callee: u8;
        let observed: u8;

        {
            pointer = std::ptr::addr_of!(source);
            Call(callee = consume(Move(source)), ReturnTo(after_call), UnwindContinue())
        }

        after_call = {
            Call(observed = read_payload(pointer), ReturnTo(done), UnwindContinue())
        }

        done = {
            RET.0 = callee;
            RET.1 = observed;
            Return()
        }
    }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn move_uninitialized_payload(source: MaybeUninit<u8>) -> u8 {
    mir! {
        type RET = u8;
        let callee: u8;

        {
            Call(callee = consume(Move(source)), ReturnTo(done), UnwindContinue())
        }

        done = {
            RET = callee;
            Return()
        }
    }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn move_initialized_callee_only(source: MaybeUninit<u8>) -> u8 {
    mir! {
        type RET = u8;
        let callee: u8;

        {
            Call(callee = consume(Move(source)), ReturnTo(done), UnwindContinue())
        }

        done = {
            RET = callee;
            Return()
        }
    }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn move_call_writes_parameter(source: MaybeUninit<u8>) -> (u8, u8) {
    mir! {
        type RET = (u8, u8);
        let pointer: *const MaybeUninit<u8>;
        let callee: u8;
        let observed: u8;

        {
            pointer = std::ptr::addr_of!(source);
            Call(callee = consume_and_write(Move(source)), ReturnTo(after_call), UnwindContinue())
        }

        after_call = {
            Call(observed = read_payload(pointer), ReturnTo(done), UnwindContinue())
        }

        done = {
            RET.0 = callee;
            RET.1 = observed;
            Return()
        }
    }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn copy_call(source: MaybeUninit<u8>) -> (u8, u8) {
    mir! {
        type RET = (u8, u8);
        let pointer: *const MaybeUninit<u8>;
        let callee: u8;
        let observed: u8;

        {
            pointer = std::ptr::addr_of!(source);
            // The bare place is Operand::Copy; the custom MIR source is Copy.
            Call(callee = consume(source), ReturnTo(after_call), UnwindContinue())
        }

        after_call = {
            Call(observed = read_payload(pointer), ReturnTo(done), UnwindContinue())
        }

        done = {
            RET.0 = callee;
            RET.1 = observed;
            Return()
        }
    }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn copy_call_writes_parameter(source: MaybeUninit<u8>) -> (u8, u8) {
    mir! {
        type RET = (u8, u8);
        let pointer: *const MaybeUninit<u8>;
        let callee: u8;
        let observed: u8;

        {
            pointer = std::ptr::addr_of!(source);
            Call(callee = consume_and_write(source), ReturnTo(after_call), UnwindContinue())
        }

        after_call = {
            Call(observed = read_payload(pointer), ReturnTo(done), UnwindContinue())
        }

        done = {
            RET.0 = callee;
            RET.1 = observed;
            Return()
        }
    }
}

#[kani::proof]
fn in_place_move_reads_initialized_callee_then_uninit_source() {
    let (callee, source) = unsafe { move_call(MaybeUninit::new(0x51)) };
    assert_eq!(callee, 0x51);
    assert_eq!(source, 0x51);
}

#[kani::proof]
fn in_place_move_still_checks_uninitialized_callee_payload() {
    let _callee = unsafe { move_uninitialized_payload(MaybeUninit::uninit()) };
}

#[kani::proof]
fn in_place_move_delivers_initialized_payload_to_callee() {
    let callee = unsafe { move_initialized_callee_only(MaybeUninit::new(0x51)) };
    assert_eq!(callee, 0x51);
}

#[kani::proof]
fn in_place_move_write_still_deinitializes_source() {
    let (callee, source) = unsafe { move_call_writes_parameter(MaybeUninit::new(0x51)) };
    assert_eq!(callee, 0xA7);
    assert_eq!(source, 0x51);
}

#[kani::proof]
fn in_place_copy_preserves_source() {
    let (callee, source) = unsafe { copy_call(MaybeUninit::new(0x51)) };
    assert_eq!(callee, 0x51);
    assert_eq!(source, 0x51);
}

#[kani::proof]
fn in_place_copy_write_changes_parameter_only() {
    let (callee, source) = unsafe { copy_call_writes_parameter(MaybeUninit::new(0x51)) };
    assert_eq!(callee, 0xA7);
    assert_eq!(source, 0x51);
}

struct NonCopy(u8);

#[inline(never)]
fn consume_noncopy(value: MaybeUninit<NonCopy>) -> u8 {
    unsafe { value.assume_init().0 }
}

#[kani::proof]
fn ordinary_by_value_temporary_preserves_original_source() {
    let source = MaybeUninit::new(NonCopy(0x51));
    let pointer = source.as_ptr().cast::<u8>();
    let callee = consume_noncopy(source);
    let observed = unsafe { std::ptr::read_volatile(pointer) };
    assert_eq!(callee, 0x51);
    assert_eq!(observed, 0x51);
}

#[derive(Clone, Copy)]
union Byte {
    byte: u8,
}

#[inline(never)]
fn consume_union(value: Byte) -> u8 {
    unsafe { value.byte }
}

#[inline(never)]
unsafe fn read_union(pointer: *const u8) -> u8 {
    unsafe { std::ptr::read_volatile(pointer) }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn union_move_call(source: Byte) -> (u8, u8) {
    mir! {
        type RET = (u8, u8);
        let pointer: *const u8;
        let callee: u8;
        let observed: u8;

        {
            pointer = std::ptr::addr_of!(source.byte);
            Call(callee = consume_union(Move(source)), ReturnTo(after_call), UnwindContinue())
        }

        after_call = {
            Call(observed = read_union(pointer), ReturnTo(done), UnwindContinue())
        }

        done = {
            RET.0 = callee;
            RET.1 = observed;
            Return()
        }
    }
}

#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn union_copy_call(source: Byte) -> (u8, u8) {
    mir! {
        type RET = (u8, u8);
        let pointer: *const u8;
        let callee: u8;
        let observed: u8;

        {
            pointer = std::ptr::addr_of!(source.byte);
            Call(callee = consume_union(source), ReturnTo(after_call), UnwindContinue())
        }

        after_call = {
            Call(observed = read_union(pointer), ReturnTo(done), UnwindContinue())
        }

        done = {
            RET.0 = callee;
            RET.1 = observed;
            Return()
        }
    }
}

#[kani::proof]
fn union_in_place_move_deinitializes_source() {
    let (callee, source) = unsafe { union_move_call(Byte { byte: 0x51 }) };
    assert_eq!(callee, 0x51);
    assert_eq!(source, 0x51);
}

#[kani::proof]
fn union_in_place_copy_preserves_source() {
    let (callee, source) = unsafe { union_copy_call(Byte { byte: 0x51 }) };
    assert_eq!(callee, 0x51);
    assert_eq!(source, 0x51);
}
