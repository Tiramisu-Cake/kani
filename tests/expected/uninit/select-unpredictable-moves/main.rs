// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -C panic=abort
// kani-flags: -Z uninit-checks --output-format=regular

#![feature(core_intrinsics, custom_mir)]
#![allow(internal_features)]

use std::{intrinsics::mir::*, mem::MaybeUninit};

#[inline(never)]
fn consume(value: MaybeUninit<u8>) -> u8 {
    unsafe { value.assume_init() }
}

#[inline(never)]
unsafe fn read_payload(pointer: *const MaybeUninit<u8>) -> u8 {
    unsafe { (*pointer).assume_init() }
}

// Snapshot source A, Move both actual operands directly into the intrinsic, and
// consume the selected result before reading the moved-from source snapshot.
#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn move_then_read_a(
    condition: bool,
    a: MaybeUninit<u8>,
    b: MaybeUninit<u8>,
) -> (u8, u8) {
    mir! {
        type RET = (u8, u8);
        let pointer_a: *const MaybeUninit<u8>;
        let selected: MaybeUninit<u8>;
        let selected_value: u8;
        let observed_a: u8;

        {
            pointer_a = std::ptr::addr_of!(a);
            Call(selected = core::intrinsics::select_unpredictable(condition, Move(a), Move(b)), ReturnTo(consume_selected), UnwindUnreachable())
        }

        consume_selected = {
            Call(selected_value = consume(Move(selected)), ReturnTo(read_a), UnwindUnreachable())
        }

        read_a = {
            Call(observed_a = read_payload(pointer_a), ReturnTo(done), UnwindUnreachable())
        }

        done = {
            RET.0 = selected_value;
            RET.1 = observed_a;
            Return()
        }
    }
}

// Same direct Move operands; observe source B independently so each selector
// has exactly one intended source-read failure.
#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn move_then_read_b(
    condition: bool,
    a: MaybeUninit<u8>,
    b: MaybeUninit<u8>,
) -> (u8, u8) {
    mir! {
        type RET = (u8, u8);
        let pointer_b: *const MaybeUninit<u8>;
        let selected: MaybeUninit<u8>;
        let selected_value: u8;
        let observed_b: u8;

        {
            pointer_b = std::ptr::addr_of!(b);
            Call(selected = core::intrinsics::select_unpredictable(condition, Move(a), Move(b)), ReturnTo(consume_selected), UnwindUnreachable())
        }

        consume_selected = {
            Call(selected_value = consume(Move(selected)), ReturnTo(read_b), UnwindUnreachable())
        }

        read_b = {
            Call(observed_b = read_payload(pointer_b), ReturnTo(done), UnwindUnreachable())
        }

        done = {
            RET.0 = selected_value;
            RET.1 = observed_b;
            Return()
        }
    }
}

// Bare places are Copy operands in the custom-MIR DSL (mir.rs Operands).
// Both actual source locals must remain initialized.
#[custom_mir(dialect = "runtime", phase = "optimized")]
unsafe fn copy_select_and_read_sources(
    condition: bool,
    a: MaybeUninit<u8>,
    b: MaybeUninit<u8>,
) -> (u8, u8, u8) {
    mir! {
        type RET = (u8, u8, u8);
        let pointer_a: *const MaybeUninit<u8>;
        let pointer_b: *const MaybeUninit<u8>;
        let selected: MaybeUninit<u8>;
        let selected_value: u8;
        let observed_a: u8;
        let observed_b: u8;

        {
            pointer_a = std::ptr::addr_of!(a);
            pointer_b = std::ptr::addr_of!(b);
            Call(selected = core::intrinsics::select_unpredictable(condition, a, b), ReturnTo(consume_selected), UnwindUnreachable())
        }

        consume_selected = {
            Call(selected_value = consume(Move(selected)), ReturnTo(read_a), UnwindUnreachable())
        }

        read_a = {
            Call(observed_a = read_payload(pointer_a), ReturnTo(read_b), UnwindUnreachable())
        }

        read_b = {
            Call(observed_b = read_payload(pointer_b), ReturnTo(done), UnwindUnreachable())
        }

        done = {
            RET.0 = selected_value;
            RET.1 = observed_a;
            RET.2 = observed_b;
            Return()
        }
    }
}

#[kani::proof]
unsafe fn copy_intrinsic_operands_preserve_both_sources() {
    let condition: bool = kani::any();
    let (selected, source_a, source_b) = unsafe {
        copy_select_and_read_sources(condition, MaybeUninit::new(83), MaybeUninit::new(89))
    };
    kani::assert(
        selected == (if condition { 83 } else { 89 })
            && source_a == 83
            && source_b == 89,
        "Copy sources and selected result retain their values"
    );
    kani::cover!(condition);
    kani::cover!(!condition);
}

#[kani::proof]
unsafe fn true_selected_arm_still_deinitializes_source_a() {
    let (selected, _) = unsafe {
        move_then_read_a(true, MaybeUninit::new(47), MaybeUninit::new(53))
    };
    kani::assert(selected == 47, "true arm selected value is preserved");
}

#[kani::proof]
unsafe fn false_selected_arm_still_deinitializes_source_a() {
    let (selected, _) = unsafe {
        move_then_read_a(false, MaybeUninit::new(59), MaybeUninit::new(61))
    };
    kani::assert(selected == 61, "false arm selected value is preserved");
}

#[kani::proof]
unsafe fn true_selected_arm_still_deinitializes_source_b() {
    let (selected, _) = unsafe {
        move_then_read_b(true, MaybeUninit::new(67), MaybeUninit::new(71))
    };
    kani::assert(selected == 67, "true arm selected value is preserved");
}

#[kani::proof]
unsafe fn false_selected_arm_still_deinitializes_source_b() {
    let (selected, _) = unsafe {
        move_then_read_b(false, MaybeUninit::new(73), MaybeUninit::new(79))
    };
    kani::assert(selected == 79, "false arm selected value is preserved");
}
