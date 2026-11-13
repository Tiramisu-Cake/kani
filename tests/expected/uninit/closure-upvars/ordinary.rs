// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn touch<T>(_: &T) {}

#[inline(never)]
fn copy_call<F: Copy + Fn() -> bool>(callback: F) -> bool {
    // Actual typed closure read: the layout request must be reached in CI.
    let copied = unsafe { std::ptr::addr_of!(callback).read() };
    copied()
}

#[inline(never)]
fn captured_bool(flag: bool) -> bool {
    let callback = move || {
        touch(&flag);
        kani::cover!(true, "bool capture body reached");
        flag
    };
    assert!(std::mem::size_of_val(&callback) > 0);
    copy_call(callback)
}

#[kani::proof]
#[kani::unwind(8)]
fn bool_captures_true_false() {
    assert!(captured_bool(true), "true captured bool consumed");
    assert!(!captured_bool(false), "false captured bool consumed");
    kani::cover!(true, "both bool captures consumed");
}

#[inline(never)]
fn payload_is_17(value: &MaybeUninit<u8>) -> bool {
    unsafe { value.assume_init_read() == 17 }
}

#[kani::requires(!initialized || payload_is_17(&value))]
#[kani::ensures(|result: &MaybeUninit<u8>| !initialized || payload_is_17(result))]
fn captured_contract(value: MaybeUninit<u8>, initialized: bool) -> MaybeUninit<u8> {
    // The ensures environment captures &initialized: the residual CC2 &bool slot.
    value
}

fn exercise_contract(initialized: bool) {
    let value = if initialized { MaybeUninit::new(17) } else { MaybeUninit::uninit() };
    let result = captured_contract(value, initialized);
    if initialized {
        assert!(payload_is_17(&result), "captured contract initialized result read");
        kani::cover!(true, "captured contract true result consumed");
    } else {
        kani::cover!(true, "captured contract false storage returned");
    }
}

#[kani::proof]
#[kani::unwind(8)]
fn ordinary_captured_contract() {
    exercise_contract(kani::any());
}

#[kani::proof_for_contract(captured_contract)]
#[kani::unwind(8)]
fn simple_check_captured_contract() {
    exercise_contract(kani::any());
}
