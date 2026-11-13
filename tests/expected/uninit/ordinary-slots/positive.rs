// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn scalar_slot(initialized: bool) -> bool {
    // Consume the parameter BEFORE taking its address. The local pointer pass
    // can initialize addressed ordinary storage later; it cannot repair this read.
    kani::cover!(initialized, "true scalar entry read before address");
    kani::cover!(!initialized, "false scalar entry read before address");
    // The changed-pointee cast selects the parameter's storage for tracking.
    // Reading it as MU is legal; its payload is an already valid bool value.
    let storage = std::ptr::addr_of!(initialized).cast::<MaybeUninit<bool>>();
    let copied = unsafe { storage.read().assume_init() };
    assert_eq!(copied, initialized, "scalar parameter slot read");
    copied
}

#[inline(never)]
fn reference_identity(value: &bool) -> &bool {
    value
}

#[inline(never)]
fn reference_slot(value: &bool) -> &bool {
    // This by-value reference operand read also precedes the address setter.
    let before_address = reference_identity(value);
    let storage = std::ptr::addr_of!(value).cast::<MaybeUninit<&bool>>();
    let copied = unsafe { storage.read().assume_init() };
    assert_eq!(*copied, *before_address, "reference parameter slot read");
    copied
}

// No Copy implementation: moving this wrapper also exercises an ordinary
// aggregate argument/return with padding, independently of closure layout.
#[repr(C)]
struct RefWrapper<'a> {
    tag: u8,
    value: &'a bool,
}

#[inline(never)]
fn move_wrapper(value: RefWrapper<'_>) -> RefWrapper<'_> {
    assert!(value.tag == 7, "wrapper entry data read before address");
    let storage = std::ptr::addr_of!(value).cast::<MaybeUninit<RefWrapper<'_>>>();
    let moved = unsafe { storage.read().assume_init() };
    assert_eq!(moved.tag, 7, "wrapper data read");
    moved
}

#[kani::proof]
#[kani::unwind(8)]
fn scalar_parameters_true_false() {
    let yes = scalar_slot(true);
    let no = scalar_slot(false);
    assert!(yes && !no, "scalar normal returns consumed");
    kani::cover!(yes && !no, "true and false scalar slots reached");
}

#[kani::proof]
#[kani::unwind(8)]
fn reference_copy_move_return() {
    let yes = true;
    let no = false;
    let copied = reference_slot(&yes);
    let moved = move_wrapper(RefWrapper { tag: 7, value: reference_slot(&no) });
    assert!(*copied && !*moved.value, "reference normal returns consumed");
    kani::cover!(*copied && !*moved.value, "reference copy and wrapper move reached");
}

// Both generated body and ensures environments have zero upvars. All scalar/ref
// slot work happens in ordinary helpers, isolating CC2 from nonzero layout CC3.
#[kani::ensures(|result: &bool| *result)]
fn capture_free_slots() -> bool {
    let yes = scalar_slot(true);
    let no = scalar_slot(false);
    let copied = reference_slot(&yes);
    let moved = move_wrapper(RefWrapper { tag: 7, value: reference_slot(&no) });
    *copied && !*moved.value
}

#[kani::proof]
#[kani::unwind(8)]
fn capture_free_ordinary() {
    assert!(capture_free_slots(), "ordinary slot body and return reached");
    kani::cover!(true, "ordinary capture-free slots consumed");
}

#[kani::proof_for_contract(capture_free_slots)]
#[kani::unwind(8)]
fn capture_free_simple_check() {
    assert!(capture_free_slots(), "SimpleCheck slot body and return reached");
    kani::cover!(true, "SimpleCheck capture-free slots consumed");
}
