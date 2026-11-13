// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn read_reference(value: &MaybeUninit<u8>) -> u8 {
    // The reference is valid even when the MU payload has a hole. Its slot must
    // initialize without making the distinct pointee data initialized.
    let storage = std::ptr::addr_of!(value).cast::<MaybeUninit<&MaybeUninit<u8>>>();
    let copied = unsafe { storage.read().assume_init() };
    kani::cover!(true, "reference body reached payload read");
    unsafe { copied.as_ptr().read() }
}

#[inline(never)]
fn read_raw(value: *const u8) -> u8 {
    let storage = std::ptr::addr_of!(value).cast::<MaybeUninit<*const u8>>();
    let copied = unsafe { storage.read().assume_init() };
    kani::cover!(true, "raw body reached payload read");
    unsafe { copied.read() }
}

#[inline(never)]
fn consume_byte(value: u8) -> u8 {
    let storage = std::ptr::addr_of!(value).cast::<MaybeUninit<u8>>();
    unsafe { storage.read().assume_init() }
}

#[kani::proof]
#[kani::unwind(8)]
fn initialized_payloads() {
    let value = MaybeUninit::new(42u8);
    assert_eq!(read_reference(&value), 42, "reference payload consumed");
    assert_eq!(read_raw(value.as_ptr()), 42, "raw payload consumed");
    assert_eq!(consume_byte(42), 42, "ordinary byte entry consumed");
    kani::cover!(true, "both initialized payload reads returned");
}

#[kani::proof]
#[kani::unwind(8)]
fn reference_slot_preserves_hole() {
    let hole = MaybeUninit::<u8>::uninit();
    let byte = read_reference(&hole);
    kani::cover!(byte == 42, "hole reference result consumed");
}

#[kani::proof]
#[kani::unwind(8)]
fn raw_slot_preserves_hole() {
    let hole = MaybeUninit::<u8>::uninit();
    let byte = read_raw(hole.as_ptr());
    kani::cover!(byte == 42, "hole raw result consumed");
}

#[kani::proof]
#[kani::unwind(8)]
fn entry_does_not_hide_caller_read() {
    let hole = MaybeUninit::<u8>::uninit();
    // The target bad read is here, before a callee entry can seed its own slot.
    // No invalid typed bool/reference is constructed before the target read.
    let byte = consume_byte(unsafe { hole.as_ptr().read() });
    kani::cover!(byte == 42, "caller hole result consumed");
}
