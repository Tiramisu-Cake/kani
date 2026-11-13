// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn touch<T>(_: &T) {}

#[inline(never)]
fn copy_call<F: Copy + Fn() -> u8>(callback: F) -> u8 {
    let copied = unsafe { std::ptr::addr_of!(callback).read() };
    copied()
}

#[inline(never)]
fn two_refs(initialized: bool) -> u8 {
    let flag = true;
    let data = if initialized { MaybeUninit::new(17u8) } else { MaybeUninit::uninit() };
    let enabled = &flag;
    let payload = &data;
    let callback = move || {
        touch(&enabled);
        touch(&payload);
        assert!(*enabled, "initialized bool referent consumed");
        kani::cover!(true, "two-ref body reached payload read");
        // Both references are valid; the target bad read is the MU byte only.
        unsafe { payload.as_ptr().read() }
    };
    assert!(std::mem::size_of_val(&callback) > 0);
    copy_call(callback)
}

#[kani::proof]
#[kani::unwind(8)]
fn two_refs_initialized() {
    assert_eq!(two_refs(true), 17, "two-ref initialized payload consumed");
    kani::cover!(true, "two-ref initialized return reached");
}

#[kani::proof]
#[kani::unwind(8)]
fn two_refs_preserve_hole() {
    let byte = two_refs(false);
    kani::cover!(byte == 17, "two-ref hole result consumed");
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Padded {
    byte: u8,
    word: u32,
}

#[inline(never)]
fn read_closure_padding<F: Copy + Fn() -> *const u8>(callback: F) -> u8 {
    let copied = unsafe { std::ptr::addr_of!(callback).read() };
    let padding = copied();
    // copied remains alive: padding points inside its captured Padded field.
    kani::cover!(true, "closure padding byte read reached");
    unsafe { padding.read() }
}

#[kani::proof]
#[kani::unwind(8)]
fn capture_padding_stays_false() {
    let mut storage = MaybeUninit::<Padded>::uninit();
    let ptr = storage.as_mut_ptr();
    unsafe {
        std::ptr::addr_of_mut!((*ptr).byte).write(7);
        std::ptr::addr_of_mut!((*ptr).word).write(42);
    }
    let capture = unsafe { storage.assume_init() };
    let callback = move || {
        touch(&capture);
        // repr(C) offset 1 is padding, irrespective of the closure field offset.
        std::ptr::addr_of!(capture).cast::<u8>().wrapping_add(1)
    };
    assert!(std::mem::size_of_val(&callback) > 0);
    let byte = read_closure_padding(callback);
    kani::cover!(byte == 0, "closure padding result consumed");
}
