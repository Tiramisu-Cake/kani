// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn select(a: MaybeUninit<u8>, b: MaybeUninit<u8>, first: bool) -> MaybeUninit<u8> {
    if first { a } else { b }
}

// Borrow the entire capture, preventing field-only capture in these controls.
#[inline(never)]
fn touch<T>(_: &T) {}

// The typed raw read explicitly requests the closure's own initialization mask.
// Copy excludes duplicating an exclusive reference or an owned destructor.
#[inline(never)]
fn copy_and_call<F: Copy + Fn(&MaybeUninit<u8>) -> bool>(
    callback: F,
    payload: &MaybeUninit<u8>,
) -> bool {
    let copied = unsafe { std::ptr::read(std::ptr::addr_of!(callback)) };
    copied(payload)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Padded(u32, u8);

#[kani::proof]
fn capture_padded() {
    let payload = select(MaybeUninit::new(17), MaybeUninit::uninit(), true);
    let capture = Padded(7, 3);
    let callback = move |value: &MaybeUninit<u8>| {
        touch(&capture);
        touch(&capture.0);
        touch(&capture.1);
        unsafe { value.assume_init_read() == 17 }
    };
    assert!(std::mem::size_of_val(&callback) > 0);
    assert!(copy_and_call(callback, &payload));
}
