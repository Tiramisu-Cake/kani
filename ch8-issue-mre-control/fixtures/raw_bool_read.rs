// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
#[kani::proof]
fn raw_bool_read() {
    let byte = 2u8;
    let mut dst = core::mem::MaybeUninit::<bool>::uninit();
    unsafe {
        core::ptr::copy_nonoverlapping(
            (&byte as *const u8).cast::<bool>(), dst.as_mut_ptr(), 1);
        let value = core::ptr::read_volatile(dst.as_ptr());
        assert!(value);
    }
}
