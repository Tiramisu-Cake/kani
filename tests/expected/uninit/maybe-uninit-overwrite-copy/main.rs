// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular
use std::{mem::MaybeUninit, ptr};
#[kani::proof]
fn overwrite_copy() {
    let mut src = MaybeUninit::<[u8; 2]>::uninit();
    let mut dst = MaybeUninit::new([9u8; 2]);
    unsafe {
        src.as_mut_ptr().cast::<u8>().write(7);
        ptr::copy_nonoverlapping(ptr::addr_of!(src), ptr::addr_of_mut!(dst), 1);
        let _value = dst.assume_init();
    }
}
