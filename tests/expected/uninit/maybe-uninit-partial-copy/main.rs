// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};
use std::ptr;

#[kani::proof]
fn copy_replaces_initialized_bytes() {
    let mut from = [MaybeUninit::<[u8; 4]>::uninit(); 2];
    let mut to = [MaybeUninit::new([9; 4]); 2];
    unsafe {
        from[1].as_mut_ptr().cast::<u8>().write(7);
        ptr::copy_nonoverlapping(from.as_ptr().add(1), to.as_mut_ptr(), 1);
        let data = to[0].as_ptr().cast::<u8>();
        assert_eq!(data.read(), 7);
        assert_eq!(to[1].assume_init(), [9; 4]);
        let wide: [u8; 4] = mem::transmute(to[0]);
        assert_eq!(wide, [7, 9, 9, 9]);
    }
}
