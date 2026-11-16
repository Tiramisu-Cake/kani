// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks

use core::mem::MaybeUninit;
use core::ptr::{addr_of, read_volatile};

struct D(u8);

impl Drop for D {
    fn drop(&mut self) {
        unsafe {
            let _ = read_volatile(addr_of!(self.0));
        }
    }
}

#[kani::proof]
fn read_in_drop_of_uninit_slot() {
    let mut a: [MaybeUninit<D>; 2] = [const { MaybeUninit::uninit() }; 2];
    a[0].write(D(1));
    unsafe { core::ptr::drop_in_place(a.as_mut_ptr().cast::<D>().add(1)) };
}
