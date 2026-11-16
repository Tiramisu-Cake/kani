// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// kani-flags: -Z uninit-checks

use core::mem::MaybeUninit;

struct D(u8);

impl Drop for D {
    fn drop(&mut self) {}
}

#[kani::proof]
fn drop_initialized_slot() {
    let mut a: [MaybeUninit<D>; 2] = [const { MaybeUninit::uninit() }; 2];
    a[0].write(D(1));
    unsafe { core::ptr::drop_in_place(a.as_mut_ptr().cast::<D>()) };
}
