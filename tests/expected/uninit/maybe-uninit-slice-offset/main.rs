// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};
use std::ptr;

#[kani::proof]
fn slice_write_leaves_neighbor_empty() {
    let mut slots = [MaybeUninit::<u64>::uninit(); 2];
    let slice: &mut [MaybeUninit<u64>] = &mut slots;
    let raw = ptr::addr_of_mut!(*slice);
    unsafe {
        (*raw)[1].as_mut_ptr().write(7);
        assert_eq!((*raw)[1].assume_init(), 7);
        let neighbor: u64 = mem::transmute((*raw)[0]);
        assert_eq!(neighbor, 9);
    }
}
