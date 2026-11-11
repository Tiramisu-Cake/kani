// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};
use std::ptr;

#[kani::proof]
fn typed_source_read_still_checked() {
    let uninitialized = MaybeUninit::<u64>::uninit();
    let mut source = 9u64;
    unsafe {
        // Poison the already typed local using an untyped copy. Delayed UB must
        // reject its typed read even when the transmute destination allows uninit.
        ptr::copy_nonoverlapping(
            ptr::addr_of!(uninitialized),
            ptr::addr_of_mut!(source).cast::<MaybeUninit<u64>>(),
            1,
        );
        let destination: MaybeUninit<u64> = mem::transmute(source);
        // Do not read the slot: only the typed source read should fail.
        std::hint::black_box(ptr::addr_of!(destination));
    }
}
