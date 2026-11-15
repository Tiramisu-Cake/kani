// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[inline(never)]
unsafe fn write_bytes(out: *mut u8, full: bool) {
    unsafe {
        out.write(11);
        out.add(2).write(33);
        if full {
            out.add(1).write(22);
        }
    }
}

#[kani::proof]
fn out_pointer_fully_written() {
    let mut slot = MaybeUninit::<[u8; 3]>::uninit();
    unsafe { write_bytes(slot.as_mut_ptr().cast::<u8>(), true) };
    let value = unsafe { slot.assume_init() };
    assert_eq!(value[0], 11);
    assert_eq!(value[1], 22);
    assert_eq!(value[2], 33);
}

#[kani::proof]
fn out_pointer_preserves_middle_hole() {
    let mut slot = MaybeUninit::<[u8; 3]>::uninit();
    let data = slot.as_mut_ptr().cast::<u8>();
    unsafe {
        write_bytes(data, false);
        assert_eq!(data.read(), 11);
        assert_eq!(data.add(2).read(), 33);
        // No typed [u8; 3] or reference to uninitialized u8 precedes this read.
        let _hole = data.add(1).read();
    }
}
