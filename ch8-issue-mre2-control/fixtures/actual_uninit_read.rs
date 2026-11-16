// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// True negative control: the same allocation and null handling, with an actual byte read.
use std::alloc::{alloc, dealloc, Layout};

#[kani::proof]
fn actual_uninit_read() {
    let layout = Layout::array::<u8>(2).unwrap();
    unsafe {
        let p = alloc(layout);
        if p.is_null() { return; }
        let _ = std::ptr::read_volatile(p.cast_const());
        dealloc(p, layout);
    }
}
