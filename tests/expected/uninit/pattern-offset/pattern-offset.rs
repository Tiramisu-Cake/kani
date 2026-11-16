// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// kani-flags: -Z uninit-checks --output-format=regular

use std::alloc::{alloc, dealloc, Layout};
use std::ptr::{addr_of_mut, NonNull};

#[repr(C)]
struct PrefixAndPointer {
    prefix: u64,
    pointer: NonNull<u8>,
}

#[kani::proof]
fn read_requires_nonnull_at_nonzero_offset() {
    let layout = Layout::new::<PrefixAndPointer>();
    assert_eq!(std::mem::offset_of!(PrefixAndPointer, pointer), 8);
    unsafe {
        let allocation = alloc(layout).cast::<PrefixAndPointer>();
        kani::assume(!allocation.is_null());
        addr_of_mut!((*allocation).prefix).write(1);
        let _value = allocation.read();
        dealloc(allocation.cast(), layout);
    }
}
