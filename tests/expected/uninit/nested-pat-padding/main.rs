// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};
use std::ptr::{self, NonNull};

#[repr(C)]
struct NestedPat {
    prefix: u8,
    pointer: NonNull<[u8]>,
}

#[kani::proof]
fn nested_pat_does_not_initialize_prefix_padding() {
    assert_eq!(mem::offset_of!(NestedPat, pointer), 8);
    assert_eq!(mem::size_of::<NestedPat>(), 24);
    let mut bytes = [7_u8; 3];
    let pointer = NonNull::from(&mut bytes[..]);
    let mut source = MaybeUninit::<NestedPat>::uninit();
    unsafe {
        source.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 24);
        ptr::addr_of_mut!((*source.as_mut_ptr()).pointer).write(pointer);
    }
    let destination = source;
    unsafe {
        assert_eq!((*destination.as_ptr()).prefix, 0x5a);
        assert_eq!(ptr::addr_of!((*destination.as_ptr()).pointer).read().len(), 3);
    }
    // Byte 1 is outside the Pat at offset 8. Typed copying discards this padding,
    // even though the source byte was physically initialized before the copy.
    assert_eq!(unsafe { destination.as_ptr().cast::<u8>().add(1).read() }, 0x5a);
}
