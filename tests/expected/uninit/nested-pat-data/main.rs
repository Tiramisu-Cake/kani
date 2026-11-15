// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};
use std::ptr::{self, NonNull};

// NonNull<[u8]> contains a wide-pointer RigidTy::Pat, whose layout is arbitrary,
// so this exercises the recursive Pat branch rather than the scalar shortcut.
#[repr(C)]
struct NestedPat {
    prefix: u8,
    pointer: NonNull<[u8]>,
}

#[kani::proof]
fn nested_pat_preserves_data_at_nonzero_offset() {
    assert_eq!(mem::offset_of!(NestedPat, pointer), 8);
    assert_eq!(mem::size_of::<NestedPat>(), 24);
    let mut bytes = [7_u8; 3];
    let pointer = NonNull::from(&mut bytes[..]);
    let mut source = MaybeUninit::<NestedPat>::uninit();
    unsafe {
        ptr::addr_of_mut!((*source.as_mut_ptr()).prefix).write(11);
        ptr::addr_of_mut!((*source.as_mut_ptr()).pointer).write(pointer);
    }
    let destination = source;
    unsafe {
        assert_eq!((*destination.as_ptr()).prefix, 11);
        let actual = ptr::addr_of!((*destination.as_ptr()).pointer).read();
        assert_eq!(actual.len(), 3);
        assert_eq!(actual.as_ptr().cast::<u8>(), pointer.as_ptr().cast::<u8>());
    }
}
