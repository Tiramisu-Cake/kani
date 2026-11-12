// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::mem::{offset_of, size_of};
use std::ptr;

#[repr(C)]
#[derive(Clone, Copy)]
struct Tail {
    b: u8,
    z: [(); 2],
}

#[repr(C)]
union Probe {
    tail: Tail,
    bytes: [u8; 8],
}

#[kani::proof]
fn tail_first() {
    assert_eq!(size_of::<Tail>(), 1);
    assert_eq!(size_of::<Probe>(), 8);
    assert_eq!(offset_of!(Tail, b), 0);
    assert_eq!(offset_of!(Tail, z), 1);
    let mut src = Probe { bytes: [0; 8] };
    let mut dst = Probe { bytes: [0; 8] };
    unsafe {
        ptr::write_bytes((&mut src as *mut Probe).cast::<u8>(), 0x5a, size_of::<Probe>());
        ptr::write(&mut dst, ptr::read(&src));
        assert_eq!(dst.tail.b, 0x5a);
        assert_eq!(dst.tail.z.len(), 2);
        assert_eq!(std::mem::size_of_val(&dst.tail.z[1]), 0);
        kani::cover!(dst.tail.b == 0x5a && dst.tail.z.len() == 2, "tail_first post-copy data");
    }
}
