// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::mem::{size_of, size_of_val};
use std::ptr;

#[repr(C)]
union Probe {
    pair: (u64, [(); 2]),
    bytes: [u8; 8],
}

#[kani::proof]
fn tuple_first() {
    assert_eq!(size_of::<(u64, [(); 2])>(), 8);
    assert_eq!(size_of::<Probe>(), 8);
    let mut src = Probe { bytes: [0; 8] };
    let mut dst = Probe { bytes: [0; 8] };
    unsafe {
        ptr::write_bytes((&mut src as *mut Probe).cast::<u8>(), 0x5a, size_of::<Probe>());
        ptr::write(&mut dst, ptr::read(&src));
        assert_eq!(dst.pair.0, 0x5a5a5a5a5a5a5a5a);
        assert_eq!(dst.pair.1.len(), 2);
        assert_eq!(size_of_val(&dst.pair.1[1]), 0);
        kani::cover!(
            dst.pair.0 == 0x5a5a5a5a5a5a5a5a && dst.pair.1.len() == 2,
            "tuple_first post-copy data"
        );
    }
}
