// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[repr(C)]
#[allow(dead_code)] // The fields define initialized bytes; the read uses the union address.
union Bytes {
    first: u8,
    all: [u8; 4],
}

fn initialized_read() {
    let bytes = Bytes { all: [7; 4] };
    // Read the last byte: a fixed zero-offset witness would miss this hole.
    let ptr = (&raw const bytes).cast::<u8>();
    let _last = unsafe { ptr.add(3).read() };
}
