// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[repr(C)]
struct Bytes {
    a: u8,
    b: u32,
}

fn uninit_read() {
    let bytes = Bytes { a: 7, b: 7 };
    // Offset 1 is padding on the pinned x86_64 target, despite both fields being initialized.
    let ptr = (&raw const bytes).cast::<u8>();
    let _padding = unsafe { ptr.add(1).read() };
}
