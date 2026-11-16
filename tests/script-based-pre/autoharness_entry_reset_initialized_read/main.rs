// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[repr(C)]
struct Bytes {
    a: u8,
    b: u32,
}

fn initialized_read() {
    let mut bytes = Bytes { a: 7, b: 7 };
    let ptr = (&raw mut bytes).cast::<u8>();
    // Initialize the same padding byte in place; do not move the struct before reading it.
    unsafe { ptr.add(1).write(7) };
    let _padding = unsafe { ptr.add(1).read() };
}
