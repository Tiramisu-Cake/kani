// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[repr(C)]
struct Padded(u32, u8);

pub fn read_data() -> u8 {
    let value = Padded(0, 0);
    unsafe { *std::ptr::addr_of!(value).cast::<u8>() }
}

pub fn read_padding() -> u8 {
    let value = Padded(0, 0);
    unsafe { *std::ptr::addr_of!(value).cast::<u8>().add(5) }
}
