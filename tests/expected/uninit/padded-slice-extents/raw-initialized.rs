// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular --harness raw_slice_cross_slot_initialized --exact -Z unstable-options --cbmc-args --object-bits 12

use std::mem::{self, MaybeUninit};

#[derive(Clone, Copy)]
#[repr(C)]
struct Padded {
    tag: u8,
    value: u32,
}

fn check_layout(slice: &[MaybeUninit<Padded>; 2]) -> usize {
    let value_offset = mem::offset_of!(Padded, value);
    let value_end = value_offset + mem::size_of::<u32>();
    let align = mem::align_of::<Padded>();
    let stride = value_end.div_ceil(align) * align;
    assert_eq!(mem::offset_of!(Padded, tag), 0);
    assert_eq!(value_offset % mem::align_of::<u32>(), 0);
    assert_eq!(mem::align_of::<Padded>(), mem::align_of::<u32>());
    assert_eq!(mem::size_of::<Padded>(), stride);
    assert_eq!(mem::size_of::<MaybeUninit<Padded>>(), stride);
    assert_eq!(mem::size_of_val(slice), 2 * stride);
    value_offset
}

#[kani::proof]
fn raw_slice_cross_slot_initialized() {
    let mut slots = [MaybeUninit::<Padded>::uninit(); 2];
    let value_offset = check_layout(&slots);
    let initialized_prefix = mem::size_of::<Padded>() + value_offset + mem::size_of::<u32>();
    unsafe { slots.as_mut_ptr().cast::<u8>().write_bytes(0x5a, initialized_prefix) };
    let raw_slice = std::ptr::slice_from_raw_parts(slots.as_ptr(), slots.len());
    let borrowed = unsafe { &*raw_slice };
    let second = unsafe { borrowed.get_unchecked(1) };
    let crossed_byte =
        unsafe { second.as_ptr().cast::<u8>().add(value_offset + 2).read_volatile() };
    let byte = unsafe { second.as_ptr().cast::<u8>().add(value_offset + 3).read() };
    assert_eq!(crossed_byte, 0x5a);
    assert_eq!(byte, 0x5a);
}
