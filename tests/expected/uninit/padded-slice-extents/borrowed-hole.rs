// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular --harness borrowed_slice_cross_slot_hole --exact -Z unstable-options --cbmc-args --object-bits 12

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
fn borrowed_slice_cross_slot_hole() {
    let mut slots = [MaybeUninit::<Padded>::uninit(); 2];
    let value_offset = check_layout(&slots);
    let stride = mem::size_of::<Padded>();
    // Initialize slot 0 and the tag, padding, and first three value bytes of slot 1.
    let initialized_prefix = stride + value_offset + mem::size_of::<u32>() - 1;
    unsafe { slots.as_mut_ptr().cast::<u8>().write_bytes(0x5a, initialized_prefix) };
    let borrowed: &[MaybeUninit<Padded>] = &slots;
    let first = unsafe { borrowed.get_unchecked(0) };
    let first_value = unsafe { std::ptr::addr_of!((*first.as_ptr()).value).read_volatile() };
    assert_eq!(first_value, 0x5a5a_5a5a);
    let second = unsafe { borrowed.get_unchecked(1) };
    let crossed_byte = unsafe { second.as_ptr().cast::<u8>().add(value_offset + 2).read_volatile() };
    assert_eq!(crossed_byte, 0x5a);
    let _hole = unsafe { second.as_ptr().cast::<u8>().add(value_offset + 3).read() };
}
