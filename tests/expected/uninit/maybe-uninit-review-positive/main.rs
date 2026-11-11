// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::{
    mem::{self, ManuallyDrop, MaybeUninit},
    ptr,
};

#[kani::proof]
fn overwrite_copy_written_byte() {
    let mut src = MaybeUninit::<[u8; 2]>::uninit();
    let mut dst = MaybeUninit::new([9u8; 2]);
    unsafe {
        src.as_mut_ptr().cast::<u8>().write(7);
        ptr::copy_nonoverlapping(ptr::addr_of!(src), ptr::addr_of_mut!(dst), 1);
        // The other byte remains uninitialized after replacing dst.
        assert_eq!(dst.as_ptr().cast::<u8>().read(), 7);
    }
}

#[kani::proof]
fn overlap_copy_right_written_slot() {
    let mut slots = [MaybeUninit::new(1u8), MaybeUninit::uninit(), MaybeUninit::new(3)];
    let p = slots.as_mut_ptr();
    unsafe {
        ptr::copy(p, p.add(1), 2);
        // Original slot 0 was copied into slot 1.
        assert_eq!(slots[1].assume_init(), 1);
    }
}

#[kani::proof]
fn overlap_copy_left_written_slot() {
    let mut slots = [MaybeUninit::new(1u8), MaybeUninit::uninit(), MaybeUninit::new(3)];
    let p = slots.as_mut_ptr();
    unsafe {
        ptr::copy(p.add(1), p, 2);
        // Original slot 2 was copied into slot 1.
        assert_eq!(slots[1].assume_init(), 3);
    }
}

#[kani::proof]
fn repeat_local_initialized_source() {
    let mut source = MaybeUninit::<u64>::uninit();
    let mut slots = [MaybeUninit::new(9u64); 3];
    unsafe {
        ptr::addr_of_mut!(source).write(MaybeUninit::new(7));
    }
    slots = [source; 3];
    assert_eq!(unsafe { slots[2].assume_init() }, 7);
}

#[kani::proof]
fn reset_after_zst_then_initialize() {
    let empty = [MaybeUninit::<()>::uninit(); 3];
    unsafe {
        empty[2].assume_init();
    }
    let mut slot = MaybeUninit::new(9u64);
    unsafe {
        let raw = ptr::addr_of_mut!(slot);
        raw.write(MaybeUninit::uninit());
        (*raw).as_mut_ptr().write(7);
        assert_eq!(slot.assume_init(), 7);
    }
}

#[repr(C)]
struct Padded {
    a: u8,
    b: u64,
}

#[kani::proof]
fn complete_padded_transmute() {
    let mut slot = MaybeUninit::<Padded>::uninit();
    unsafe {
        ptr::addr_of_mut!((*slot.as_mut_ptr()).a).write(7);
        ptr::addr_of_mut!((*slot.as_mut_ptr()).b).write(9);
        // Initialize both fields, leaving repr(C) padding uninitialized.
        let wrapped: ManuallyDrop<Padded> = mem::transmute(slot);
        let value = ManuallyDrop::into_inner(wrapped);
        assert_eq!((value.a, value.b), (7, 9));
    }
}

#[inline(never)]
fn select(a: MaybeUninit<u16>, b: MaybeUninit<u16>, first: bool) -> MaybeUninit<u16> {
    if first { a } else { b }
}

#[kani::proof]
fn argument_return_both_initialized() {
    let first: bool = kani::any();
    let value = select(MaybeUninit::new(9), MaybeUninit::new(7), first);
    assert_eq!(unsafe { value.assume_init() }, if first { 9 } else { 7 });
}
