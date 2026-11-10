// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, ManuallyDrop, MaybeUninit};
use std::ptr;

#[repr(C)]
struct Padded {
    tag: u8,
    value: u64,
}

#[kani::proof]
fn assume_init_after_write() {
    let mut slot = MaybeUninit::<u8>::uninit();
    slot.write(7);
    assert_eq!(unsafe { slot.assume_init() }, 7);
}

#[inline(never)]
fn carry(slot: MaybeUninit<u8>) -> MaybeUninit<u8> {
    slot
}

#[kani::proof]
fn raw_read_after_write() {
    let mut slot = MaybeUninit::<u8>::uninit();
    let raw = ptr::addr_of_mut!(slot);
    unsafe {
        *raw = MaybeUninit::new(7);
        assert_eq!(carry(raw.read()).assume_init_read(), 7);
    }
}

#[kani::proof]
fn padded_and_manually_drop_transmute() {
    let mut slot = MaybeUninit::<Padded>::uninit();
    let ptr = slot.as_mut_ptr();
    unsafe {
        ptr::addr_of_mut!((*ptr).tag).write(7);
        ptr::addr_of_mut!((*ptr).value).write(9);
        let wrapped: ManuallyDrop<Padded> = mem::transmute(slot);
        let value = ManuallyDrop::into_inner(wrapped);
        assert_eq!((value.tag, value.value), (7, 9));
    }
}

#[kani::proof]
fn partial_copy_preserves_written_byte() {
    let mut from = [MaybeUninit::<[u8; 4]>::uninit(); 2];
    let mut to = [MaybeUninit::new([9; 4]); 2];
    unsafe {
        from[1].as_mut_ptr().cast::<u8>().write(7);
        ptr::copy_nonoverlapping(from.as_ptr().add(1), to.as_mut_ptr(), 1);
        assert_eq!(to[0].as_ptr().cast::<u8>().read(), 7);
        assert_eq!(to[1].assume_init(), [9; 4]);
    }
}

#[kani::proof]
fn slice_offset_and_reinitialization() {
    let mut slots = [MaybeUninit::new(9u64); 2];
    let slice: &mut [MaybeUninit<u64>] = &mut slots;
    let raw = ptr::addr_of_mut!(*slice);
    unsafe {
        (*raw)[1] = MaybeUninit::uninit();
        (*raw)[1].as_mut_ptr().write(7);
        assert_eq!((*raw)[0].assume_init(), 9);
        assert_eq!((*raw)[1].assume_init(), 7);
    }
}

#[kani::proof]
fn array_value_as_used_by_merge_output() {
    let mut slot = MaybeUninit::<[u8; 4]>::uninit();
    let data = slot.as_mut_ptr().cast::<u8>();
    unsafe {
        data.write(1);
        data.add(1).write(2);
        data.add(2).write(3);
        data.add(3).write(4);
        assert_eq!(slot.assume_init(), [1, 2, 3, 4]);
    }
}
