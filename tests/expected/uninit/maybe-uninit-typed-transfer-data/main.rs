// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::{self, MaybeUninit};

#[derive(Clone, Copy)]
#[repr(C)]
struct Padded {
    tag: u8,
    value: u32,
}

fn check_layout() {
    assert_eq!(mem::offset_of!(Padded, tag), 0);
    assert_eq!(mem::offset_of!(Padded, value), 4);
    assert_eq!(mem::size_of::<Padded>(), 8);
    assert_eq!(mem::size_of::<MaybeUninit<Padded>>(), 8);
}

#[kani::proof]
fn raw_nonoverlapping_copy_preserves_padding() {
    check_layout();
    let mut source = MaybeUninit::<Padded>::uninit();
    unsafe { source.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 8) };
    let mut destination = MaybeUninit::<Padded>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(&source, &mut destination, 1);
        assert_eq!(destination.as_ptr().cast::<u8>().add(1).read(), 0x5a);
    }
}

#[kani::proof]
fn raw_copy_preserves_padding() {
    check_layout();
    let mut source = MaybeUninit::<Padded>::uninit();
    unsafe { source.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 8) };
    let mut destination = MaybeUninit::<Padded>::uninit();
    unsafe {
        std::ptr::copy(&source, &mut destination, 1);
        assert_eq!(destination.as_ptr().cast::<u8>().add(3).read(), 0x5a);
    }
}

#[kani::proof]
fn typed_assignment_preserves_data() {
    check_layout();
    let mut source = MaybeUninit::<Padded>::uninit();
    unsafe { source.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 8) };
    let destination = source;
    unsafe {
        assert_eq!((*destination.as_ptr()).tag, 0x5a);
        assert_eq!((*destination.as_ptr()).value, 0x5a5a5a5a);
    }
}

#[inline(never)]
fn roundtrip(slot: MaybeUninit<Padded>) -> MaybeUninit<Padded> {
    assert_eq!(unsafe { (*slot.as_ptr()).value }, 0x5a5a5a5a);
    slot
}

#[kani::proof]
fn typed_argument_return_preserves_data() {
    check_layout();
    let mut source = MaybeUninit::<Padded>::uninit();
    unsafe { source.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 8) };
    let destination = roundtrip(source);
    unsafe {
        assert_eq!((*destination.as_ptr()).tag, 0x5a);
        assert_eq!((*destination.as_ptr()).value, 0x5a5a5a5a);
    }
}

#[kani::proof]
fn typed_array_preserves_data() {
    check_layout();
    let mut source = [MaybeUninit::<Padded>::uninit(); 2];
    assert_eq!(mem::size_of_val(&source), 16);
    unsafe {
        assert_eq!(
            source.as_ptr().add(1).cast::<u8>().offset_from(source.as_ptr().cast::<u8>()),
            8
        );
        source.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 16);
    }
    let destination = source;
    unsafe {
        assert_eq!((*destination[0].as_ptr()).tag, 0x5a);
        assert_eq!((*destination[0].as_ptr()).value, 0x5a5a5a5a);
        assert_eq!((*destination[1].as_ptr()).tag, 0x5a);
        assert_eq!((*destination[1].as_ptr()).value, 0x5a5a5a5a);
    }
}

#[kani::proof]
fn raw_array_copy_preserves_second_slot_padding() {
    check_layout();
    let mut source = [MaybeUninit::<Padded>::uninit(); 2];
    assert_eq!(mem::size_of_val(&source), 16);
    unsafe {
        assert_eq!(
            source.as_ptr().add(1).cast::<u8>().offset_from(source.as_ptr().cast::<u8>()),
            8
        );
        source.as_mut_ptr().cast::<u8>().write_bytes(0x5a, 16);
    }
    let mut destination = [MaybeUninit::<Padded>::uninit(); 2];
    unsafe {
        std::ptr::copy_nonoverlapping(source.as_ptr(), destination.as_mut_ptr(), 2);
        assert_eq!(destination[0].as_ptr().cast::<u8>().add(1).read(), 0x5a);
        assert_eq!(destination[1].as_ptr().cast::<u8>().add(1).read(), 0x5a);
    }
}
