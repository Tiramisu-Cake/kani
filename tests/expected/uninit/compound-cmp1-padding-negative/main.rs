// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=terse

use std::mem::MaybeUninit;
use std::ptr;

#[repr(C)]
#[derive(Clone, Copy)]
struct Pad {
    byte: u8,
    word: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct C<T> {
    marker: T,
    slots: [MaybeUninit<usize>; 2],
}

fn complete_value() -> C<Pad> {
    C { marker: Pad { byte: 7, word: 11 }, slots: [MaybeUninit::new(13), MaybeUninit::new(17)] }
}

// Copy an uninitialized padding byte from an ordinary, initialized Pad into
// one byte of the ordinary word field. The storage leaves stay initialized.
unsafe fn poison_one_word_byte(value: &mut C<Pad>) {
    let pad_start = ptr::addr_of!(value.marker).cast::<u8>();
    let word_start = ptr::addr_of_mut!(value.marker.word).cast::<u8>();
    ptr::copy_nonoverlapping(pad_start.add(1), word_start, 1);
}

#[kani::proof]
fn partial_ordinary_field_cannot_be_read_as_whole_product_after_copy() {
    let mut source = complete_value();
    assert_eq!(unsafe { source.slots[0].assume_init() }, 13);
    assert_eq!(unsafe { source.slots[1].assume_init() }, 17);
    unsafe {
        poison_one_word_byte(&mut source);
    }
    kani::cover!(true);
    let copy = source;
    #[inline(never)]
    fn consume(value: C<Pad>) -> u8 {
        value.marker.byte
    }
    std::hint::black_box(consume(copy));
}

#[kani::proof]
fn partial_ordinary_field_read_remains_checked_after_call_copy() {
    #[inline(never)]
    fn id(value: C<Pad>) -> C<Pad> {
        value
    }
    let mut returned = id(complete_value());
    unsafe {
        poison_one_word_byte(&mut returned);
    }
    assert_eq!(unsafe { returned.slots[0].assume_init() }, 13);
    assert_eq!(unsafe { returned.slots[1].assume_init() }, 17);
    kani::cover!(true);
    let word = returned.marker.word;
    std::hint::black_box(word);
}

#[kani::proof]
fn padding_byte_stays_uninitialized_after_typed_copy() {
    let source = complete_value();
    let copy = source;
    assert_eq!(copy.marker.byte, 7);
    assert_eq!(copy.marker.word, 11);
    assert_eq!(unsafe { copy.slots[0].assume_init() }, 13);
    kani::cover!(true);
    let padding = unsafe { ptr::addr_of!(copy.marker).cast::<u8>().add(1).read() };
    std::hint::black_box(padding);
}

#[kani::proof]
fn padding_stays_uninitialized_after_call_return() {
    #[inline(never)]
    fn id(value: C<Pad>) -> C<Pad> {
        value
    }
    let returned = id(complete_value());
    assert_eq!(returned.marker.byte, 7);
    assert_eq!(returned.marker.word, 11);
    kani::cover!(true);
    let padding = unsafe { ptr::addr_of!(returned.marker).cast::<u8>().add(1).read() };
    std::hint::black_box(padding);
}

#[kani::proof]
fn ordinary_operand_aggregate_preserves_typed_source_checks() {
    let mut marker = Pad { byte: 31, word: 37 };
    unsafe {
        let padding = ptr::addr_of!(marker).cast::<u8>().add(1);
        let ordinary = ptr::addr_of_mut!(marker.word).cast::<u8>();
        ptr::copy_nonoverlapping(padding, ordinary, 1);
    }
    let slots = [MaybeUninit::new(41), MaybeUninit::new(43)];
    kani::cover!(true);
    let value = C { marker, slots };
    std::hint::black_box(value.marker.word);
}
