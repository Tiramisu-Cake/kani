// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=terse

use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
union U {
    word: usize,
    byte: [u8; 8],
}
#[derive(Clone, Copy)]
struct HasUnion {
    marker: usize,
    slots: [MaybeUninit<usize>; 2],
    union: U,
}

enum StorageEnum {
    Empty,
    Full([MaybeUninit<usize>; 2]),
}
struct NestedStorage(MaybeUninit<MaybeUninit<usize>>);
#[derive(Clone, Copy)]
union InnerUnion {
    value: usize,
    bytes: [u8; 8],
}
#[derive(Clone, Copy)]
struct NestedUnionField {
    union: InnerUnion,
}
#[derive(Clone, Copy)]
struct HasNestedUnion {
    marker: usize,
    slots: [MaybeUninit<usize>; 2],
    nested: NestedUnionField,
}

#[kani::proof]
fn arbitrary_union_product_is_unsupported() {
    let value = HasUnion {
        marker: 1,
        slots: [MaybeUninit::new(2), MaybeUninit::uninit()],
        union: U { word: 3 },
    };
    std::hint::black_box(value);
}

#[kani::proof]
fn storage_enum_is_unsupported() {
    let value = StorageEnum::Full([MaybeUninit::new(5), MaybeUninit::uninit()]);
    std::hint::black_box(value);
}

#[kani::proof]
fn nested_maybe_uninit_is_unsupported() {
    let value = NestedStorage(MaybeUninit::uninit());
    std::hint::black_box(value);
}

#[kani::proof]
fn nested_union_product_is_unsupported() {
    let value = HasNestedUnion {
        marker: 7,
        slots: [MaybeUninit::new(11), MaybeUninit::uninit()],
        nested: NestedUnionField { union: InnerUnion { value: 13 } },
    };
    std::hint::black_box(value);
}

#[derive(Clone, Copy)]
struct IndirectProduct {
    marker: usize,
    slot: MaybeUninit<usize>,
}

#[kani::proof]
fn indirect_whole_product_write_is_unsupported() {
    let src = IndirectProduct { marker: 17, slot: MaybeUninit::uninit() };
    let mut dst = IndirectProduct { marker: 19, slot: MaybeUninit::new(23) };
    let address = std::ptr::addr_of_mut!(dst);
    unsafe {
        *address = src;
    }
    std::hint::black_box(dst);
}
