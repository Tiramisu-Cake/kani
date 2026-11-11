// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::mem::ManuallyDrop;
use std::num::NonZeroU32;
use std::ptr;

#[derive(Clone, Copy)]
union U {
    wide: u32,
    small: u8,
}
#[derive(Clone, Copy)]
struct HasUnion {
    value: U,
}
#[derive(Clone, Copy)]
union Outer {
    inner: U,
    wide: u32,
}
#[derive(Clone, Copy)]
struct Padded {
    byte: u8,
    word: u32,
}
#[derive(Clone, Copy)]
union PaddedUnion {
    value: ManuallyDrop<Padded>,
    wide: u64,
}
#[derive(Clone, Copy)]
enum Niche {
    Empty,
    Some(NonZeroU32),
}
#[derive(Clone, Copy)]
#[repr(u8)]
enum DifferentPadding {
    Padded(Padded),
    Byte(u8),
}
#[derive(Clone, Copy)]
union NicheUnion {
    value: Niche,
    wide: u32,
}
#[derive(Clone, Copy)]
union DifferentPaddingUnion {
    value: DifferentPadding,
    wide: u64,
}
#[derive(Clone, Copy)]
union FunctionPointerUnion {
    value: fn() -> u32,
    wide: u32,
}

#[inline(never)]
fn indirect_target(x: U) -> U {
    x
}

unsafe extern "Rust" {
    fn bodyless_union_transfer(value: U) -> U;
    fn bodyless_union_return() -> U;
    fn foreign_mutate_union(value: *mut U);
    fn foreign_mutate_erased(pointer: *mut u8);
}
