// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=terse

use std::mem::MaybeUninit;
use std::ptr;
#[repr(C)]
struct Pad {
    byte: u8,
    word: u32,
}
#[inline(never)]
fn consume(value: Pad) -> u32 {
    value.word
}
#[inline(never)]
fn poison_in_callee(mut value: Pad) -> u32 {
    unsafe {
        ptr::copy_nonoverlapping(
            (&value as *const Pad).cast::<u8>().add(1),
            ptr::addr_of_mut!(value.word).cast::<u8>(),
            1,
        );
    }
    kani::cover!(true);
    value.word
}
#[kani::proof]
fn ordinary_parameter_seed_does_not_hide_caller_poison() {
    let mut value = Pad { byte: 7, word: 11 };
    unsafe {
        ptr::copy_nonoverlapping(
            (&value as *const Pad).cast::<u8>().add(1),
            ptr::addr_of_mut!(value.word).cast::<u8>(),
            1,
        );
    }
    kani::cover!(true);
    std::hint::black_box(consume(value));
}
#[kani::proof]
fn ordinary_parameter_seed_does_not_hide_callee_poison() {
    std::hint::black_box(poison_in_callee(Pad { byte: 7, word: 11 }));
}
#[inline(never)]
unsafe fn read_pointee(pointer: *const u32) -> u32 {
    unsafe { *pointer }
}
#[kani::proof]
fn pointer_parameter_seed_does_not_initialize_pointee() {
    let value = MaybeUninit::<u32>::uninit();
    kani::cover!(true);
    std::hint::black_box(unsafe { read_pointee(value.as_ptr()) });
}
