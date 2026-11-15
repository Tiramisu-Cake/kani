// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[inline(never)]
fn select(
    first: MaybeUninit<u16>,
    gap: u32,
    second: MaybeUninit<u16>,
    gap2: u64,
    third: MaybeUninit<u16>,
    which: u8,
) -> MaybeUninit<u16> {
    let _keep_non_shadow_arguments = (gap, gap2);
    match which {
        0 => first,
        1 => second,
        _ => third,
    }
}

#[inline(never)]
fn nested_select(
    first: MaybeUninit<u16>,
    gap: u32,
    second: MaybeUninit<u16>,
    gap2: u64,
    third: MaybeUninit<u16>,
) -> MaybeUninit<u16> {
    select(first, gap, second, gap2, third, 2)
}

#[kani::proof]
fn selected_first_argument_reads_uninit() {
    let value =
        select(MaybeUninit::uninit(), 11, MaybeUninit::new(21), 17, MaybeUninit::new(31), 0);
    let _read = unsafe { value.assume_init() };
}

#[kani::proof]
fn selected_middle_argument_reads_uninit() {
    let value =
        select(MaybeUninit::new(11), 13, MaybeUninit::uninit(), 19, MaybeUninit::new(31), 1);
    let _read = unsafe { value.assume_init() };
}

#[kani::proof]
fn selected_last_argument_reads_uninit() {
    let value =
        select(MaybeUninit::new(11), 13, MaybeUninit::new(21), 19, MaybeUninit::uninit(), 2);
    let _read = unsafe { value.assume_init() };
}

#[kani::proof]
fn nested_same_size_calls_preserve_selected_uninit() {
    let initialized =
        nested_select(MaybeUninit::new(11), 13, MaybeUninit::new(21), 19, MaybeUninit::new(31));
    let _initialized = unsafe { initialized.assume_init() };

    let uninitialized =
        nested_select(MaybeUninit::new(41), 23, MaybeUninit::new(51), 29, MaybeUninit::uninit());
    let _read = unsafe { uninitialized.assume_init() };
}

#[kani::proof]
fn initialized_argument_return_control() {
    let value =
        select(MaybeUninit::new(11), 13, MaybeUninit::uninit(), 19, MaybeUninit::new(31), 0);
    assert_eq!(unsafe { value.assume_init() }, 11);
}

#[kani::proof]
fn repeated_call_unread_uninit_then_initialized_return() {
    let _unread =
        select(MaybeUninit::uninit(), 13, MaybeUninit::new(21), 19, MaybeUninit::new(31), 0);
    let initialized =
        select(MaybeUninit::new(41), 23, MaybeUninit::uninit(), 29, MaybeUninit::new(61), 2);
    assert_eq!(unsafe { initialized.assume_init() }, 61);
}
