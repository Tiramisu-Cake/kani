// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// This test exceeds the CI memory limit with 16 object bits because of the
// contract write-set tables. Reducing the number of object bits to 12.
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn select(a: MaybeUninit<u8>, b: MaybeUninit<u8>, first: bool) -> MaybeUninit<u8> {
    if first { a } else { b }
}

#[kani::modifies(out)]
#[kani::ensures(|result: &u8| *result == 7 && *out == [1, 2, 3])]
fn write_initialized(out: &mut [u8; 3]) -> u8 {
    // Only the true arm is the initialized conditional-return control.
    let selected = select(MaybeUninit::new(7), MaybeUninit::uninit(), true);
    let byte = unsafe { selected.assume_init() };
    assert_eq!(byte, 7);

    let mut slot = MaybeUninit::<[u8; 3]>::uninit();
    let data = slot.as_mut_ptr().cast::<u8>();
    unsafe {
        data.write(1);
        data.add(1).write(2);
        data.add(2).write(3);
    }
    let value = unsafe { slot.assume_init() };
    // The RHS must bind to an anonymous immutable allocation in emitted MIR.
    assert_eq!(value, [1, 2, 3]);
    *out = value;
    byte
}

#[kani::proof]
fn legal_ordinary_transfer() {
    let mut out = [0; 3];
    assert_eq!(write_initialized(&mut out), 7);
    assert_eq!(out, [1, 2, 3]);
}
