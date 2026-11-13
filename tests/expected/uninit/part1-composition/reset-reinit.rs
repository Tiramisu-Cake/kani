// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[inline(never)]
fn relay(value: MaybeUninit<u8>) -> MaybeUninit<u8> {
    value
}

#[inline(never)]
fn reset(destination: &mut MaybeUninit<u8>) {
    *destination = MaybeUninit::uninit();
}

#[kani::proof]
fn reset_reinit() {
    let mut storage = [MaybeUninit::new(42_u8); 3];
    assert_eq!(unsafe { storage[1].assume_init() }, 42);
    reset(&mut storage[1]);
    storage[1].write(42);
    let returned = relay(storage[1]);
    assert_eq!(unsafe { returned.assume_init() }, 42);
    assert_eq!(unsafe { storage[0].assume_init() }, 42);
    assert_eq!(unsafe { storage[2].assume_init() }, 42);
}
