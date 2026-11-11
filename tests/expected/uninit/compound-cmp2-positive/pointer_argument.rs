// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
#[inline(never)]
fn read(pointer: *const u8) -> u8 {
    unsafe { *pointer }
}
#[kani::proof]
fn ordinary_pointer_argument_does_not_poison_valid_read() {
    let word = 7usize;
    let bytes = (&word as *const usize).cast::<u8>();
    assert_eq!(read(bytes), 7);
    kani::cover!(true);
}
