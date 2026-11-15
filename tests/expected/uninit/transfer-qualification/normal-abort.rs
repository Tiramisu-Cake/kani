// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

use std::mem::MaybeUninit;

#[inline(never)]
fn return_or_abort(abort: bool) -> MaybeUninit<u8> {
    if abort {
        panic!("transfer qualification abort");
    }
    MaybeUninit::new(7)
}

#[kani::proof]
fn normal_return_or_abort() {
    // On panic=abort the true branch never reaches return0 or the caller read.
    // The false branch exercises the same call's initialized normal destination.
    let value = return_or_abort(kani::any());
    assert_eq!(unsafe { value.assume_init() }, 7);
}
