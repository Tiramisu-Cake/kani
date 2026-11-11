// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_foreign_mutation_erased() {
    let mut value = U { wide: 31 };
    unsafe {
        foreign_mutate_erased((&mut value as *mut U).cast());
        let _read = (&value as *const U).read().wide;
    }
}
