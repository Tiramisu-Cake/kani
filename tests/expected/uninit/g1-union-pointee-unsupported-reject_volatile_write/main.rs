// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_volatile_write() {
    let mut value = U { wide: 23 };
    let p = &mut value as *mut U;
    unsafe {
        ptr::write_volatile(p, U { wide: 29 });
    }
}
