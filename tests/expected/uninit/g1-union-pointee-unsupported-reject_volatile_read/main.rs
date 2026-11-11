// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_volatile_read() {
    let value = U { wide: 23 };
    let p = &value as *const U;
    let _read = unsafe { ptr::read_volatile(p) };
}
