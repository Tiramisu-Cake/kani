// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_union_in_union() {
    let outer = Outer { inner: U { wide: 1 } };
    let p = &outer as *const Outer;
    unsafe {
        let _value = (*p).inner.wide;
    }
}
