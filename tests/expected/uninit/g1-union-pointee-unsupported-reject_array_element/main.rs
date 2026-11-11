// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_array_element() {
    let values = [U { wide: 1 }];
    let p = values.as_ptr();
    unsafe {
        let _value = (*p).wide;
    }
}
