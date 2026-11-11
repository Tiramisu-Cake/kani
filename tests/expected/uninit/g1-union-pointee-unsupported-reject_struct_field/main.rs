// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_struct_field() {
    let wrapper = HasUnion { value: U { wide: 1 } };
    let p = &wrapper as *const HasUnion;
    unsafe {
        let _value = (*p).value.wide;
    }
}
