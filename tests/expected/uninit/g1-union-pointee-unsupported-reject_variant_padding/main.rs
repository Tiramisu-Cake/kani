// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_variant_padding() {
    let u = DifferentPaddingUnion { value: DifferentPadding::Byte(1) };
    let p = &u as *const DifferentPaddingUnion;
    unsafe {
        let _value = (*p).value;
    }
}
