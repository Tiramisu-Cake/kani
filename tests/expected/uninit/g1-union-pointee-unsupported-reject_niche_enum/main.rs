// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_niche_enum() {
    let u = NicheUnion { value: Niche::Some(NonZeroU32::new(1).unwrap()) };
    let p = &u as *const NicheUnion;
    unsafe {
        let _value = (*p).value;
    }
}
