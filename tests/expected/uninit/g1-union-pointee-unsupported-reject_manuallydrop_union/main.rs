// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_manuallydrop_union() {
    let wrapper = ManuallyDrop::new(U { wide: 1 });
    let p = &wrapper as *const ManuallyDrop<U>;
    unsafe {
        let _value = (&*p).wide;
    }
}
