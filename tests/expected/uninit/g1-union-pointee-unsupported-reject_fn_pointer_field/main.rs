// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_fn_pointer_field() {
    let f: fn() -> u32 = || 1;
    let u = FunctionPointerUnion { value: f };
    let p = &u as *const FunctionPointerUnion;
    unsafe {
        let _value = (*p).value;
    }
}
