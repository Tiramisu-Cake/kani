// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

// This helper is used only by CTFE. The runtime reachability graph follows T's
// evaluated allocation, not the initializer's call to this function.
const fn nested_origin() -> [&'static u8; 1] {
    [&5]
}

static T: [&u8; 1] = nested_origin();

// The direct and nested references exercise immutable descriptor qualification
// across const-evaluated initializer forms.
#[kani::proof]
fn const_fn_initializer() {
    let direct: &u8 = &5;
    let nested: &u8 = T[0];
    let direct_value = unsafe { std::ptr::read_volatile(direct) };
    let nested_value = unsafe { std::ptr::read_volatile(nested) };
    assert!(direct_value == 5);
    assert!(nested_value == 5);
    assert!(direct_value == nested_value);
}
