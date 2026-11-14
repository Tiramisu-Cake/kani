// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

// Keep the nested reference inside an aggregate constant instead of a ref-typed
// constant in T's initializer. Const definitions are not runtime MonoItems.
const INDIRECT: [&u8; 1] = [&5];
static T: [&u8; 1] = INDIRECT;

// Candidate mixed-qualification control: actual distinct AllocId keys, shared symbol and
// qualification must be inspected in CI before claiming this case distinguishes registration.
#[kani::proof]
fn aggregate_constant_initializer() {
    let direct: &u8 = &5;
    let nested: &u8 = T[0];
    let direct_value = unsafe { std::ptr::read_volatile(direct) };
    let nested_value = unsafe { std::ptr::read_volatile(nested) };
    assert!(direct_value == 5);
    assert!(nested_value == 5);
    assert!(direct_value == nested_value);
}
