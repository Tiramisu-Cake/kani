// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular

static T: [&u8; 1] = [&5];

// The direct whole-object reference and the nested relocation may use different AllocId keys
// for the same emitted byte. Their actual keys, symbol and qualification require CI inspection.
#[kani::proof]
fn direct_first() {
    let direct: &u8 = &5;
    let nested: &u8 = T[0];
    let direct_value = *direct;
    let nested_value = *nested;
    assert!(direct_value == 5);
    assert!(nested_value == 5);
    assert!(direct_value == nested_value);
}
