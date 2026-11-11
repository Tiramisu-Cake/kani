// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_bodyless_transfer() {
    let value = U { wide: 3 };
    let out = unsafe { bodyless_union_transfer(value) };
    let _read = unsafe { out.wide };
}
