// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_union_transmute() {
    let value = TransmuteU { bytes: [5; 5] };
    let _out: [u64; 1] = unsafe { std::mem::transmute(value) };
}
