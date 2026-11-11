// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular
#![feature(core_intrinsics)]

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_select_unpredictable() {
    let a = U { wide: 17 };
    let b = U { wide: 19 };
    let _selected = unsafe { std::intrinsics::select_unpredictable(true, a, b) };
}
