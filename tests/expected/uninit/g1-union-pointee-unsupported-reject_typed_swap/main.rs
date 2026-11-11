// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular
#![feature(core_intrinsics)]

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_typed_swap() {
    let mut left = U { wide: 11 };
    let mut right = U { wide: 13 };
    unsafe {
        std::intrinsics::typed_swap_nonoverlapping(&mut left, &mut right);
    }
}
