// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular
#![feature(core_intrinsics)]

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_forget_union_array() {
    unsafe {
        let source = [U { wide: 1 }; 1];
        // Reading the container requires a layout; forget alone has no storage effects.
        let value = ptr::read(&source as *const [U; 1]);
        std::intrinsics::forget(value);
    }
}
