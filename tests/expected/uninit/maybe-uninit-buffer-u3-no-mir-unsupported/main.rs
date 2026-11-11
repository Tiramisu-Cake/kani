// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks -Z function-contracts --output-format=regular

use std::mem::MaybeUninit;

extern "C" {
    fn shadow_sink(value: MaybeUninit<u16>);
}

#[kani::proof]
fn no_mir_shadow_argument_is_unsupported() {
    // The expected Kani diagnostic is the new fail-closed check. The external-item
    // handling may also emit its standard unsupported diagnostic.
    unsafe { shadow_sink(MaybeUninit::uninit()) };
}
