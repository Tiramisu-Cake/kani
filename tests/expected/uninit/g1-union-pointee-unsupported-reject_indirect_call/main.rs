// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_indirect_call() {
    let call: fn(U) -> U = indirect_target;
    let value = U { wide: 2 };
    let out = call(value);
    let _read = unsafe { out.wide };
}
