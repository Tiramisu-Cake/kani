// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks -Z valid-value-checks -Z mem-predicates --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_init_predicate() {
    let value = U { wide: 7 };
    let pointer = &value as *const U;
    let _initialized = kani::mem::can_dereference(pointer);
}
