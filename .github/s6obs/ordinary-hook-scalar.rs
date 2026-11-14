// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

#[kani::proof]
fn ordinary_hook_scalar() {
    let source = 37u16;
    let destination = kani::internal::untracked_deref(&source);
    assert_eq!(destination, 37);
    assert_eq!(source, 37);
}
