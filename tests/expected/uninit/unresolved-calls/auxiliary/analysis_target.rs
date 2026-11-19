// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

// The copy intrinsic initializes the destination and creates an analysis target.
#[inline(never)]
pub fn check_byte_copy() {
    let source = 7u8;
    let mut destination = 0u8;
    unsafe { std::ptr::copy_nonoverlapping(&source, &mut destination, 1) };
    assert_eq!(destination, source);
}
