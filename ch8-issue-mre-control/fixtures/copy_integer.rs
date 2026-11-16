// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
#[kani::proof]
fn copy_integer() {
    let src = kani::any::<u8>();
    let mut dst = 0u8;
    unsafe { core::ptr::copy_nonoverlapping(&src, &mut dst, 1) };
    assert_eq!(dst, src);
}
