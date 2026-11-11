// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

include!("../g1-union-pointee-unsupported/types.inc");

#[kani::proof]
fn reject_unaligned_read() {
    let bytes = [0u8; 16];
    let p = unsafe { bytes.as_ptr().add(1).cast::<U>() };
    unsafe {
        let _value = ptr::read_unaligned(p);
    }
}
