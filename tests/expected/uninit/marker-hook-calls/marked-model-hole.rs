// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[derive(Clone, Copy)]
#[allow(dead_code)]
union Byte {
    byte: u8,
    empty: (),
}

impl kani::Arbitrary for Byte {
    fn any() -> Self {
        Self { empty: () }
    }
}

#[kani::proof]
fn marked_model_hole() {
    let source = MaybeUninit::new(11u16);
    // NondetFn1Model has a real, non-inlined MIR body. It accepts a shadow argument
    // and returns ordinary union storage via AnyModel and this Arbitrary body.
    let result = kani::arbitrary::nondet_fn1::<_, Byte>(source);
    assert_eq!(unsafe { source.assume_init_read() }, 11);
    let _payload = unsafe { result.byte };
}
