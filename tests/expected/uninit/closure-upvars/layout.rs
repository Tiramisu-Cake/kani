// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks -Z function-contracts -Z unstable-options --output-format=regular --cbmc-args --object-bits 12

use std::mem::MaybeUninit;

#[inline(never)]
fn touch<T>(_: &T) {}

#[repr(C)]
#[derive(Clone, Copy)]
struct Padded {
    byte: u8,
    word: u32,
}

#[derive(Clone, Copy)]
struct Unit;

#[repr(C)]
#[derive(Clone, Copy)]
struct Offset<F> {
    prefix: u8,
    callback: F,
}

#[inline(never)]
fn offset_copy_call<F: Copy + Fn() -> bool>(callback: F) -> bool {
    let wrapped = Offset { prefix: 7, callback };
    // A closure nested at a nonzero offset; recurse using that current_offset.
    let copied = unsafe { std::ptr::addr_of!(wrapped).read() };
    assert_eq!(copied.prefix, 7, "prefix survives closure layout composition");
    (copied.callback)()
}

#[kani::proof]
#[kani::unwind(8)]
fn mixed_scalar_ref_padding() {
    let data = MaybeUninit::new(17u8);
    let yes = true;
    let small = 3u16;
    let reference = &yes;
    let payload = &data;
    let padded = Padded { byte: 5, word: 29 };
    let unit = Unit;
    let callback = move || {
        // Logical use order interleaves fields of different size/alignment.
        touch(&small);
        touch(&reference);
        touch(&padded);
        touch(&payload);
        touch(&unit);
        kani::cover!(true, "mixed upvars reached payload read");
        small == 3
            && *reference
            && padded.byte == 5
            && padded.word == 29
            && unsafe { payload.assume_init_read() == 17 }
    };
    assert!(std::mem::size_of_val(&callback) > 0);
    assert!(offset_copy_call(callback), "mixed captures and padding consumed");
    kani::cover!(true, "mixed upvars returned");
}

#[kani::proof]
#[kani::unwind(8)]
fn reordered_nested_captures() {
    let no = false;
    let data = MaybeUninit::new(17u8);
    let reference = &no;
    let payload = &data;
    let byte = 9u8;
    let wide = 41u64;
    let inner = move || {
        // Request the same sort of fields in a different logical order.
        touch(&reference);
        touch(&wide);
        touch(&byte);
        touch(&payload);
        !*reference && wide == 41 && byte == 9 && unsafe { payload.assume_init_read() == 17 }
    };
    let outer = move || {
        touch(&inner); // Retain the complete inner closure as an upvar.
        kani::cover!(true, "nested ordinary closure reached");
        inner()
    };
    assert!(std::mem::size_of_val(&outer) > 0);
    assert!(offset_copy_call(outer), "nested closure fields consumed");
    kani::cover!(true, "nested upvars returned");
}
