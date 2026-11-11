// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular
// Unexecuted reduction candidate for G1R5: each harness should expose uninitialized padding.
// Kept outside the regression suite until the coordinator runs the reduction.
use std::mem::ManuallyDrop;
use std::ptr;

#[repr(C)]
#[derive(Clone, Copy)]
struct Padded {
    byte: u8,
    word: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
union CU {
    z: (),
    padded: ManuallyDrop<Padded>,
}
#[derive(Clone, Copy)]
union RU {
    z: (),
    padded: ManuallyDrop<Padded>,
}

#[inline(never)]
fn identity_c(value: CU) -> CU {
    value
}
#[kani::proof]
fn typed_copy_c() {
    let mut src = CU { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = CU { z: () };
    unsafe {
        ptr::write_bytes((&mut src as *mut CU).cast::<u8>(), 0x5a, std::mem::size_of::<CU>());
        ptr::write(&mut dst, ptr::read(&src));
        let padding = ptr::addr_of!((&dst.padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[kani::proof]
fn argument_return_c() {
    let mut src = CU { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    unsafe {
        ptr::write_bytes((&mut src as *mut CU).cast::<u8>(), 0x5a, std::mem::size_of::<CU>());
    }
    let dst = identity_c(src);
    unsafe {
        let padding = ptr::addr_of!((&dst.padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}

#[inline(never)]
fn identity_rust(value: RU) -> RU {
    value
}
#[kani::proof]
fn typed_copy_rust() {
    let mut src = RU { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = RU { z: () };
    unsafe {
        ptr::write_bytes((&mut src as *mut RU).cast::<u8>(), 0x5a, std::mem::size_of::<RU>());
        ptr::write(&mut dst, ptr::read(&src));
        let padding = ptr::addr_of!((&dst.padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[kani::proof]
fn argument_return_rust() {
    let mut src = RU { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    unsafe {
        ptr::write_bytes((&mut src as *mut RU).cast::<u8>(), 0x5a, std::mem::size_of::<RU>());
    }
    let dst = identity_rust(src);
    unsafe {
        let padding = ptr::addr_of!((&dst.padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
