// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular
// CI-only bisection: which extra union arm makes CBMC abort on a padded typed transfer.
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
union U_base {
    z: (),
    padded: ManuallyDrop<Padded>,
}
#[kani::proof]
fn bisect_base() {
    let mut src = U_base { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = U_base { z: () };
    unsafe {
        ptr::write_bytes(
            (&mut src as *mut U_base).cast::<u8>(),
            0x5a,
            std::mem::size_of::<U_base>(),
        );
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const U_base;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
union U_wide {
    z: (),
    padded: ManuallyDrop<Padded>,
    wide: u32,
}
#[kani::proof]
fn bisect_wide() {
    let mut src = U_wide { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = U_wide { z: () };
    unsafe {
        ptr::write_bytes(
            (&mut src as *mut U_wide).cast::<u8>(),
            0x5a,
            std::mem::size_of::<U_wide>(),
        );
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const U_wide;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
union U_narrow {
    z: (),
    padded: ManuallyDrop<Padded>,
    narrow: u8,
}
#[kani::proof]
fn bisect_narrow() {
    let mut src = U_narrow { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = U_narrow { z: () };
    unsafe {
        ptr::write_bytes(
            (&mut src as *mut U_narrow).cast::<u8>(),
            0x5a,
            std::mem::size_of::<U_narrow>(),
        );
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const U_narrow;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
union U_pair {
    z: (),
    padded: ManuallyDrop<Padded>,
    pair: [u16; 2],
}
#[kani::proof]
fn bisect_pair() {
    let mut src = U_pair { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = U_pair { z: () };
    unsafe {
        ptr::write_bytes(
            (&mut src as *mut U_pair).cast::<u8>(),
            0x5a,
            std::mem::size_of::<U_pair>(),
        );
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const U_pair;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
union U_tuple {
    z: (),
    padded: ManuallyDrop<Padded>,
    tuple: ManuallyDrop<(u8, u32)>,
}
#[kani::proof]
fn bisect_tuple() {
    let mut src = U_tuple { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = U_tuple { z: () };
    unsafe {
        ptr::write_bytes(
            (&mut src as *mut U_tuple).cast::<u8>(),
            0x5a,
            std::mem::size_of::<U_tuple>(),
        );
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const U_tuple;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
union U_padded_pair {
    z: (),
    padded: ManuallyDrop<Padded>,
    padded_pair: [ManuallyDrop<Padded>; 2],
}
#[kani::proof]
fn bisect_padded_pair() {
    let mut src = U_padded_pair { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = U_padded_pair { z: () };
    unsafe {
        ptr::write_bytes(
            (&mut src as *mut U_padded_pair).cast::<u8>(),
            0x5a,
            std::mem::size_of::<U_padded_pair>(),
        );
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const U_padded_pair;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
union U_zst_array {
    z: (),
    padded: ManuallyDrop<Padded>,
    zst_array: [(); 2],
}
#[kani::proof]
fn bisect_zst_array() {
    let mut src = U_zst_array { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = U_zst_array { z: () };
    unsafe {
        ptr::write_bytes(
            (&mut src as *mut U_zst_array).cast::<u8>(),
            0x5a,
            std::mem::size_of::<U_zst_array>(),
        );
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const U_zst_array;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
union U_ptr {
    z: (),
    padded: ManuallyDrop<Padded>,
    ptr: *mut u32,
}
#[kani::proof]
fn bisect_ptr() {
    let mut src = U_ptr { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = U_ptr { z: () };
    unsafe {
        ptr::write_bytes((&mut src as *mut U_ptr).cast::<u8>(), 0x5a, std::mem::size_of::<U_ptr>());
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const U_ptr;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
union U_fat {
    z: (),
    padded: ManuallyDrop<Padded>,
    fat: *const [u8],
}
#[kani::proof]
fn bisect_fat() {
    let mut src = U_fat { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = U_fat { z: () };
    unsafe {
        ptr::write_bytes((&mut src as *mut U_fat).cast::<u8>(), 0x5a, std::mem::size_of::<U_fat>());
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const U_fat;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[repr(C)]
#[derive(Clone, Copy)]
union U_all {
    z: (),
    padded: ManuallyDrop<Padded>,
    wide: u32,
    narrow: u8,
    pair: [u16; 2],
    tuple: ManuallyDrop<(u8, u32)>,
    padded_pair: [ManuallyDrop<Padded>; 2],
    zst_array: [(); 2],
    ptr: *mut u32,
    fat: *const [u8],
}
#[kani::proof]
fn bisect_all() {
    let mut src = U_all { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = U_all { z: () };
    unsafe {
        ptr::write_bytes((&mut src as *mut U_all).cast::<u8>(), 0x5a, std::mem::size_of::<U_all>());
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const U_all;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
