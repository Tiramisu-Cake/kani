// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular
#![feature(core_intrinsics)]

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
    wide: u32,
    narrow: u8,
    z: (),
    pair: [u16; 2],
    padded: ManuallyDrop<Padded>,
    tuple: ManuallyDrop<(u8, u32)>,
    padded_pair: [ManuallyDrop<Padded>; 2],
    zst_array: [(); 2],
    ptr: *mut u32,
    fat: *const [u8],
}
#[derive(Clone, Copy)]
union RU {
    wide: u32,
    narrow: u8,
    z: (),
    pair: [u16; 2],
    padded: ManuallyDrop<Padded>,
    tuple: ManuallyDrop<(u8, u32)>,
    padded_pair: [ManuallyDrop<Padded>; 2],
    zst_array: [(); 2],
    ptr: *mut u32,
    fat: *const [u8],
}
#[repr(C, align(8))]
#[derive(Clone, Copy)]
union TailC {
    bytes: [u8; 5],
    word: u32,
}
#[repr(align(8))]
#[derive(Clone, Copy)]
union TailR {
    bytes: [u8; 5],
    word: u32,
}

unsafe fn tail_c_padding(p: *const TailC) -> *const u8 {
    unsafe {
        p.cast::<u8>().add(std::mem::offset_of!(TailC, bytes) + std::mem::size_of::<[u8; 5]>())
    }
}
unsafe fn tail_r_padding(p: *const TailR) -> *const u8 {
    unsafe {
        p.cast::<u8>().add(std::mem::offset_of!(TailR, bytes) + std::mem::size_of::<[u8; 5]>())
    }
}

#[kani::proof]
fn unwritten_c() {
    let u = CU { z: () };
    let p = &u as *const CU;
    unsafe {
        let _value = (*p).wide;
    }
}
#[kani::proof]
fn unwritten_rust() {
    let u = RU { z: () };
    let p = &u as *const RU;
    unsafe {
        let _value = (*p).wide;
    }
}
#[kani::proof]
fn narrow_then_wide_c() {
    let mut u = CU { narrow: 9 };
    let p = &mut u as *mut CU;
    unsafe {
        (*p).narrow = 10;
        let _value = (*p).wide;
    }
}
#[kani::proof]
fn narrow_then_wide_rust() {
    let mut u = RU { narrow: 9 };
    let p = &mut u as *mut RU;
    unsafe {
        (*p).narrow = 10;
        let _value = (*p).wide;
    }
}

#[kani::proof]
fn whole_copy_partial_assign_c() {
    let src = CU { z: () };
    let mut dst = CU { wide: 1 };
    unsafe {
        *(&mut dst as *mut CU) = *(&src as *const CU);
        let _value = (*(&dst as *const CU)).wide;
    }
}
#[kani::proof]
fn whole_copy_partial_assign_rust() {
    let src = RU { z: () };
    let mut dst = RU { wide: 1 };
    unsafe {
        *(&mut dst as *mut RU) = *(&src as *const RU);
        let _value = (*(&dst as *const RU)).wide;
    }
}
#[kani::proof]
fn whole_copy_partial_ptr_read_c() {
    let src = CU { z: () };
    let dst = unsafe { ptr::read(&src) };
    let _value = unsafe { (*(&dst as *const CU)).wide };
}
#[kani::proof]
fn whole_copy_partial_ptr_read_rust() {
    let src = RU { z: () };
    let dst = unsafe { ptr::read(&src) };
    let _value = unsafe { (*(&dst as *const RU)).wide };
}
union MoveC {
    wide: u32,
    narrow: u8,
    z: (),
}
union MoveR {
    wide: u32,
    narrow: u8,
    z: (),
}
#[kani::proof]
fn whole_move_source_uninit_c() {
    let src = MoveC { wide: 173 };
    let p = ptr::addr_of!(src);
    let _dst = src;
    unsafe {
        let _moved_from = (*p).wide;
    }
}
#[kani::proof]
fn whole_move_source_uninit_rust() {
    let src = MoveR { wide: 179 };
    let p = ptr::addr_of!(src);
    let _dst = src;
    unsafe {
        let _moved_from = (*p).wide;
    }
}
#[inline(never)]
fn consume_move_c(_value: MoveC) {}
#[inline(never)]
fn consume_move_rust(_value: MoveR) {}
#[kani::proof]
fn argument_move_source_uninit_c() {
    let src = MoveC { wide: 181 };
    let p = ptr::addr_of!(src);
    consume_move_c(src);
    unsafe {
        let _moved_from = (*p).wide;
    }
}
#[kani::proof]
fn argument_move_source_uninit_rust() {
    let src = MoveR { wide: 191 };
    let p = ptr::addr_of!(src);
    consume_move_rust(src);
    unsafe {
        let _moved_from = (*p).wide;
    }
}
#[kani::proof]
fn whole_move_partial_c() {
    let src = MoveC { z: () };
    let dst = src;
    unsafe {
        let _value = dst.wide;
    }
}
#[kani::proof]
fn whole_move_partial_rust() {
    let src = MoveR { z: () };
    let dst = src;
    unsafe {
        let _value = dst.wide;
    }
}
#[kani::proof]
fn whole_copy_partial_nonoverlap_c() {
    let src = CU { z: () };
    let mut dst = CU { wide: 3 };
    unsafe {
        ptr::copy_nonoverlapping(&src, &mut dst, 1);
        let _value = (*(&dst as *const CU)).wide;
    }
}
#[kani::proof]
fn whole_copy_partial_nonoverlap_rust() {
    let src = RU { z: () };
    let mut dst = RU { wide: 3 };
    unsafe {
        ptr::copy_nonoverlapping(&src, &mut dst, 1);
        let _value = (*(&dst as *const RU)).wide;
    }
}
#[kani::proof]
fn whole_copy_partial_overlapping_c() {
    let mut b = RawBacking([0u8; 32]);
    let base = b.0.as_mut_ptr();
    unsafe {
        ptr::write(base.cast::<CU>(), CU { z: () });
        ptr::copy(base, base.add(1), std::mem::size_of::<CU>());
        let _value = *base.add(1);
    }
}
#[kani::proof]
fn whole_copy_partial_overlapping_rust() {
    let mut b = RawBacking([0u8; 32]);
    let base = b.0.as_mut_ptr();
    unsafe {
        ptr::write(base.cast::<RU>(), RU { z: () });
        ptr::copy(base, base.add(1), std::mem::size_of::<RU>());
        let _value = *base.add(1);
    }
}

#[kani::proof]
fn whole_reset_c() {
    let mut u = CU { wide: 0x12345678 };
    let p = &mut u as *mut CU;
    unsafe {
        ptr::write(p, CU { narrow: 1 });
        let _value = (*p).wide;
    }
}
#[kani::proof]
fn whole_reset_rust() {
    let mut u = RU { wide: 0x12345678 };
    let p = &mut u as *mut RU;
    unsafe {
        ptr::write(p, RU { narrow: 1 });
        let _value = (*p).wide;
    }
}
#[kani::proof]
fn whole_reset_alias_c() {
    let mut u = CU { wide: 0x12345678 };
    let p = &mut u as *mut CU;
    let alias = p;
    unsafe {
        ptr::write(p, CU { narrow: 1 });
        let _value = (*alias).wide;
    }
}
#[kani::proof]
fn whole_reset_alias_rust() {
    let mut u = RU { wide: 0x12345678 };
    let p = &mut u as *mut RU;
    let alias = p;
    unsafe {
        ptr::write(p, RU { narrow: 1 });
        let _value = (*alias).wide;
    }
}

#[inline(never)]
fn identity_c(x: CU) -> CU {
    x
}
#[inline(never)]
fn identity_rust(x: RU) -> RU {
    x
}
#[kani::proof]
fn argument_return_partial_c() {
    let x = identity_c(CU { z: () });
    let _value = unsafe { x.wide };
}
#[kani::proof]
fn argument_return_partial_rust() {
    let x = identity_rust(RU { z: () });
    let _value = unsafe { x.wide };
}
#[inline(never)]
fn pair_identity_c(a: CU, _b: CU) -> CU {
    identity_c(a)
}
#[inline(never)]
fn pair_identity_rust(a: RU, _b: RU) -> RU {
    identity_rust(a)
}
#[kani::proof]
fn argument_return_partial_reused_c() {
    let mut destination = pair_identity_c(CU { wide: 1 }, CU { z: () });
    destination = pair_identity_c(CU { z: () }, CU { wide: 2 });
    let _value = unsafe { destination.wide };
}
#[kani::proof]
fn argument_return_partial_reused_rust() {
    let mut destination = pair_identity_rust(RU { wide: 1 }, RU { z: () });
    destination = pair_identity_rust(RU { z: () }, RU { wide: 2 });
    let _value = unsafe { destination.wide };
}

#[inline(never)]
fn pair_mixed_c(a: CU, _b: TailC) -> CU {
    a
}
#[inline(never)]
fn pair_mixed_rust(a: RU, _b: TailR) -> RU {
    a
}
#[kani::proof]
fn argument_return_partial_mixed_size_c() {
    let value = pair_mixed_c(CU { z: () }, TailC { bytes: [1; 5] });
    let _read = unsafe { value.wide };
}
#[kani::proof]
fn argument_return_partial_mixed_size_rust() {
    let value = pair_mixed_rust(RU { z: () }, TailR { bytes: [1; 5] });
    let _read = unsafe { value.wide };
}
#[kani::proof]
fn padded_byte_c() {
    let u = CU { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let p = &u as *const CU;
    unsafe {
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[kani::proof]
fn padded_byte_rust() {
    let u = RU { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let p = &u as *const RU;
    unsafe {
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[kani::proof]
fn padded_typed_transfer_padding_c() {
    let mut src = CU { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = CU { z: () };
    unsafe {
        ptr::write_bytes((&mut src as *mut CU).cast::<u8>(), 0x5a, std::mem::size_of::<CU>());
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const CU;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[kani::proof]
fn padded_typed_transfer_padding_rust() {
    let mut src = RU { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    let mut dst = RU { z: () };
    unsafe {
        ptr::write_bytes((&mut src as *mut RU).cast::<u8>(), 0x5a, std::mem::size_of::<RU>());
        ptr::write(&mut dst, ptr::read(&src));
        let p = &dst as *const RU;
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[inline(never)]
fn padded_identity_c(x: CU) -> CU {
    x
}
#[inline(never)]
fn padded_identity_rust(x: RU) -> RU {
    x
}
#[kani::proof]
fn padded_argument_return_padding_c() {
    let mut src = CU { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    unsafe {
        ptr::write_bytes((&mut src as *mut CU).cast::<u8>(), 0x5a, std::mem::size_of::<CU>());
    }
    let u = padded_identity_c(src);
    let p = &u as *const CU;
    unsafe {
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[kani::proof]
fn padded_argument_return_padding_rust() {
    let mut src = RU { padded: ManuallyDrop::new(Padded { byte: 4, word: 5 }) };
    unsafe {
        ptr::write_bytes((&mut src as *mut RU).cast::<u8>(), 0x5a, std::mem::size_of::<RU>());
    }
    let u = padded_identity_rust(src);
    let p = &u as *const RU;
    unsafe {
        let padding = ptr::addr_of!((&(*p).padded).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}

#[kani::proof]
fn array_field_unwritten_c() {
    let u = CU { z: () };
    let p = &u as *const CU;
    unsafe {
        let _value = (*p).pair[1];
    }
}
#[kani::proof]
fn array_field_unwritten_rust() {
    let u = RU { z: () };
    let p = &u as *const RU;
    unsafe {
        let _value = (*p).pair[1];
    }
}
#[kani::proof]
fn array_padded_byte_c() {
    let u = CU { padded: ManuallyDrop::new(Padded { byte: 1, word: 2 }) };
    let p = (&u as *const CU).cast::<u8>();
    unsafe {
        let _padding = *p.add(1);
    }
}
#[kani::proof]
fn array_padded_byte_rust() {
    let u = RU { padded: ManuallyDrop::new(Padded { byte: 1, word: 2 }) };
    let p = (&u as *const RU).cast::<u8>();
    unsafe {
        let _padding = *p.add(1);
    }
}
#[kani::proof]
fn array_padded_elements_byte_c() {
    let u = CU {
        padded_pair: [
            ManuallyDrop::new(Padded { byte: 1, word: 2 }),
            ManuallyDrop::new(Padded { byte: 3, word: 5 }),
        ],
    };
    let p = &u as *const CU;
    unsafe {
        let padding = ptr::addr_of!((&(*p).padded_pair[1]).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}
#[kani::proof]
fn array_padded_elements_byte_rust() {
    let u = RU {
        padded_pair: [
            ManuallyDrop::new(Padded { byte: 1, word: 2 }),
            ManuallyDrop::new(Padded { byte: 3, word: 5 }),
        ],
    };
    let p = &u as *const RU;
    unsafe {
        let padding = ptr::addr_of!((&(*p).padded_pair[1]).word).cast::<u8>().sub(1);
        let _padding = *padding;
    }
}

#[kani::proof]
fn zst_whole_reset_c() {
    let mut u = CU { wide: 0x76543210 };
    let p = &mut u as *mut CU;
    unsafe {
        ptr::write(p, CU { z: () });
        let _value = (*p).wide;
    }
}
#[kani::proof]
fn zst_whole_reset_rust() {
    let mut u = RU { wide: 0x76543210 };
    let p = &mut u as *mut RU;
    unsafe {
        ptr::write(p, RU { z: () });
        let _value = (*p).wide;
    }
}

#[repr(align(8))]
struct RawBacking([u8; 32]);
#[kani::proof]
fn align_tail_typed_copy_c() {
    let mut b = RawBacking([0u8; 32]);
    let p = b.0.as_mut_ptr().cast::<TailC>();
    unsafe {
        ptr::write(p, TailC { bytes: [0x5a; 5] });
        ptr::write_bytes(p.cast::<u8>(), 0x5a, std::mem::size_of::<TailC>());
        let value = ptr::read(p);
        ptr::write(p.add(1), value);
        let _tail = *tail_c_padding(p.add(1));
    }
}
#[kani::proof]
fn align_tail_typed_copy_rust() {
    let mut b = RawBacking([0u8; 32]);
    let p = b.0.as_mut_ptr().cast::<TailR>();
    unsafe {
        ptr::write(p, TailR { bytes: [0x5a; 5] });
        ptr::write_bytes(p.cast::<u8>(), 0x5a, std::mem::size_of::<TailR>());
        let value = ptr::read(p);
        ptr::write(p.add(1), value);
        let _tail = *tail_r_padding(p.add(1));
    }
}
#[inline(never)]
fn tail_identity_c(x: TailC) -> TailC {
    x
}
#[inline(never)]
fn tail_identity_rust(x: TailR) -> TailR {
    x
}
#[kani::proof]
fn align_tail_argument_return_c() {
    let mut src = TailC { bytes: [1; 5] };
    unsafe {
        ptr::write_bytes((&mut src as *mut TailC).cast::<u8>(), 0x5a, std::mem::size_of::<TailC>());
    }
    let u = tail_identity_c(src);
    unsafe {
        let _tail = *tail_c_padding(&u as *const TailC);
    }
}
#[kani::proof]
fn align_tail_argument_return_rust() {
    let mut src = TailR { bytes: [1; 5] };
    unsafe {
        ptr::write_bytes((&mut src as *mut TailR).cast::<u8>(), 0x5a, std::mem::size_of::<TailR>());
    }
    let u = tail_identity_rust(src);
    unsafe {
        let _tail = *tail_r_padding(&u as *const TailR);
    }
}
#[kani::proof]
fn align_tail_reset_c() {
    let mut b = RawBacking([0u8; 32]);
    let p = b.0.as_mut_ptr().cast::<TailC>();
    unsafe {
        ptr::write_bytes(p.cast::<u8>(), 0x5a, std::mem::size_of::<TailC>());
        ptr::write(p, TailC { bytes: [1; 5] });
        let _tail = *tail_c_padding(p);
    }
}
#[kani::proof]
fn align_tail_reset_rust() {
    let mut b = RawBacking([0u8; 32]);
    let p = b.0.as_mut_ptr().cast::<TailR>();
    unsafe {
        ptr::write_bytes(p.cast::<u8>(), 0x5a, std::mem::size_of::<TailR>());
        ptr::write(p, TailR { bytes: [1; 5] });
        let _tail = *tail_r_padding(p);
    }
}

#[kani::proof]
fn address_no_bless_c() {
    let u = CU { z: () };
    let p = &u as *const CU;
    let _address = unsafe { ptr::addr_of!((*p).wide) };
    unsafe {
        let _value = (*p).wide;
    }
}
#[kani::proof]
fn address_no_bless_rust() {
    let u = RU { z: () };
    let p = &u as *const RU;
    let _address = unsafe { ptr::addr_of!((*p).wide) };
    unsafe {
        let _value = (*p).wide;
    }
}

#[kani::proof]
fn pointer_pointee_uninit_c() {
    let mut target = std::mem::MaybeUninit::<u32>::uninit();
    let mut u = CU { ptr: target.as_mut_ptr() };
    let p = &mut u as *mut CU;
    unsafe {
        (*p).ptr = target.as_mut_ptr();
        let q = (*p).ptr;
        let _value = *q;
    }
}
#[kani::proof]
fn pointer_pointee_uninit_rust() {
    let mut target = std::mem::MaybeUninit::<u32>::uninit();
    let mut u = RU { ptr: target.as_mut_ptr() };
    let p = &mut u as *mut RU;
    unsafe {
        (*p).ptr = target.as_mut_ptr();
        let q = (*p).ptr;
        let _value = *q;
    }
}
#[kani::proof]
fn pointer_compound_read_uninit_c() {
    let u = CU { z: () };
    let p = &u as *const CU;
    unsafe {
        let _value = *(*p).ptr;
    }
}
#[kani::proof]
fn pointer_compound_read_uninit_rust() {
    let u = RU { z: () };
    let p = &u as *const RU;
    unsafe {
        let _value = *(*p).ptr;
    }
}
#[kani::proof]
fn pointer_compound_store_uninit_c() {
    let mut u = CU { z: () };
    let p = &mut u as *mut CU;
    unsafe {
        *(*p).ptr = 113;
    }
}
#[kani::proof]
fn pointer_compound_store_uninit_rust() {
    let mut u = RU { z: () };
    let p = &mut u as *mut RU;
    unsafe {
        *(*p).ptr = 127;
    }
}
#[kani::proof]
fn pointer_compound_read_after_reset_c() {
    let mut target = 131u32;
    let mut u = CU { ptr: &mut target };
    let p = &mut u as *mut CU;
    unsafe {
        ptr::write(p, CU { z: () });
        let _value = *(*p).ptr;
    }
}
#[kani::proof]
fn pointer_compound_read_after_reset_rust() {
    let mut target = 137u32;
    let mut u = RU { ptr: &mut target };
    let p = &mut u as *mut RU;
    unsafe {
        ptr::write(p, RU { z: () });
        let _value = *(*p).ptr;
    }
}
#[kani::proof]
fn pointer_delayed_partial_c() {
    let src = CU { z: () };
    let mut local = 37u32;
    let holder = identity_c(CU { ptr: &mut local });
    let q = unsafe { holder.ptr };
    unsafe {
        ptr::copy_nonoverlapping(
            (&src as *const CU).cast::<u8>(),
            q.cast::<u8>(),
            std::mem::size_of::<u32>(),
        );
    }
    assert_eq!(local, 37);
}
#[kani::proof]
fn pointer_delayed_partial_rust() {
    let src = RU { z: () };
    let mut local = 41u32;
    let holder = identity_rust(RU { ptr: &mut local });
    let q = unsafe { holder.ptr };
    unsafe {
        ptr::copy_nonoverlapping(
            (&src as *const RU).cast::<u8>(),
            q.cast::<u8>(),
            std::mem::size_of::<u32>(),
        );
    }
    assert_eq!(local, 41);
}
#[kani::proof]
fn pointer_field_value_uninit_c() {
    let u = CU { z: () };
    unsafe {
        let _pointer = (*(&u as *const CU)).ptr;
    }
}
#[kani::proof]
fn pointer_field_value_uninit_rust() {
    let u = RU { z: () };
    unsafe {
        let _pointer = (*(&u as *const RU)).ptr;
    }
}
#[kani::proof]
fn fat_pointer_field_value_uninit_c() {
    let u = CU { z: () };
    unsafe {
        let _pointer = (*(&u as *const CU)).fat;
    }
}
#[kani::proof]
fn fat_pointer_field_value_uninit_rust() {
    let u = RU { z: () };
    unsafe {
        let _pointer = (*(&u as *const RU)).fat;
    }
}
