// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

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
fn written_c() {
    let mut u = CU { z: () };
    let p = &mut u as *mut CU;
    unsafe {
        (*p).wide = 0x1234;
        assert_eq!((*p).wide, 0x1234);
    }
}
#[kani::proof]
fn written_rust() {
    let mut u = RU { z: () };
    let p = &mut u as *mut RU;
    unsafe {
        (*p).wide = 0x1234;
        assert_eq!((*p).wide, 0x1234);
    }
}

#[kani::proof]
fn wide_then_narrow_field_c() {
    let mut u = CU { wide: 0x12345678 };
    let p = &mut u as *mut CU;
    unsafe {
        (*p).narrow = 4;
        let mut expected = 0x12345678u32.to_ne_bytes();
        expected[std::mem::offset_of!(CU, narrow)] = 4;
        assert_eq!((*p).wide, u32::from_ne_bytes(expected));
    }
}
#[kani::proof]
fn wide_then_narrow_field_rust() {
    let mut u = RU { wide: 0x12345678 };
    let p = &mut u as *mut RU;
    unsafe {
        (*p).narrow = 4;
        let mut expected = 0x12345678u32.to_ne_bytes();
        expected[std::mem::offset_of!(RU, narrow)] = 4;
        assert_eq!((*p).wide, u32::from_ne_bytes(expected));
    }
}

#[kani::proof]
fn whole_copy_assign_c() {
    let src = CU { wide: 17 };
    let mut dst = CU { z: () };
    let (s, d) = (&src as *const CU, &mut dst as *mut CU);
    unsafe {
        *d = *s;
        assert_eq!((*d).wide, 17);
    }
}
#[kani::proof]
fn whole_copy_assign_rust() {
    let src = RU { wide: 17 };
    let mut dst = RU { z: () };
    let (s, d) = (&src as *const RU, &mut dst as *mut RU);
    unsafe {
        *d = *s;
        assert_eq!((*d).wide, 17);
    }
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
fn whole_move_c() {
    let src = MoveC { wide: 163 };
    let dst = src;
    assert_eq!(unsafe { dst.wide }, 163);
}
#[kani::proof]
fn whole_move_rust() {
    let src = MoveR { wide: 167 };
    let dst = src;
    assert_eq!(unsafe { dst.wide }, 167);
}
#[kani::proof]
fn whole_copy_ptr_read_c() {
    let src = CU { wide: 19 };
    let mut dst = CU { z: () };
    unsafe {
        let value = ptr::read(&src);
        ptr::write(&mut dst, value);
        assert_eq!((*(&dst as *const CU)).wide, 19);
    }
}
#[kani::proof]
fn whole_copy_ptr_read_rust() {
    let src = RU { wide: 19 };
    let mut dst = RU { z: () };
    unsafe {
        let value = ptr::read(&src);
        ptr::write(&mut dst, value);
        assert_eq!((*(&dst as *const RU)).wide, 19);
    }
}
#[kani::proof]
fn whole_copy_bytes_c() {
    let src = CU { wide: 23 };
    let mut dst = CU { z: () };
    unsafe {
        ptr::copy_nonoverlapping(&src, &mut dst, 1);
        assert_eq!((*(&dst as *const CU)).wide, 23);
    }
}
#[kani::proof]
fn whole_copy_bytes_rust() {
    let src = RU { wide: 23 };
    let mut dst = RU { z: () };
    unsafe {
        ptr::copy_nonoverlapping(&src, &mut dst, 1);
        assert_eq!((*(&dst as *const RU)).wide, 23);
    }
}
#[kani::proof]
fn whole_copy_overlap_self_c() {
    let mut u = CU { wide: 29 };
    let p = &mut u as *mut CU;
    unsafe {
        ptr::copy(p, p, 1);
        assert_eq!((*p).wide, 29);
    }
}
#[kani::proof]
fn whole_copy_overlap_self_rust() {
    let mut u = RU { wide: 31 };
    let p = &mut u as *mut RU;
    unsafe {
        ptr::copy(p, p, 1);
        assert_eq!((*p).wide, 31);
    }
}
#[kani::proof]
fn overlap_byte_copy_c() {
    let mut b = RawBacking([0; 32]);
    let base = b.0.as_mut_ptr();
    unsafe {
        ptr::write(base.cast::<CU>(), CU { wide: 0x12345678 });
        ptr::copy(base, base.add(1), std::mem::size_of::<CU>());
        assert_eq!(ptr::read(base.add(1)), 0x78);
    }
}
#[kani::proof]
fn overlap_byte_copy_rust() {
    let mut b = RawBacking([0; 32]);
    let base = b.0.as_mut_ptr();
    unsafe {
        ptr::write(base.cast::<RU>(), RU { wide: 0x12345678 });
        ptr::copy(base, base.add(1), std::mem::size_of::<RU>());
        assert_eq!(ptr::read(base.add(1)), 0x78);
    }
}

#[kani::proof]
fn whole_overwrite_c() {
    let mut u = CU { wide: 0x12345678 };
    let p = &mut u as *mut CU;
    unsafe {
        ptr::write(p, CU { wide: 0x87654321 });
        assert_eq!((*p).wide, 0x87654321);
    }
}
#[kani::proof]
fn whole_overwrite_rust() {
    let mut u = RU { wide: 0x12345678 };
    let p = &mut u as *mut RU;
    unsafe {
        ptr::write(p, RU { wide: 0x87654321 });
        assert_eq!((*p).wide, 0x87654321);
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
fn argument_return_c() {
    let x = identity_c(CU { wide: 37 });
    assert_eq!(unsafe { x.wide }, 37);
}
#[kani::proof]
fn argument_return_rust() {
    let x = identity_rust(RU { wide: 41 });
    assert_eq!(unsafe { x.wide }, 41);
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
fn argument_return_reused_c() {
    let mut destination = pair_identity_c(CU { wide: 43 }, CU { z: () });
    assert_eq!(unsafe { destination.wide }, 43);
    destination = pair_identity_c(CU { wide: 47 }, CU { z: () });
    assert_eq!(unsafe { destination.wide }, 47);
}
#[kani::proof]
fn argument_return_reused_rust() {
    let mut destination = pair_identity_rust(RU { wide: 53 }, RU { z: () });
    assert_eq!(unsafe { destination.wide }, 53);
    destination = pair_identity_rust(RU { wide: 59 }, RU { z: () });
    assert_eq!(unsafe { destination.wide }, 59);
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
fn argument_return_mixed_size_c() {
    let value = pair_mixed_c(CU { wide: 61 }, TailC { bytes: [1; 5] });
    assert_eq!(unsafe { value.wide }, 61);
}
#[kani::proof]
fn argument_return_mixed_size_rust() {
    let value = pair_mixed_rust(RU { wide: 67 }, TailR { bytes: [1; 5] });
    assert_eq!(unsafe { value.wide }, 67);
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
fn padded_argument_return_c() {
    let u = padded_identity_c(CU { padded: ManuallyDrop::new(Padded { byte: 2, word: 37 }) });
    assert_eq!(unsafe { u.padded.word }, 37);
}
#[kani::proof]
fn padded_argument_return_rust() {
    let u = padded_identity_rust(RU { padded: ManuallyDrop::new(Padded { byte: 3, word: 41 }) });
    assert_eq!(unsafe { u.padded.word }, 41);
}

#[kani::proof]
fn padded_typed_c() {
    let p = Padded { byte: 7, word: 11 };
    let u = CU { padded: ManuallyDrop::new(p) };
    assert_eq!(unsafe { (&(*(&u as *const CU)).padded).byte }, 7);
    assert_eq!(unsafe { (&(*(&u as *const CU)).padded).word }, 11);
}
#[kani::proof]
fn padded_typed_rust() {
    let p = Padded { byte: 13, word: 17 };
    let u = RU { padded: ManuallyDrop::new(p) };
    assert_eq!(unsafe { (&(*(&u as *const RU)).padded).byte }, 13);
    assert_eq!(unsafe { (&(*(&u as *const RU)).padded).word }, 17);
}
#[kani::proof]
fn padded_tuple_typed_c() {
    let u = CU { tuple: ManuallyDrop::new((2, 151)) };
    assert_eq!(unsafe { (&(*(&u as *const CU)).tuple).0 }, 2);
    assert_eq!(unsafe { (&(*(&u as *const CU)).tuple).1 }, 151);
}
#[kani::proof]
fn padded_tuple_typed_rust() {
    let u = RU { tuple: ManuallyDrop::new((3, 157)) };
    assert_eq!(unsafe { (&(*(&u as *const RU)).tuple).0 }, 3);
    assert_eq!(unsafe { (&(*(&u as *const RU)).tuple).1 }, 157);
}
#[kani::proof]
fn padded_typed_copy_c() {
    let src = CU { padded: ManuallyDrop::new(Padded { byte: 19, word: 23 }) };
    let mut dst = CU { z: () };
    unsafe {
        ptr::write(&mut dst, ptr::read(&src));
        assert_eq!((&(*(&dst as *const CU)).padded).word, 23);
    }
}
#[kani::proof]
fn padded_typed_copy_rust() {
    let src = RU { padded: ManuallyDrop::new(Padded { byte: 29, word: 31 }) };
    let mut dst = RU { z: () };
    unsafe {
        ptr::write(&mut dst, ptr::read(&src));
        assert_eq!((&(*(&dst as *const RU)).padded).word, 31);
    }
}

#[kani::proof]
fn array_field_c() {
    let u = CU { pair: [61, 67] };
    assert_eq!(unsafe { (*(&u as *const CU)).pair[1] }, 67);
}
#[kani::proof]
fn array_field_rust() {
    let u = RU { pair: [71, 73] };
    assert_eq!(unsafe { (*(&u as *const RU)).pair[1] }, 73);
}
#[kani::proof]
fn array_padded_field_c() {
    let a = [Padded { byte: 1, word: 2 }, Padded { byte: 3, word: 5 }];
    let u = CU { padded: ManuallyDrop::new(a[1]) };
    assert_eq!(unsafe { (&(*(&u as *const CU)).padded).word }, 5);
}
#[kani::proof]
fn array_zst_field_c() {
    let u = CU { z: () };
    assert_eq!(unsafe { (*(&u as *const CU)).zst_array[1] }, ());
}
#[kani::proof]
fn array_zst_field_rust() {
    let u = RU { z: () };
    assert_eq!(unsafe { (*(&u as *const RU)).zst_array[1] }, ());
}
#[kani::proof]
fn array_padded_elements_c() {
    let u = CU {
        padded_pair: [
            ManuallyDrop::new(Padded { byte: 2, word: 3 }),
            ManuallyDrop::new(Padded { byte: 5, word: 7 }),
        ],
    };
    assert_eq!(unsafe { (&(*(&u as *const CU)).padded_pair[1]).word }, 7);
}
#[kani::proof]
fn array_padded_elements_rust() {
    let u = RU {
        padded_pair: [
            ManuallyDrop::new(Padded { byte: 11, word: 13 }),
            ManuallyDrop::new(Padded { byte: 17, word: 19 }),
        ],
    };
    assert_eq!(unsafe { (&(*(&u as *const RU)).padded_pair[1]).word }, 19);
}

#[kani::proof]
fn zst_field_no_reset_c() {
    let mut u = CU { wide: 0x76543210 };
    let p = &mut u as *mut CU;
    unsafe {
        (*p).z = ();
        assert_eq!((*p).wide, 0x76543210);
    }
}
#[kani::proof]
fn zst_field_no_reset_rust() {
    let mut u = RU { wide: 0x76543210 };
    let p = &mut u as *mut RU;
    unsafe {
        (*p).z = ();
        assert_eq!((*p).wide, 0x76543210);
    }
}

// The backing is aligned raw bytes, not an array of by-value union elements.
#[repr(align(8))]
struct RawBacking([u8; 32]);
#[kani::proof]
fn aligned_tail_untyped_copy_c() {
    let mut backing = RawBacking([0u8; 32]);
    let base = backing.0.as_mut_ptr().cast::<u8>();
    unsafe {
        ptr::write_bytes(base, 0x5a, std::mem::size_of::<TailC>());
        let src = base.cast::<TailC>();
        let dst = base.add(std::mem::size_of::<TailC>()).cast::<TailC>();
        ptr::copy_nonoverlapping(src, dst, 1);
        assert_eq!(*tail_c_padding(dst), 0x5a);
    }
}
#[kani::proof]
fn aligned_tail_untyped_copy_rust() {
    let mut backing = RawBacking([0u8; 32]);
    let base = backing.0.as_mut_ptr().cast::<u8>();
    unsafe {
        ptr::write_bytes(base, 0x6b, std::mem::size_of::<TailR>());
        let src = base.cast::<TailR>();
        let dst = base.add(std::mem::size_of::<TailR>()).cast::<TailR>();
        ptr::copy(src, dst, 1);
        assert_eq!(*tail_r_padding(dst), 0x6b);
    }
}

#[kani::proof]
fn address_only_c() {
    let u = CU { z: () };
    let p = &u as *const CU;
    let field = unsafe { ptr::addr_of!((*p).wide) };
    assert!(!field.is_null());
}
#[kani::proof]
fn address_only_rust() {
    let u = RU { z: () };
    let p = &u as *const RU;
    let field = unsafe { ptr::addr_of!((*p).wide) };
    assert!(!field.is_null());
}

#[kani::proof]
fn pointer_alias_c() {
    let mut target = 79u32;
    let mut u = CU { ptr: &mut target };
    let p = &mut u as *mut CU;
    unsafe {
        (*p).ptr = &mut target;
        let q = (*p).ptr;
        assert_eq!(*q, 79);
    }
}
#[kani::proof]
fn pointer_alias_rust() {
    let mut target = 83u32;
    let mut u = RU { ptr: &mut target };
    let p = &mut u as *mut RU;
    unsafe {
        (*p).ptr = &mut target;
        let q = (*p).ptr;
        assert_eq!(*q, 83);
    }
}
#[kani::proof]
fn pointer_compound_read_c() {
    let mut target = 101u32;
    let mut u = CU { ptr: &mut target };
    let p = &mut u as *mut CU;
    unsafe {
        let value = *(*p).ptr;
        assert_eq!(value, 101);
    }
}
#[kani::proof]
fn pointer_compound_read_rust() {
    let mut target = 103u32;
    let mut u = RU { ptr: &mut target };
    let p = &mut u as *mut RU;
    unsafe {
        let value = *(*p).ptr;
        assert_eq!(value, 103);
    }
}
#[kani::proof]
fn pointer_compound_store_c() {
    let mut target = 0u32;
    let mut u = CU { ptr: &mut target };
    let p = &mut u as *mut CU;
    unsafe {
        *(*p).ptr = 107;
        assert_eq!(target, 107);
    }
}
#[kani::proof]
fn pointer_compound_store_rust() {
    let mut target = 0u32;
    let mut u = RU { ptr: &mut target };
    let p = &mut u as *mut RU;
    unsafe {
        *(*p).ptr = 109;
        assert_eq!(target, 109);
    }
}

#[kani::proof]
fn pointer_argument_return_c() {
    let mut target = 139u32;
    let value = identity_c(CU { ptr: &mut target });
    unsafe {
        assert_eq!(*value.ptr, 139);
    }
}
#[kani::proof]
fn pointer_argument_return_rust() {
    let mut target = 149u32;
    let value = identity_rust(RU { ptr: &mut target });
    unsafe {
        assert_eq!(*value.ptr, 149);
    }
}
#[kani::proof]
fn pointer_delayed_c() {
    let src = CU { wide: 37 };
    let mut local = 0u32;
    let holder = identity_c(CU { ptr: &mut local });
    let q = unsafe { holder.ptr };
    unsafe {
        ptr::copy_nonoverlapping(
            (&src as *const CU).cast::<u8>(),
            q.cast::<u8>(),
            std::mem::size_of::<u32>(),
        );
        assert_eq!(local, 37);
    }
}
#[kani::proof]
fn pointer_delayed_rust() {
    let src = RU { wide: 41 };
    let mut local = 0u32;
    let holder = identity_rust(RU { ptr: &mut local });
    let q = unsafe { holder.ptr };
    unsafe {
        ptr::copy_nonoverlapping(
            (&src as *const RU).cast::<u8>(),
            q.cast::<u8>(),
            std::mem::size_of::<u32>(),
        );
        assert_eq!(local, 41);
    }
}
#[kani::proof]
fn fat_pointer_field_c() {
    let data = [2u8, 3, 5];
    let u = CU { fat: &data[..] };
    unsafe {
        let s = (*(&u as *const CU)).fat;
        assert_eq!(s.len(), 3);
        assert_eq!(*(s as *const u8).add(2), 5);
    }
}
#[kani::proof]
fn fat_pointer_field_rust() {
    let data = [7u8, 11];
    let u = RU { fat: &data[..] };
    unsafe {
        let s = (*(&u as *const RU)).fat;
        assert_eq!(s.len(), 2);
        assert_eq!(*(s as *const u8).add(1), 11);
    }
}

#[repr(C)]
union ZC {
    a: (),
    b: [(); 0],
}
union ZR {
    a: (),
    b: [(); 0],
}
#[inline(never)]
fn zc(x: ZC) -> ZC {
    x
}
#[inline(never)]
fn zr(x: ZR) -> ZR {
    x
}
#[kani::proof]
fn size0_union_copy_argument_return_c() {
    let x = zc(ZC { a: () });
    let y = unsafe { ptr::read(&x) };
    let _ = zc(y);
}
#[kani::proof]
fn size0_union_copy_argument_return_rust() {
    let x = zr(ZR { a: () });
    let y = unsafe { ptr::read(&x) };
    let _ = zr(y);
}

#[repr(C)]
struct NonCopyWord {
    word: u32,
}
union NonCopyFieldC {
    value: ManuallyDrop<NonCopyWord>,
    z: (),
}
union NonCopyFieldR {
    value: ManuallyDrop<NonCopyWord>,
    z: (),
}

#[kani::proof]
fn field_move_constructor_c() {
    let source = ManuallyDrop::new(NonCopyWord { word: 223 });
    let union = NonCopyFieldC { value: source };
    assert_eq!(unsafe { union.value.word }, 223);
}
#[kani::proof]
fn field_move_constructor_rust() {
    let source = ManuallyDrop::new(NonCopyWord { word: 227 });
    let union = NonCopyFieldR { value: source };
    assert_eq!(unsafe { union.value.word }, 227);
}
#[kani::proof]
fn field_move_projection_c() {
    let source = ManuallyDrop::new(NonCopyWord { word: 229 });
    let mut union = NonCopyFieldC { z: () };
    let union_ptr = &mut union as *mut NonCopyFieldC;
    unsafe {
        (*union_ptr).value = source;
        assert_eq!((&(*union_ptr).value).word, 229);
    }
}
#[kani::proof]
fn field_move_projection_rust() {
    let source = ManuallyDrop::new(NonCopyWord { word: 233 });
    let mut union = NonCopyFieldR { z: () };
    let union_ptr = &mut union as *mut NonCopyFieldR;
    unsafe {
        (*union_ptr).value = source;
        assert_eq!((&(*union_ptr).value).word, 233);
    }
}
