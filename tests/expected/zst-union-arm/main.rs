// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Regression tests for zero-sized union fields, padded layouts, and typed copies.

use std::mem::{align_of, offset_of, size_of, size_of_val};
use std::ptr;

#[repr(C)]
union ArrayUnion {
    bytes: [u8; 8],
    zst_array: [(); 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Padded {
    byte: u8,
    word: u32,
}

#[repr(C)]
union PaddedUnionC {
    padded: Padded,
    zst_array: [(); 2],
}

union PaddedUnionRust {
    padded: Padded,
    zst_array: [(); 2],
}

#[repr(align(8))]
#[derive(Clone, Copy)]
struct Z;

#[repr(C)]
union AlignedUnion {
    bytes: [u8; 8],
    zst: Z,
}

#[repr(C)]
struct AtOffset {
    prefix: u64,
    value: ArrayUnion,
}

#[repr(C)]
union AllZst {
    aligned: Z,
    unit: (),
    zst_array: [(); 2],
}

#[kani::proof]
fn array_typed_copy() {
    let mut src = ArrayUnion { zst_array: [(); 2] };
    let mut dst = ArrayUnion { zst_array: [(); 2] };
    unsafe {
        ptr::write_bytes((&mut src as *mut ArrayUnion).cast::<u8>(), 0x5a, size_of::<ArrayUnion>());
        ptr::write(&mut dst, ptr::read(&src));
        assert_eq!(size_of_val(&dst.zst_array[1]), 0);
        // This union's byte arm covers every byte: there is no padding to read.
        assert_eq!(dst.bytes, [0x5a; 8]);
    }
}

// Exercise a padded payload without reading its padding after the typed copy.
#[kani::proof]
fn padded_typed_copy_c() {
    let mut src = PaddedUnionC { padded: Padded { byte: 4, word: 5 } };
    let mut dst = PaddedUnionC { zst_array: [(); 2] };
    unsafe {
        ptr::write_bytes(
            (&mut src as *mut PaddedUnionC).cast::<u8>(),
            0x5a,
            size_of::<PaddedUnionC>(),
        );
        ptr::write(&mut dst, ptr::read(&src));
        assert_eq!(size_of_val(&dst.zst_array[1]), 0);
        assert_eq!(dst.padded.byte, 0x5a);
        assert_eq!(dst.padded.word, 0x5a5a5a5a);
    }
}

#[kani::proof]
fn padded_typed_copy_rust() {
    let mut src = PaddedUnionRust { padded: Padded { byte: 4, word: 5 } };
    let mut dst = PaddedUnionRust { zst_array: [(); 2] };
    unsafe {
        ptr::write_bytes(
            (&mut src as *mut PaddedUnionRust).cast::<u8>(),
            0x5a,
            size_of::<PaddedUnionRust>(),
        );
        ptr::write(&mut dst, ptr::read(&src));
        assert_eq!(size_of_val(&dst.zst_array[1]), 0);
        assert_eq!(dst.padded.byte, 0x5a);
        assert_eq!(dst.padded.word, 0x5a5a5a5a);
    }
}

#[kani::proof]
fn aligned_zst_typed_copy() {
    let mut src = AlignedUnion { zst: Z };
    let mut dst = AlignedUnion { zst: Z };
    unsafe {
        ptr::write_bytes(
            (&mut src as *mut AlignedUnion).cast::<u8>(),
            0x5a,
            size_of::<AlignedUnion>(),
        );
        ptr::write(&mut dst, ptr::read(&src));
        let z = dst.zst;
        assert_eq!(size_of_val(&z), 0);
        assert_eq!(align_of::<AlignedUnion>(), 8);
        assert_eq!(dst.bytes, [0x5a; 8]);
    }
}

#[kani::proof]
fn zst_arm_at_nonzero_offset() {
    // Union arms themselves start at zero; place the containing union at offset 8.
    let mut src = AtOffset { prefix: 17, value: ArrayUnion { zst_array: [(); 2] } };
    let mut dst = AtOffset { prefix: 23, value: ArrayUnion { zst_array: [(); 2] } };
    assert_eq!(offset_of!(AtOffset, value), 8);
    unsafe {
        ptr::write_bytes(
            (&mut src.value as *mut ArrayUnion).cast::<u8>(),
            0x5a,
            size_of::<ArrayUnion>(),
        );
        ptr::write(&mut dst.value, ptr::read(&src.value));
        assert_eq!(size_of_val(&dst.value.zst_array[1]), 0);
        assert_eq!(dst.value.bytes, [0x5a; 8]);
    }
    assert_eq!(src.prefix, 17);
    assert_eq!(dst.prefix, 23);
}

#[kani::proof]
fn all_zst_union() {
    let mut src = AllZst { unit: () };
    let mut dst = AllZst { aligned: Z };
    assert_eq!(size_of::<AllZst>(), 0);
    assert_eq!(align_of::<AllZst>(), 8);
    unsafe {
        // Even with count zero, the pointer is valid and sufficiently aligned.
        ptr::write_bytes((&mut src as *mut AllZst).cast::<u8>(), 0x5a, size_of::<AllZst>());
        ptr::write(&mut dst, ptr::read(&src));
        assert_eq!(size_of_val(&dst.unit), 0);
        assert_eq!(size_of_val(&dst.zst_array[1]), 0);
        let z = dst.aligned;
        assert_eq!(size_of_val(&z), 0);
    }
}

#[kani::proof]
fn zst_array_indexing() {
    let mut value = ArrayUnion { zst_array: [(); 2] };
    let index: usize = kani::any();
    kani::assume(index < 2);
    unsafe {
        let array = value.zst_array;
        assert_eq!(size_of_val(&array[index]), 0);
        value.zst_array[index] = ();
        let element = &value.zst_array[index];
        assert_eq!(size_of_val(element), 0);
        assert_eq!(value.zst_array.len(), 2);
    }
}

mod array_first {
    use std::mem::{size_of, size_of_val};
    use std::ptr;

    #[repr(C)]
    union Edge {
        zst: [(); 2],
        bytes: [u8; 16],
    }

    #[kani::proof]
    fn copy_array_first() {
        let mut src = Edge { zst: [(); 2] };
        let mut dst = Edge { zst: [(); 2] };
        assert_eq!(size_of::<[(); 2]>(), 0);
        assert_eq!(size_of::<Edge>(), 16);
        unsafe {
            ptr::write_bytes((&mut src as *mut Edge).cast::<u8>(), 0x5a, size_of::<Edge>());
            ptr::write(&mut dst, ptr::read(&src));
            assert_eq!(dst.zst.len(), 2);
            assert_eq!(size_of_val(&dst.zst[1]), 0);

            // The byte arm spans the full extent; these are initialized data bytes.
            assert_eq!(dst.bytes, [0x5a; 16]);
            kani::cover!(
                dst.bytes[15] == 0x5a && dst.zst.len() == 2,
                "copy_array_first post-copy data and projection"
            );
        }
    }
}

mod nested_unit_array {
    use std::mem::{size_of, size_of_val};
    use std::ptr;

    #[repr(C)]
    union Edge {
        zst: [[(); 2]; 3],
        bytes: [u8; 16],
    }

    #[kani::proof]
    fn copy_nested_unit_array() {
        let mut src = Edge { zst: [[(); 2]; 3] };
        let mut dst = Edge { zst: [[(); 2]; 3] };
        assert_eq!(size_of::<[[(); 2]; 3]>(), 0);
        assert_eq!(size_of::<Edge>(), 16);
        unsafe {
            ptr::write_bytes((&mut src as *mut Edge).cast::<u8>(), 0x5a, size_of::<Edge>());
            ptr::write(&mut dst, ptr::read(&src));
            assert_eq!(dst.zst[2].len(), 2);
            assert_eq!(size_of_val(&dst.zst[2][1]), 0);
            assert_eq!(dst.zst.len(), 3);
            // The byte arm spans the full extent; these are initialized data bytes.
            assert_eq!(dst.bytes, [0x5a; 16]);
            kani::cover!(
                dst.bytes[15] == 0x5a && dst.zst[2].len() == 2,
                "copy_nested_unit_array post-copy data and projection"
            );
        }
    }
}

mod nested_empty_byte_array {
    use std::mem::{size_of, size_of_val};
    use std::ptr;

    #[repr(C)]
    union Edge {
        zst: [[u8; 0]; 2],
        bytes: [u8; 16],
    }

    #[kani::proof]
    fn copy_nested_empty_byte_array() {
        let mut src = Edge { zst: [[0u8; 0]; 2] };
        let mut dst = Edge { zst: [[0u8; 0]; 2] };
        assert_eq!(size_of::<[[u8; 0]; 2]>(), 0);
        assert_eq!(size_of::<Edge>(), 16);
        unsafe {
            ptr::write_bytes((&mut src as *mut Edge).cast::<u8>(), 0x5a, size_of::<Edge>());
            ptr::write(&mut dst, ptr::read(&src));
            assert_eq!(dst.zst.len(), 2);
            assert_eq!(size_of_val(&dst.zst[1]), 0);
            assert_eq!(dst.zst[1].len(), 0);
            // The byte arm spans the full extent; these are initialized data bytes.
            assert_eq!(dst.bytes, [0x5a; 16]);
            kani::cover!(
                dst.bytes[15] == 0x5a && dst.zst.len() == 2,
                "copy_nested_empty_byte_array post-copy data and projection"
            );
        }
    }
}

mod aligned_array {
    use std::mem::{align_of, size_of, size_of_val};
    use std::ptr;

    #[repr(align(8))]
    #[derive(Clone, Copy)]
    struct Z;

    #[repr(C)]
    union Edge {
        zst: [Z; 2],
        bytes: [u8; 16],
    }

    #[kani::proof]
    fn copy_aligned_array() {
        let mut src = Edge { zst: [Z; 2] };
        let mut dst = Edge { zst: [Z; 2] };
        assert_eq!(size_of::<[Z; 2]>(), 0);
        assert_eq!(size_of::<Edge>(), 16);
        unsafe {
            ptr::write_bytes((&mut src as *mut Edge).cast::<u8>(), 0x5a, size_of::<Edge>());
            ptr::write(&mut dst, ptr::read(&src));
            assert_eq!(dst.zst.len(), 2);
            assert_eq!(size_of_val(&dst.zst[1]), 0);
            assert_eq!(align_of::<[Z; 2]>(), 8);
            assert_eq!(align_of::<Edge>(), 8);
            // The byte arm spans the full extent; these are initialized data bytes.
            assert_eq!(dst.bytes, [0x5a; 16]);
            kani::cover!(
                dst.bytes[15] == 0x5a && dst.zst.len() == 2,
                "copy_aligned_array post-copy data and projection"
            );
        }
    }
}

mod struct_array {
    use std::mem::{size_of, size_of_val};
    use std::ptr;

    #[derive(Clone, Copy)]
    struct Wrapped {
        array: [(); 2],
    }

    #[repr(C)]
    union Edge {
        zst: Wrapped,
        bytes: [u8; 16],
    }

    #[kani::proof]
    fn copy_struct_array() {
        let mut src = Edge { zst: Wrapped { array: [(); 2] } };
        let mut dst = Edge { zst: Wrapped { array: [(); 2] } };
        assert_eq!(size_of::<Wrapped>(), 0);
        assert_eq!(size_of::<Edge>(), 16);
        unsafe {
            ptr::write_bytes((&mut src as *mut Edge).cast::<u8>(), 0x5a, size_of::<Edge>());
            ptr::write(&mut dst, ptr::read(&src));
            assert_eq!(dst.zst.array.len(), 2);
            assert_eq!(size_of_val(&dst.zst.array[1]), 0);

            // The byte arm spans the full extent; these are initialized data bytes.
            assert_eq!(dst.bytes, [0x5a; 16]);
            kani::cover!(
                dst.bytes[15] == 0x5a && dst.zst.array.len() == 2,
                "copy_struct_array post-copy data and projection"
            );
        }
    }
}
