#![feature(core_intrinsics)]
#![allow(internal_features)]

use std::mem::ManuallyDrop;

#[repr(C)]
struct NonCopyWord {
    word: u32,
}

// Historical union has default representation, including the C-suffixed name.
#[allow(dead_code)]
union NonCopyFieldR {
    value: ManuallyDrop<NonCopyWord>,
    z: (),
}

fn main() {
    println!("field_move_projection_source_uninit_rust: historical move into union field projection, then intrinsic forget");
    let source = ManuallyDrop::new(NonCopyWord { word: 211 });
    let source_bytes = std::ptr::addr_of!(source).cast::<u8>();
    let mut union = NonCopyFieldR { z: () };
    let union_ptr = std::ptr::addr_of_mut!(union);
    unsafe { (*union_ptr).value = source; }
    let _destination_byte = unsafe { std::ptr::addr_of!(union).cast::<u8>().read_volatile() };
    std::intrinsics::forget(union);
    // Observe the original allocation, never the destination or a reconstructed pointer.
    // u8 has alignment 1 and every initialized bit pattern is valid.
    for offset in 0..4 {
        let _byte = unsafe { source_bytes.add(offset).read_volatile() };
    }
    println!("original source: all four byte reads completed");
}
