#![feature(core_intrinsics)]
#![allow(internal_features)]

// Historical type: no Copy implementation and no repr attribute (also for MoveC).
#[allow(dead_code)]
union MoveC {
    wide: u32,
    narrow: u8,
    z: (),
}

fn main() {
    println!("intrinsic_forget_move_source_uninit_c: historical union intrinsic forget; reread original bytes");
    let src = MoveC { wide: 239 };
    let source_bytes = std::ptr::addr_of!(src).cast::<u8>();
    std::intrinsics::forget(src);
    // Observe the original allocation, never the destination or a reconstructed pointer.
    // u8 has alignment 1 and every initialized bit pattern is valid.
    for offset in 0..4 {
        let _byte = unsafe { source_bytes.add(offset).read_volatile() };
    }
    println!("original source: all four byte reads completed");
}
