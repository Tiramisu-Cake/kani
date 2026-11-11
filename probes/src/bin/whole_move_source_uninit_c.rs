// Historical type: no Copy implementation and no repr attribute (also for MoveC).
#[allow(dead_code)]
union MoveC {
    wide: u32,
    narrow: u8,
    z: (),
}

fn main() {
    println!("whole_move_source_uninit_c: historical union assignment Move; reread original bytes");
    let src = MoveC { wide: 173 };
    let source_bytes = std::ptr::addr_of!(src).cast::<u8>();
    let dst = src;
    let _destination_byte = unsafe { std::ptr::addr_of!(dst).cast::<u8>().read_volatile() };
    // Observe the original allocation, never the destination or a reconstructed pointer.
    // u8 has alignment 1 and every initialized bit pattern is valid.
    for offset in 0..4 {
        let _byte = unsafe { source_bytes.add(offset).read_volatile() };
    }
    println!("original source: all four byte reads completed");
}
