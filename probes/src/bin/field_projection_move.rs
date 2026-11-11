#[repr(transparent)]
struct Word([u8; 4]);

#[repr(C)]
struct Pair {
    first: Word,
    sibling: Word,
}

fn main() {
    println!("field_projection_move: move src.first by assignment; reread original field bytes");
    let src = Pair { first: Word([0x51; 4]), sibling: Word([0x72; 4]) };
    let source_bytes = std::ptr::addr_of!(src.first).cast::<u8>();
    let dst = src.first;
    let _destination_byte = unsafe { std::ptr::addr_of!(dst).cast::<u8>().read_volatile() };
    // Observe the original allocation, never the destination or a reconstructed pointer.
    // u8 has alignment 1 and every initialized bit pattern is valid.
    for offset in 0..4 {
        let _byte = unsafe { source_bytes.add(offset).read_volatile() };
    }
    println!("original source: all four byte reads completed");
}
