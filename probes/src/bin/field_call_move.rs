#[repr(transparent)]
struct Word([u8; 4]);

#[repr(C)]
struct Pair {
    first: Word,
    sibling: Word,
}

#[inline(never)]
fn consume(value: Word) {
    assert_eq!(value.0[0], 0x51);
}

fn main() {
    println!("field_call_move: pass src.first by value; reread original field bytes");
    let src = Pair { first: Word([0x51; 4]), sibling: Word([0x72; 4]) };
    let source_bytes = std::ptr::addr_of!(src.first).cast::<u8>();
    consume(src.first);
    // Observe the original allocation, never the destination or a reconstructed pointer.
    // u8 has alignment 1 and every initialized bit pattern is valid.
    for offset in 0..4 {
        let _byte = unsafe { source_bytes.add(offset).read_volatile() };
    }
    println!("original source: all four byte reads completed");
}
