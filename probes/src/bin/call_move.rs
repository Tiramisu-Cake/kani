#[repr(transparent)]
struct Word([u8; 4]);

#[inline(never)]
fn consume(value: Word) {
    assert_eq!(value.0[0], 0x51);
}

fn main() {
    println!("call_move: non-Copy by-value call; caller source address taken");
    let src = Word([0x51; 4]);
    let source_bytes = std::ptr::addr_of!(src).cast::<u8>();
    consume(src);
    // Observe the original allocation, never the destination or a reconstructed pointer.
    // u8 has alignment 1 and every initialized bit pattern is valid.
    for offset in 0..4 {
        let _byte = unsafe { source_bytes.add(offset).read_volatile() };
    }
    println!("original source: all four byte reads completed");
}
