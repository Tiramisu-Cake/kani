#[inline(never)]
fn consume(value: [u8; 4]) {
    assert_eq!(value[0], 0x51);
}

fn main() {
    println!("copy_call: Copy by-value call; reread original bytes");
    let src = [0x51_u8; 4];
    let source_bytes = std::ptr::addr_of!(src).cast::<u8>();
    consume(src);
    // Observe the original allocation, never the destination or a reconstructed pointer.
    // u8 has alignment 1 and every initialized bit pattern is valid.
    for offset in 0..4 {
        let _byte = unsafe { source_bytes.add(offset).read_volatile() };
    }
    println!("original source: all four byte reads completed");
}
