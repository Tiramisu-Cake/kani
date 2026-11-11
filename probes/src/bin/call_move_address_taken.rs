#[repr(transparent)]
struct Word([u8; 4]);

#[inline(never)]
fn consume(value: Word) {
    // Also force a callee parameter allocation; do not access the caller during the call.
    let parameter_bytes = std::ptr::addr_of!(value).cast::<u8>();
    let _byte = unsafe { parameter_bytes.read_volatile() };
}

fn main() {
    println!("call_move_address_taken: by-value call; caller and callee parameter addresses taken");
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
