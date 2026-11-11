#[repr(transparent)]
struct Word([u8; 4]);

fn main() {
    println!("mem_forget: std::mem::forget(non-Copy); reread original bytes");
    let src = Word([0x51; 4]);
    let source_bytes = std::ptr::addr_of!(src).cast::<u8>();
    std::mem::forget(src);
    // Observe the original allocation, never the destination or a reconstructed pointer.
    // u8 has alignment 1 and every initialized bit pattern is valid.
    for offset in 0..4 {
        let _byte = unsafe { source_bytes.add(offset).read_volatile() };
    }
    println!("original source: all four byte reads completed");
}
