use std::mem::MaybeUninit;

#[repr(transparent)]
struct Word([u8; 4]);

fn main() {
    println!("maybe_uninit_assignment: move initialized MaybeUninit<non-Copy> by assignment");
    let src = MaybeUninit::new(Word([0x51; 4]));
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
