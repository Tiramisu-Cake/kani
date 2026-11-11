use std::mem::MaybeUninit;

#[repr(transparent)]
struct Word([u8; 4]);

fn main() {
    println!("maybe_uninit_uninit_control: uninitialized MaybeUninit byte read; detector control");
    let src = MaybeUninit::<Word>::uninit();
    let source_bytes = std::ptr::addr_of!(src).cast::<u8>();
    let dst = src;
    // Moving MaybeUninit is allowed; do not read its uninitialized destination.
    let _ = std::ptr::addr_of!(dst);
    // Observe the original allocation, never the destination or a reconstructed pointer.
    // u8 has alignment 1 and every initialized bit pattern is valid.
    for offset in 0..4 {
        let _byte = unsafe { source_bytes.add(offset).read_volatile() };
    }
    println!("original source: all four byte reads completed");
}
