use std::alloc::{alloc, dealloc, Layout};
use std::ptr::NonNull;

#[repr(C)] struct S { a: u64, p: NonNull<u8> } // p at bytes 8..16

// Initialize only `a`, then read the whole value.
unsafe fn read_half_init<X>() {
    let lay = Layout::new::<X>();
    let base = alloc(lay);
    base.write_bytes(1, 8);
    let x: X = std::ptr::read(base as *const X); // UB: bytes 8..16 uninit
    std::mem::forget(x);
    dealloc(base, lay);
}

#[cfg_attr(kani, kani::proof)]
fn nonnull_field() { unsafe { read_half_init::<S>() } }
