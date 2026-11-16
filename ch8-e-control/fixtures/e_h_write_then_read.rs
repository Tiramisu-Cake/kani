#![feature(stmt_expr_attributes)]
#![feature(proc_macro_hygiene)]

use std::mem::MaybeUninit;

#[kani::proof]
fn e_h_write_then_read() {
    let mut destination = MaybeUninit::<u8>::uninit();
    let destination_ptr = destination.as_mut_ptr();
    let frame = std::ptr::slice_from_raw_parts_mut(destination_ptr, 1);
    let mut remaining = 1usize;

    #[kani::loop_invariant(remaining <= 1)]
    #[kani::loop_modifies(&remaining, frame)]
    #[kani::loop_decreases(remaining)]
    while remaining != 0 {
        kani::cover(remaining == 1, "E-H write loop body reached");
        unsafe { destination_ptr.write(41) };
        let written = unsafe { destination_ptr.read() };
        assert_eq!(written, 41);
        remaining -= 1;
    }
}
