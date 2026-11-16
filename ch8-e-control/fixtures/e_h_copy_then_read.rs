#![feature(stmt_expr_attributes)]
#![feature(proc_macro_hygiene)]

use std::mem::MaybeUninit;

#[kani::proof]
fn e_h_copy_then_read() {
    let source = MaybeUninit::new(53u8);
    let mut destination = MaybeUninit::<u8>::uninit();
    let source_ptr = source.as_ptr();
    let destination_ptr = destination.as_mut_ptr();
    let frame = std::ptr::slice_from_raw_parts_mut(destination_ptr, 1);
    let mut remaining = 1usize;

    #[kani::loop_invariant(remaining <= 1)]
    #[kani::loop_modifies(&remaining, frame)]
    #[kani::loop_decreases(remaining)]
    while remaining != 0 {
        kani::cover(remaining == 1, "E-H copy loop body reached");
        unsafe { std::ptr::copy_nonoverlapping(source_ptr, destination_ptr, 1) };
        let copied = unsafe { destination_ptr.read() };
        assert_eq!(copied, 53);
        remaining -= 1;
    }
}
