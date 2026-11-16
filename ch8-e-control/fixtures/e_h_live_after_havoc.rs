#![feature(stmt_expr_attributes)]
#![feature(proc_macro_hygiene)]

use std::mem::MaybeUninit;

#[kani::proof]
fn e_h_live_after_havoc() {
    let mut region = [MaybeUninit::new(17u8), MaybeUninit::new(23u8)];
    let alias_to_fixed_witness = region[1].as_ptr();
    let live_ptr = region[0].as_mut_ptr();
    let frame = std::ptr::slice_from_raw_parts_mut(region.as_mut_ptr().cast::<u8>(), 2);
    let mut remaining = 1usize;

    #[kani::loop_invariant(remaining <= 1)]
    #[kani::loop_modifies(&remaining, frame)]
    #[kani::loop_decreases(remaining)]
    while remaining != 0 {
        kani::cover(remaining == 1, "E-H live loop body reached");
        unsafe { live_ptr.write(41) };
        remaining -= 1;
    }

    let fixed_value = unsafe { *alias_to_fixed_witness };
    kani::cover(fixed_value == 23, "E-H fixed initialized witness read");
}
