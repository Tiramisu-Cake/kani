#![feature(stmt_expr_attributes)]
#![feature(proc_macro_hygiene)]

use std::mem::MaybeUninit;

#[kani::proof]
fn e_h_outside_false_alias() {
    let mut region = [
        MaybeUninit::new(17u8),
        MaybeUninit::new(23u8),
        MaybeUninit::uninit(),
        MaybeUninit::new(77u8),
    ];
    let alias_outside_frame = region[2].as_ptr();
    let alias_to_sentinel = region[3].as_ptr();
    let live_ptr = region[0].as_mut_ptr();
    let frame = std::ptr::slice_from_raw_parts_mut(region.as_mut_ptr().cast::<u8>(), 2);
    let mut remaining = 1usize;

    #[kani::loop_invariant(remaining <= 1)]
    #[kani::loop_modifies(&remaining, frame)]
    #[kani::loop_decreases(remaining)]
    while remaining != 0 {
        kani::cover(remaining == 1, "E-H outside-frame loop body reached");
        unsafe { live_ptr.write(41) };
        remaining -= 1;
    }

    let sentinel = unsafe { *alias_to_sentinel };
    assert_eq!(sentinel, 77);
    kani::cover(sentinel == 77, "E-H outside sentinel preserved");

    // Expected ON uninit failure through a pre-existing raw alias.
    let false_value = unsafe { *alias_outside_frame };
    kani::cover(false_value == 0, "E-H outside false alias read result");
}
