#![feature(stmt_expr_attributes)]
#![feature(proc_macro_hygiene)]

// E-02 primitive reduction. NOT RUN at either pin.
// Avoids MaybeUninit/union layout support as a confounding variable.
#[kani::proof]
fn shadow_write_u8_candidate() {
    let mut value = 17u8;
    let pointer = &mut value as *mut u8;
    let mut remaining = 1usize;

    #[kani::loop_invariant(remaining <= 1)]
    #[kani::loop_modifies(&remaining, pointer)]
    #[kani::loop_decreases(remaining)]
    while remaining != 0 {
        unsafe { pointer.write(41) };
        assert_eq!(unsafe { pointer.read() }, 41);
        remaining -= 1;
    }
    kani::cover(remaining == 0, "primitive write loop returns");
}
