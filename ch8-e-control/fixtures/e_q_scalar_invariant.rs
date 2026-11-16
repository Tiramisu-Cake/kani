#![feature(stmt_expr_attributes)]
#![feature(proc_macro_hygiene)]

#[kani::proof]
fn e_q_scalar_invariant() {
    let values = [1u8, 2];
    let p = values.as_ptr();
    let mut remaining: usize = 1;

    // The raw read is a scalar predicate outside any quantifier.
    #[kani::loop_invariant(unsafe { *p == 1 })]
    #[kani::loop_modifies(&remaining)]
    #[kani::loop_decreases(remaining)]
    while remaining != 0 {
        remaining -= 1;
    }

    assert_eq!(unsafe { *p }, 1);
    kani::cover(remaining == 0, "E-Q scalar loop returns");
}
