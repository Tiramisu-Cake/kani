#![feature(stmt_expr_attributes)]
#![feature(proc_macro_hygiene)]

#[kani::proof]
fn e_q_false_pointer_loop() {
    let values = [1u8, 2];
    let p = values.as_ptr();
    let mut remaining: usize = 1;

    // Deliberately false on the concrete base state; OFF must fail this invariant.
    #[kani::loop_invariant(kani::exists!(|i in (0, 2)| unsafe { *p.add(i) == 3 }))]
    #[kani::loop_modifies(&remaining)]
    #[kani::loop_decreases(remaining)]
    while remaining != 0 {
        remaining -= 1;
    }
}
