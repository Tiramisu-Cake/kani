#![feature(stmt_expr_attributes)]
#![feature(proc_macro_hygiene)]

#[kani::proof]
fn e_q_pointer_loop() {
    let values = [1u8, 2];
    let p = values.as_ptr();
    let mut remaining: usize = 1;

    #[kani::loop_invariant(kani::exists!(|i in (0, 2)| unsafe { *p.add(i) == 2 }))]
    #[kani::loop_modifies(&remaining)]
    #[kani::loop_decreases(remaining)]
    while remaining != 0 {
        remaining -= 1;
    }

    kani::cover(remaining == 0, "E-Q pointer loop returns");
}
