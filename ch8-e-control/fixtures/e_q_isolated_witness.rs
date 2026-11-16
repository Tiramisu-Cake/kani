#![feature(proc_macro_hygiene)]

#[kani::proof]
fn e_q_isolated_witness() {
    let values = [1u8, 2];
    let p = values.as_ptr();
    assert!(kani::exists!(|i in (0, 2)| unsafe { *p.add(i) == 2 }));
}
