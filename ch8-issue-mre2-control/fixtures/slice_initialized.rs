// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Candidate v2, NOT_RUN. Flags: -Z function-contracts -Z uninit-checks -Z stubbing.
use std::alloc::{alloc, dealloc, Layout};

// Safety: p points to a live, exclusively owned allocation of at least two bytes.
// These harnesses establish that condition with alloc; no initialized value is required.
#[kani::modifies(std::ptr::slice_from_raw_parts_mut(p, 2))]
unsafe fn initialize(p: *mut u8) {
    p.add(0).write(1);
    p.add(1).write(2);
}

#[kani::proof_for_contract(initialize)]
fn check_body() {
    let layout = Layout::array::<u8>(2).unwrap();
    unsafe {
        let p = alloc(layout);
        if p.is_null() { return; }
        p.add(0).write(0);
        p.add(1).write(0);
        initialize(p);
        dealloc(p, layout);
    }
}

#[kani::proof]
#[kani::stub_verified(initialize)]
fn check_slice_havoc() {
    let layout = Layout::array::<u8>(2).unwrap();
    unsafe {
        let p = alloc(layout);
        if p.is_null() { return; }
        p.add(0).write(0);
        p.add(1).write(0);
        initialize(p);
        dealloc(p, layout);
    }
}
