// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![cfg(kani)]

#[kani::requires(x < 8)]
#[kani::ensures(|result| *result == x + 1)]
fn f(x: u8) -> u8 {
    x + 1
}

fn g(x: u8) -> u8 {
    x + 2
}

#[kani::proof_for_contract(f)]
fn provider() {
    f(kani::any());
}

#[cfg(feature = "verified")]
#[kani::proof]
#[kani::stub_verified(f)]
fn verified_control() {
    let x: u8 = kani::any();
    kani::assume(x < 8);
    assert!(f(x) == x + 1);
}

#[cfg(feature = "ordinary")]
#[kani::proof]
#[kani::stub(f, g)]
fn ordinary_stub() {
    let x: u8 = kani::any();
    kani::assume(x < 8);
    assert!(f(x) == x + 2);
}
