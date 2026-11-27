// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Regression test for ordering on symbolic booleans (issue #5232).

use std::cmp::{self, Ordering};

#[kani::proof]
fn bool_order_probe() {
    let a: bool = kani::any();
    let b: bool = kani::any();
    kani::cover!(a != b);
    kani::assert((a < b) == (!a && b), "bool less-than matches its truth table");
}

#[kani::proof]
fn bool_order_u8_control() {
    let a: bool = kani::any();
    let b: bool = kani::any();
    kani::cover!(a != b);
    kani::assert(((a as u8) < (b as u8)) == (!a && b), "u8 less-than matches the bool truth table");
}

#[kani::proof]
fn bool_order_other_comparisons() {
    let a: bool = kani::any();
    let b: bool = kani::any();

    assert!((a <= b) == (!a || b));
    assert!((a > b) == (a && !b));
    assert!((a >= b) == (a || !b));

    let expected = match (a, b) {
        (false, true) => Ordering::Less,
        (true, false) => Ordering::Greater,
        _ => Ordering::Equal,
    };
    assert!(a.cmp(&b) == expected);
    assert!(cmp::min(a, b) == (a && b));
    assert!(cmp::max(a, b) == (a || b));
}
