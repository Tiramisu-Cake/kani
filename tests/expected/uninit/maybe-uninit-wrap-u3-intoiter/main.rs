// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular

#[kani::proof]
fn complete_standard_into_iter() {
    let source = [7usize, 9usize];
    let mut iterator = IntoIterator::into_iter(source);
    assert_eq!(iterator.next(), Some(7));
    assert_eq!(iterator.next(), Some(9));
    assert_eq!(iterator.next(), None);
}
