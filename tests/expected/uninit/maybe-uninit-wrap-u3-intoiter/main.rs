// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular --default-unwind 8

#[kani::proof]
fn complete_standard_into_iter() {
    let source = [7usize, 9usize];
    let mut iterator = IntoIterator::into_iter(source);
    assert_eq!(iterator.next(), Some(7));
    assert_eq!(iterator.next(), Some(9));
    assert_eq!(iterator.next(), None);

    kani::cover!(true);
}

#[kani::proof]
fn empty_standard_into_iter_returns_none() {
    let values: [usize; 0] = [];
    let mut iterator = IntoIterator::into_iter(values);
    assert_eq!(iterator.next(), None);
    assert_eq!(iterator.len(), 0);

    kani::cover!(true);
}

struct DropToken<'a>(&'a std::cell::Cell<usize>);
impl Drop for DropToken<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[kani::proof]
fn early_drop_after_some_drops_only_remaining_elements() {
    let drops = std::cell::Cell::new(0);
    let mut iterator = IntoIterator::into_iter([DropToken(&drops), DropToken(&drops)]);
    drop(iterator.next().unwrap());
    assert_eq!(drops.get(), 1);
    drop(iterator);
    assert_eq!(drops.get(), 2);

    kani::cover!(true);
}
