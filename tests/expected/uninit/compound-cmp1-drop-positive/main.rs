// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular --default-unwind 8

use std::cell::Cell;
use std::mem::{ManuallyDrop, MaybeUninit};

struct Token<'a>(&'a Cell<usize>);
impl Drop for Token<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

#[kani::proof]
fn early_iterator_drop_drops_remaining_tokens_once() {
    let drops = Cell::new(0);
    let mut iter = IntoIterator::into_iter([Token(&drops), Token(&drops), Token(&drops)]);
    drop(iter.next().unwrap());
    assert_eq!(drops.get(), 1);
    drop(iter);
    assert_eq!(drops.get(), 3);

    kani::cover!(true);
}

#[kani::proof]
fn exhausted_iterator_does_not_redrop_yielded_tokens() {
    let drops = Cell::new(0);
    let mut iter = IntoIterator::into_iter([Token(&drops), Token(&drops)]);
    drop(iter.next().unwrap());
    drop(iter.next().unwrap());
    assert_eq!(drops.get(), 2);
    drop(iter);
    assert_eq!(drops.get(), 2);

    kani::cover!(true);
}

struct Wrapped<'a> {
    marker: usize,
    slot: MaybeUninit<usize>,
    token: Token<'a>,
}

#[kani::proof]
fn manually_drop_wrapper_without_explicit_drop_does_not_drop_or_read_payload() {
    let drops = Cell::new(0);
    let value = ManuallyDrop::new(Wrapped {
        marker: 41,
        slot: MaybeUninit::uninit(),
        token: Token(&drops),
    });
    assert_eq!(value.marker, 41);
    assert_eq!(drops.get(), 0);

    kani::cover!(true);
}
