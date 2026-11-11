// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
use std::mem::{ManuallyDrop, MaybeUninit};
#[repr(C)]
struct Alive { start: usize, end: usize }
struct P { alive: Alive, data: [MaybeUninit<usize>; 2] }
#[inline(never)]
fn moved(p: ManuallyDrop<P>) -> ManuallyDrop<P> { p }
#[kani::proof]
fn manually_drop_keeps_ordinary_pair() {
    let p = P { alive: Alive { start: 0, end: 2 }, data: [MaybeUninit::new(7), MaybeUninit::uninit()] };
    let p = moved(ManuallyDrop::new(p));
    assert_eq!(p.alive.end - p.alive.start, 2);
    assert_eq!(unsafe { p.data[0].assume_init() }, 7);
    kani::cover!(true);
}
