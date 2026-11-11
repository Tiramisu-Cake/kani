// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
use std::mem::{ManuallyDrop, MaybeUninit};
#[repr(C)]
struct Alive { start: usize, end: usize }
struct P<T: ?Sized> { alive: Alive, data: T }
#[kani::proof]
fn unsize_and_projection_keep_ordinary_pair() {
    let mut p = ManuallyDrop::new(P { alive: Alive { start: 0, end: 2 }, data: [MaybeUninit::new(7usize), MaybeUninit::uninit()] });
    let p: &mut P<[MaybeUninit<usize>]> = &mut *p;
    assert_eq!(p.alive.end - p.alive.start, 2);
    p.alive.start = 1;
    assert_eq!(p.alive.start, 1);
    assert_eq!(unsafe { p.data[0].assume_init() }, 7);
    kani::cover!(true);
}
