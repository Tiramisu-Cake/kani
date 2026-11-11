// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
use std::mem::MaybeUninit;
#[repr(C)]
struct Alive { start: usize, end: usize }
struct P { alive: Alive, data: [MaybeUninit<usize>; 2] }
#[inline(never)]
fn moved(p: P) -> P { p }
#[kani::proof]
fn aggregate_and_move_keep_ordinary_pair() {
    let p = P { alive: Alive { start: 0, end: 2 }, data: [MaybeUninit::new(7), MaybeUninit::uninit()] };
    let p = moved(p);
    assert_eq!(p.alive.end - p.alive.start, 2);
    assert_eq!(unsafe { p.data[0].assume_init() }, 7);
    kani::cover!(true);
}
