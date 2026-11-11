// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
use std::mem::MaybeUninit;
#[repr(C)]
#[derive(Clone)]
struct Alive { start: usize, end: usize }
struct P { alive: Alive, data: [MaybeUninit<usize>; 2] }
#[inline(never)]
fn len(alive: Alive) -> usize {
    assert_eq!(unsafe { *(&alive as *const Alive).cast::<u8>() }, 0);
    alive.end - alive.start
}
#[kani::proof]
fn cloned_ordinary_argument_has_its_own_shadow() {
    let p = P { alive: Alive { start: 0, end: 2 }, data: [MaybeUninit::new(7), MaybeUninit::uninit()] };
    assert_eq!(len(p.alive.clone()), 2);
    assert_eq!(unsafe { p.data[0].assume_init() }, 7);
    kani::cover!(true);
}
