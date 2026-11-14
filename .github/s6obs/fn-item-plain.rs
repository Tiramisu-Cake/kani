// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular --cbmc-args --object-bits 12
#[inline(never)]
fn answer() -> u16 { 42 }
#[inline(never)]
fn invoke<F: FnOnce() -> u16>(f: F) -> u16 { f() }
#[kani::proof]
fn fn_item_plain() { assert_eq!(invoke(answer), 42); }
