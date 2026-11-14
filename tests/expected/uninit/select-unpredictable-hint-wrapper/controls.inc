// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{hint, mem::MaybeUninit};

#[kani::proof]
fn hint_wrapper_u8_uses_all_internal_selects() {
    let condition: bool = kani::any();
    let selected = hint::select_unpredictable(condition, 17u8, 29u8);
    assert_eq!(selected, if condition { 17 } else { 29 });
    kani::cover!(condition);
    kani::cover!(!condition);
}

#[kani::proof]
fn hint_wrapper_pointer_preserves_selected_alias_and_payload() {
    let a = MaybeUninit::new(0x1122_3344_5566_7788u64);
    let b = MaybeUninit::new(0x8877_6655_4433_2211u64);
    let condition: bool = kani::any();
    let selected = hint::select_unpredictable(condition, a.as_ptr(), b.as_ptr());
    assert_eq!(
        unsafe { selected.read() },
        if condition { 0x1122_3344_5566_7788 } else { 0x8877_6655_4433_2211 }
    );
    assert_eq!(selected, if condition { a.as_ptr() } else { b.as_ptr() });
    kani::cover!(condition);
    kani::cover!(!condition);
}
