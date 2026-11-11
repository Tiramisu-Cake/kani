// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=terse

use std::mem::{ManuallyDrop, MaybeUninit};

#[derive(Clone, Copy)]
struct C {
    marker: usize,
    slots: [MaybeUninit<usize>; 2],
}

#[kani::proof]
fn true_unsize_reborrow_and_manually_drop_projection_preserve_filled_storage() {
    let mut value = C { marker: 11, slots: [MaybeUninit::new(7), MaybeUninit::uninit()] };
    value.marker = 17;
    let raw = std::ptr::addr_of_mut!(value);
    let slots_ptr = {
        let wrapped = unsafe { ManuallyDrop::new(&mut *raw) };
        let slice: &[MaybeUninit<usize>] = &wrapped.slots;
        assert_eq!(wrapped.marker, 17);
        assert_eq!(unsafe { slice[0].assume_init() }, 7);
        std::ptr::addr_of!(wrapped.slots) as *mut [MaybeUninit<usize>; 2]
    };
    unsafe {
        (*slots_ptr)[1] = MaybeUninit::uninit();
    }
    assert_eq!(unsafe { (*slots_ptr)[0].assume_init() }, 7);

    kani::cover!(true);
}

#[kani::proof]
fn true_unsize_reborrow_empty_index_is_uninitialized() {
    let value = C { marker: 19, slots: [MaybeUninit::new(23), MaybeUninit::uninit()] };
    let wrapped = ManuallyDrop::new(value);
    let slice: &[MaybeUninit<usize>] = &wrapped.slots;
    assert_eq!(wrapped.marker, 19);
    assert_eq!(unsafe { slice[0].assume_init() }, 23);
    kani::cover!(true);
    unsafe {
        slice[1].assume_init();
    }
}

struct DropReadsEmpty {
    slots: [MaybeUninit<usize>; 2],
}
impl Drop for DropReadsEmpty {
    fn drop(&mut self) {
        kani::cover!(true);
        unsafe {
            self.slots[1].assume_init_read();
        }
    }
}

#[kani::proof]
fn drop_impl_read_of_empty_slot_fails() {
    let mut value =
        ManuallyDrop::new(DropReadsEmpty { slots: [MaybeUninit::new(27), MaybeUninit::uninit()] });
    kani::cover!(true);
    unsafe {
        std::ptr::drop_in_place(&mut *value);
    }
}

struct OrdinaryDrop<'a>(&'a std::cell::Cell<usize>);
impl Drop for OrdinaryDrop<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}
struct DropFieldProduct<'a> {
    marker: OrdinaryDrop<'a>,
    slots: [MaybeUninit<usize>; 2],
}

#[kani::proof]
fn dropping_ordinary_field_keeps_empty_manually_dropped_neighbor_empty() {
    let drops = std::cell::Cell::new(0);
    let mut outer = ManuallyDrop::new(DropFieldProduct {
        marker: OrdinaryDrop(&drops),
        slots: [MaybeUninit::new(29), MaybeUninit::uninit()],
    });
    let raw = &mut *outer as *mut DropFieldProduct<'_>;
    let slots = unsafe { std::ptr::addr_of_mut!((*raw).slots) };
    unsafe {
        std::ptr::drop_in_place(std::ptr::addr_of_mut!((*raw).marker));
    }
    assert_eq!(drops.get(), 1);
    assert_eq!(unsafe { (*slots)[0].assume_init() }, 29);
    kani::cover!(true);
    unsafe {
        (*slots)[1].assume_init();
    }
}
