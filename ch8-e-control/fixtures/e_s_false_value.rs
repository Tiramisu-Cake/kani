#![feature(proc_macro_hygiene)]

#[kani::proof]
fn e_s_false_value() {
    // Optional alloc-enabled Kani model; deliberately no length cap or bounded Vec model.
    let slice = kani::arbitrary::any_slice_mut_unbounded::<u8>();
    let len = slice.len();

    kani::cover(len > 32, "E-S length above 32");
    kani::cover(len <= isize::MAX as usize, "E-S storage call returns");

    // A legal read before any loop isolates generated storage and read validity.
    if len != 0 {
        let index: usize = kani::any();
        kani::assume(index < len);
        let value = unsafe { *slice.as_ptr().add(index) };
        kani::cover(index > 0 && index < len - 1 && value == 0, "E-S interior zero read");
        assert!(value == value.wrapping_add(1)); // False for every u8.
    }
}
