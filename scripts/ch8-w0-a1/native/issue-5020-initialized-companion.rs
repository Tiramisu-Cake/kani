use std::ptr::NonNull;

#[repr(C)]
struct S {
    a: u64,
    p: NonNull<u8>,
}

#[cfg_attr(kani, kani::proof)]
fn initialized_same_type_companion() {
    let x = S { a: 7, p: NonNull::dangling() };
    let y = unsafe { std::ptr::read(&x) };
    assert_eq!(y.a, 7);
    assert_eq!(y.p, x.p);
}

