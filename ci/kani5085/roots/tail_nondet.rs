#[repr(C)]
#[derive(Clone, Copy)]
struct Tail { b: u8, z: [(); 2] }
#[repr(C)]
union Value { bytes: [u8; 8], tail: Tail }
#[cfg_attr(kani, kani::proof)]
fn check() {
    let bytes: [u8; 8] = kani::any();
    let src = Value { bytes };
    let dst = unsafe { std::ptr::read(&src) };
    assert_eq!(unsafe { dst.tail.b }, bytes[0]);
}
fn main() { check() }
