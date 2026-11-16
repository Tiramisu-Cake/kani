#![feature(proc_macro_hygiene)]

// Matched primitive raw-write path with no loop abstraction/frame.
#[kani::proof]
fn shadow_write_u8_no_loop() {
    let mut value = 17u8;
    let pointer = &mut value as *mut u8;
    unsafe { pointer.write(41) };
    assert_eq!(unsafe { pointer.read() }, 41);
    kani::cover(true, "primitive no-loop write returns");
}
