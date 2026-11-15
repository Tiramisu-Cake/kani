use std::mem::MaybeUninit;
use std::ptr;

const MEMCPY_RET: MaybeUninit<*const i32> = MaybeUninit::new(ptr::null());

#[kani::proof]
fn explicit_proof_observes_initialized_null() {
    let value = unsafe { MEMCPY_RET.assume_init() };
    assert_eq!(value, ptr::null());
}

