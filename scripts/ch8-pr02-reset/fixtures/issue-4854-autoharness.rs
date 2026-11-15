use std::mem::MaybeUninit;
use std::ptr;
const MEMCPY_RET: MaybeUninit<*const i32> = {
    let ptr2 = MaybeUninit::new(ptr::null());
    ptr2
};
fn reassemble_ptr_fragments_in_static() {
    unsafe { MEMCPY_RET.assume_init() };
}
