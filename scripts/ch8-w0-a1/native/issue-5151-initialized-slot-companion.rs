use core::mem::MaybeUninit;

struct D(u8);
impl Drop for D { fn drop(&mut self) {} }

#[kani::proof]
fn drop_initialized_slot_in_array() {
    let mut a: [MaybeUninit<D>; 2] = [const { MaybeUninit::uninit() }; 2];
    a[0].write(D(1));
    a[1].write(D(2));
    unsafe { core::ptr::drop_in_place(a.as_mut_ptr().cast::<D>().add(1)) };
}

