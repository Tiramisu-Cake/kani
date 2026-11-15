Related: #3300 (tracking issue for memory-initialization checks).

```rust
use core::mem::MaybeUninit;
struct D(u8);
impl Drop for D { fn drop(&mut self) {} }

#[kani::proof]
fn drop_uninit_in_array() {
    let mut a: [MaybeUninit<D>; 2] = [const { MaybeUninit::uninit() }; 2];
    a[0].write(D(1));
    unsafe { core::ptr::drop_in_place(a.as_mut_ptr().cast::<D>().add(1)) }; // slot 1 uninit
}
```

`cargo kani -Z uninit-checks` on main reports: `Checking memory initialization of
type [std::mem::MaybeUninit<D>; 2] is not supported. Cannot determine layout for a
type that contains union of type std::mem::MaybeUninit<D> as a field.`
(Kani 0.68.0 instead ICEs on a larger crate, in
`check_uninit/delayed_ub/initial_target_visitor.rs:107`, when a `fmt` fn pointer is
reachable. That is fixed on main.)

`[MaybeUninit<T>; N]` is the standard buffer pattern in std (`MapWindows`,
`array::IntoIter`, `ArrayVec`-style code). Supporting it would let Kani flag
rust-lang/rust#156501 natively.

---
**Environment:** Kani `main` @ `bf9c58e` (2026-11-10), CBMC 6.11.0, x86_64 Linux. Also reproduced with Kani 0.68.0.
**Context:** found while modelling the std memory-safety bugs from https://forge-blog.github.io/posts/rust-std-memory-safety/ with Kani.


