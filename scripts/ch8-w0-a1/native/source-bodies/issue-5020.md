I found this issue while reviewing Kani with AI assistance and reproduced it with Kani built from the commit below. This report was drafted by AI.

Tested commit: 9461e07af (main), CBMC 6.11.0, toolchain nightly-2026-10-12.

### Reproducer

```rust
use std::alloc::{alloc, dealloc, Layout};
use std::ptr::NonNull;

#[repr(C)] struct S { a: u64, p: NonNull<u8> } // p at bytes 8..16

// Initialize only `a`, then read the whole value.
unsafe fn read_half_init<X>() {
    let lay = Layout::new::<X>();
    let base = alloc(lay);
    base.write_bytes(1, 8);
    let x: X = std::ptr::read(base as *const X); // UB: bytes 8..16 uninit
    std::mem::forget(x);
    dealloc(base, lay);
}

#[cfg_attr(kani, kani::proof)]
fn nonnull_field() { unsafe { read_half_init::<S>() } }
```

```
kani -Z uninit-checks uninit_nonnull.rs --harness nonnull_field --exact
```

### Expected behavior

Verification fails: the read copies 8 uninitialized bytes into a `NonNull<u8>` (Rust Reference,
[undefined.validity.scalar]: "a raw pointer must be initialized").

### Actual behavior

```
 ** 0 of 66 failed (2 unreachable)
VERIFICATION:- SUCCESSFUL
```

The same struct with `p: *const u8` fails:

```
Failed Checks: Undefined Behavior: Reading from an uninitialized pointer of type `T`
```

A `Box<u8>` field is also missed, as is the uninitialized length of a `NonNull<[u8]>` field when its data pointer bytes are initialized. This does not mean every uninitialized nonzero-offset field is missed: for the same `NonNull<[u8]>` layout, leaving both the data pointer and length uninitialized does fail a check. The incorrectly shifted byte mask still covers part of that field.

### Cause

`data_bytes_for_ty` (`kani-compiler/src/kani_middle/transform/check_uninit/ty_layout.rs:334-338`)
computes the data bytes of a pattern type's base type at offset `0` instead of `current_offset`.
`NonNull<T>` (and so `Box<T>`) wraps the pattern type `*const T is !null`, so in `S` the pointer
bytes are recorded at 0..8 instead of 8..16. Passing `current_offset` should fix it.

Possibly related: #3300 (memory-initialization tracking issue).


