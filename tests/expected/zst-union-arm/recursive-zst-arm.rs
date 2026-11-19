// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[repr(C)]
#[derive(Clone, Copy)]
struct Node2 {
    next: *const Link,
}

// The pointer field reaches this union while the enclosing struct is incomplete.
#[allow(dead_code)]
#[repr(C)]
union Link {
    bytes: [u8; 8],
    marker: [Node2; 0],
}

#[kani::proof]
fn recursive_zst_arm() {
    // Inferred cast avoids a separately monomorphized union-typed null helper.
    let node = Node2 { next: 0usize as *const _ };
    let retained = std::hint::black_box(node);
    assert!(retained.next.is_null());
    kani::cover!(retained.next.is_null(), "recursive_zst_arm retained null root");
}
