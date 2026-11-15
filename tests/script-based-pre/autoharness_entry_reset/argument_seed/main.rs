// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn argument_seed(index: u8) -> &'static [u8; 4] {
    let bytes: &'static [u8; 4] = &[1, 2, 3, 4];
    assert!(bytes[usize::from(index % 4)] > 0);
    bytes
}
