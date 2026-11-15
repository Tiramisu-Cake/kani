// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

// No input generation, MaybeUninit, or storage-dependent setup: the typed return admits a seed.
fn seed_only() -> &'static [u8; 4] {
    &[1, 2, 3, 4]
}
