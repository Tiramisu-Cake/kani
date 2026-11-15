// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

// The same seeded source is legal with Uninit disabled; no entry reset should be emitted.
fn seed_only() -> &'static [u8; 4] {
    &[1, 2, 3, 4]
}
