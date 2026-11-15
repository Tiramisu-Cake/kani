// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[kani::requires(index < 4)]
#[kani::ensures(|result| result[usize::from(index)] > 0)]
fn contract_seed(index: u8) -> &'static [u8; 4] {
    &[1, 2, 3, 4]
}
