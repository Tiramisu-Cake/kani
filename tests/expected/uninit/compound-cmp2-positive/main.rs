// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=terse --default-unwind 8

mod aggregate;
mod manually_drop;
mod unsize;
mod ordinary_argument;
mod pointer_argument;
