// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021
// kani-flags: -Z uninit-checks --output-format=regular --harness selected_false_maybe_uninit_fields_are_legal --exact

#![feature(core_intrinsics)]
#![allow(internal_features)]

include!("controls.inc");
