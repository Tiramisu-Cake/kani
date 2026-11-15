// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular --harness write_through_selected_pointer_leaves_false_source_padding_hole --exact

#![feature(core_intrinsics)]
#![allow(internal_features)]

include!("controls.inc");
