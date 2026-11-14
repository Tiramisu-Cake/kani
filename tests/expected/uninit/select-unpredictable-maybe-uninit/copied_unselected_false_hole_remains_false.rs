// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -D warnings
// kani-flags: -Z uninit-checks --output-format=regular --harness copied_unselected_false_hole_remains_false --exact

#![feature(core_intrinsics)]
#![allow(internal_features)]

include!("controls.inc");
