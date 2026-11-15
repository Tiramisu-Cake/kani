// Copyright Kani Contributors
// SPDX-License-Identifier: Apache-2.0 OR MIT
// compile-flags: --edition 2021 -C panic=abort
// kani-flags: -Z uninit-checks --output-format=regular --harness true_selected_arm_still_deinitializes_source_b --exact

#![feature(core_intrinsics, custom_mir)]
#![allow(internal_features)]

include!("controls.inc");
