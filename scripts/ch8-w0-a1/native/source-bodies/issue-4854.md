<!--
If this is a security issue, please report it following the
[security reporting procedure](https://github.com/model-checking/kani/security/policy).
-->

<!--
Thank you for filing a bug report! 🐛
Please provide a short summary of the issue, along with the information necessary to replicate.
-->

I tried this code:
<!--
If the reproducing code is small, please post it here.
Otherwise, please attach the relevant files to this issue.
Alternatively, post a link to the repository and branch that exposes the issue.
-->
```rust
use std::mem::MaybeUninit;
use std::ptr;
const MEMCPY_RET: MaybeUninit<*const i32> = {
    let ptr2 = MaybeUninit::new(ptr::null());
    ptr2
};
fn reassemble_ptr_fragments_in_static() {
    unsafe { MEMCPY_RET.assume_init() };
}
```

using the following command line invocation:

```
RUST_BACKTRACE=full  RUSTFLAGS="--edition=2021 --cap-lints=warn"  kani autoharness -Zautoharness code.rs --run-sanity-checks  -Zunstable-options   -Zuninit-checks  -Zuninit-checks
```

with Kani version:

I expected to see this happen: *explanation*

<!--
If Kani crashed, please include a backtrace in the code block by setting
`RUST_BACKTRACE=1` in your environment. E.g. `RUST_BACKTRACE=1 kani ...`
-->
Instead, this happened: *explanation*
```
Kani Rust Verifier 0.68.0 (standalone)
CBMC 6.11.0
warning: constant `MEMCPY_RET` is never used
 --> code.rs:3:7
  |
3 | const MEMCPY_RET: MaybeUninit<*const i32> = {
  |       ^^^^^^^^^^
  |
  = note: `#[warn(dead_code)]` (part of `#[warn(unused)]`) on by default

warning: function `reassemble_ptr_fragments_in_static` is never used
 --> code.rs:7:4
  |
7 | fn reassemble_ptr_fragments_in_static() {
  |    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

warning: use of an unstable feature
 --> <crate attribute>:1:12
  |
1 | #![feature(register_tool)]
  |            ^^^^^^^^^^^^^
  |
  = note: requested on the command line with `--force-warn unstable-features`


thread 'rustc' (3628014) panicked at kani-compiler/src/kani_middle/transform/check_uninit/relevant_instruction.rs:126:73:
internal error: entered unreachable code
stack backtrace:
   0:     0x7f5def4c53f6 - <<std[b8564071bfb80320]::sys::backtrace::BacktraceLock>::print::DisplayBacktrace as core[b218925afaf52552]::fmt::Display>::fmt
   1:     0x7f5defc0aca3 - core[b218925afaf52552]::fmt::write
   2:     0x7f5def4daa1c - <std[b8564071bfb80320]::sys::stdio::unix::Stderr as core[b218925afaf52552]::io::write::Write>::write_fmt
   3:     0x7f5def49868a - std[b8564071bfb80320]::panicking::default_hook::{closure#0}
   4:     0x7f5def4b96a3 - std[b8564071bfb80320]::panicking::default_hook
   5:     0x559775e90f40 - kani_compiler[980edcef3ed27b2]::session::PANIC_HOOK::{closure#0}::{closure#0}
   6:     0x559775e913a0 - kani_compiler[980edcef3ed27b2]::codegen_cprover_gotoc::utils::debug::DEFAULT_HOOK::{closure#0}::{closure#0}
   7:     0x7f5def4b9b42 - std[b8564071bfb80320]::panicking::panic_with_hook
   8:     0x7f5def498774 - std[b8564071bfb80320]::panicking::panic_handler::{closure#0}
   9:     0x7f5def4903a9 - std[b8564071bfb80320]::sys::backtrace::__rust_end_short_backtrace::<std[b8564071bfb80320]::panicking::panic_handler::{closure#0}, !>
  10:     0x7f5def49a14d - __rustc[f325e6f53f8e9f03]::rust_begin_unwind
  11:     0x7f5dec0cb57c - core[b218925afaf52552]::panicking::panic_fmt
  12:     0x7f5dec6816b2 - core[b218925afaf52552]::panicking::panic
  13:     0x559775ebf53a - <kani_compiler[980edcef3ed27b2]::kani_middle::transform::check_uninit::relevant_instruction::MemoryInitOp>::operand_ty
  14:     0x559775df5c01 - <kani_compiler[980edcef3ed27b2]::kani_middle::transform::check_uninit::UninitInstrumenter>::build_check_for_operation
  15:     0x559775dfa1f2 - <kani_compiler[980edcef3ed27b2]::kani_middle::transform::check_uninit::UninitInstrumenter>::build_check_for_instruction
  16:     0x559775de7221 - <kani_compiler[980edcef3ed27b2]::kani_middle::transform::check_uninit::UninitInstrumenter>::run::<kani_compiler[980edcef3ed27b2]::kani_middle::transform::check_uninit::ptr_uninit::uninit_visitor::CheckUninitVisitor>
  17:     0x559775ed3db8 - <kani_compiler[980edcef3ed27b2]::kani_middle::transform::check_uninit::ptr_uninit::UninitPass as kani_compiler[980edcef3ed27b2]::kani_middle::transform::TransformPass>::transform
  18:     0x559775ca4500 - <kani_compiler[980edcef3ed27b2]::kani_middle::transform::BodyTransformation>::body_ref
  19:     0x559775ddb026 - <kani_compiler[980edcef3ed27b2]::kani_middle::reachability::MonoItemsCollector>::reachable_items
  20:     0x559775ddf8f8 - kani_compiler[980edcef3ed27b2]::kani_middle::reachability::collect_reachable_items
  21:     0x559775d23b28 - <kani_compiler[980edcef3ed27b2]::codegen_cprover_gotoc::compiler_interface::GotocCodegenBackend>::codegen_items
  22:     0x559775d213fd - <kani_compiler[980edcef3ed27b2]::codegen_cprover_gotoc::compiler_interface::GotocCodegenBackend as rustc_codegen_ssa[6aa05fb22a8957d5]::traits::backend::CodegenBackend>::codegen_crate::{closure#0}
  23:     0x559775d90c15 - rustc_public[982db8fb9120de79]::compiler_interface::run::<rustc_public[982db8fb9120de79]::rustc_internal::run<<kani_compiler[980edcef3ed27b2]::codegen_cprover_gotoc::compiler_interface::GotocCodegenBackend as rustc_codegen_ssa[6aa05fb22a8957d5]::traits::backend::CodegenBackend>::codegen_crate::{closure#0}, alloc[1fd94160f0f4009f]::boxed::Box<dyn core[b218925afaf52552]::any::Any>>::{closure#0}, alloc[1fd94160f0f4009f]::boxed::Box<dyn core[b218925afaf52552]::any::Any>>
  24:     0x559775ea97c5 - rustc_public[982db8fb9120de79]::rustc_internal::run::<<kani_compiler[980edcef3ed27b2]::codegen_cprover_gotoc::compiler_interface::GotocCodegenBackend as rustc_codegen_ssa[6aa05fb22a8957d5]::traits::backend::CodegenBackend>::codegen_crate::{closure#0}, alloc[1fd94160f0f4009f]::boxed::Box<dyn core[b218925afaf52552]::any::Any>>
  25:     0x559775d2dbb9 - <kani_compiler[980edcef3ed27b2]::codegen_cprover_gotoc::compiler_interface::GotocCodegenBackend as rustc_codegen_ssa[6aa05fb22a8957d5]::traits::backend::CodegenBackend>::codegen_crate
  26:     0x7f5df0f4db8c - <rustc_interface[4089758db528eb1a]::queries::Linker>::codegen_and_build_linker
  27:     0x7f5df0f4448a - rustc_interface[4089758db528eb1a]::interface::run_compiler::<(), rustc_driver_impl[f578478d149be60]::run_compiler::{closure#0}>::{closure#2}
  28:     0x7f5df0fc1e64 - std[b8564071bfb80320]::sys::backtrace::__rust_begin_short_backtrace::<rustc_interface[4089758db528eb1a]::util::run_in_thread_with_globals<rustc_interface[4089758db528eb1a]::util::run_in_thread_pool_with_globals<rustc_interface[4089758db528eb1a]::interface::run_compiler<(), rustc_driver_impl[f578478d149be60]::run_compiler::{closure#0}>::{closure#2}, ()>::{closure#0}, ()>::{closure#0}::{closure#0}, ()>
  29:     0x7f5df0fc1c2d - <std[b8564071bfb80320]::thread::lifecycle::spawn_unchecked<rustc_interface[4089758db528eb1a]::util::run_in_thread_with_globals<rustc_interface[4089758db528eb1a]::util::run_in_thread_pool_with_globals<rustc_interface[4089758db528eb1a]::interface::run_compiler<(), rustc_driver_impl[f578478d149be60]::run_compiler::{closure#0}>::{closure#2}, ()>::{closure#0}, ()>::{closure#0}::{closure#0}, ()>::{closure#1} as core[b218925afaf52552]::ops::function::FnOnce<()>>::call_once::{shim:vtable#0}
  30:     0x7f5df0fbf907 - <std[b8564071bfb80320]::sys::thread::unix::Thread>::new::thread_start
  31:     0x7f5dea2980a2 - <unknown>
  32:     0x7f5dea32080c - <unknown>
  33:                0x0 - <unknown>

Kani unexpectedly panicked during compilation.
Please file an issue here: https://github.com/model-checking/kani/issues/new?labels=bug&template=bug_report.md

[Kani] no current codegen item.
[Kani] no current codegen location.
warning: 3 warnings emitted


