# Kani issue 5151 bounded reproduction

This package compares the issue 5151 example and two focused controls on stock Kani and the pinned C2 prototype. Each tool checkout is independent of this control checkout and must match the repository, commit, tree, and clean tracked state recorded in `CI-REQUEST.json`.

## Rows

| Source | Stock prediction | Prototype expectation |
| --- | --- | --- |
| `initialized-slot.rs` | `UNSUPPORTED_UNION` | `SUCCESS` |
| `original-empty-drop.rs` | `UNSUPPORTED_UNION` | Completed result without unsupported-layout diagnostics; `SUCCESS` exposes the empty-drop limitation, while a genuine `UNINIT_FAILURE` is also recorded. The semantic target remains `UNINIT_FAILURE`. |
| `read-in-drop.rs` | `UNSUPPORTED_UNION` | `UNINIT_FAILURE` from the Drop body reading `self.0` |

The source in `original-empty-drop.rs` preserves the issue's test body after the copyright and feature header. Its `.expected` file checks that the harness completes and reports a result without pinning an unobserved result. The runner accepts the two completed semantic outcomes for this row, while only the read-in-drop control is a strict negative gate. A completed success records the empty-drop limitation as unresolved.

Each matrix arm performs three independent exact harness invocations with `-Z uninit-checks` and `-Z export-json`. For stock, an invocation is classified as unsupported only when it exits unsuccessfully and emits the exact issue diagnostic: `Checking memory initialization of type [std::mem::MaybeUninit<D>; 2] is not supported. Cannot determine layout for a type that contains union of type std::mem::MaybeUninit<D> as a field.` A different process failure is `UNKNOWN`.

Prototype results require a complete JSON export tied to the pinned Kani commit, exact selected harness, and source path. Successful properties must have a consistent completed summary. A negative result must contain only failed `safety_check` properties with the recognized uninitialized-read diagnostic and the expected harness target. Missing, partial, null, wrong-type, oversized, mismatched, timed-out, or otherwise incomplete reports remain `UNKNOWN`. A row that never starts is `NOT_RUN`. All observations carry `proof_credit: NONE`.

## Execution and activation

The workflow uses Ubuntu 24.04, a 55 minute job cap, one matrix job at a time, no retry, a 1800 second tool build cap, and a 60 second cap per exact harness invocation. It invokes the pinned checkout's `.github/actions/setup` and runs `cargo build-dev -- --release` only in the workflow. Captured tool versions, command, working directory, tool identities before and after, frozen source hashes, exit status, error excerpts, timeout state, and bounded JSON export are stored with the receipts.

Preparation authorizes no push, workflow run, publication, or ledger update. The control commit uses `[skip ci]`. A separately approved activation creates a same-tree sibling commit on `uninit-ci/ch8-5151-*`; the workflow verifies the sibling's tree equals its `[skip ci]` parent, and that parent's parent is the pinned stock commit. The workflow has no `workflow_dispatch` trigger.

## Rust edition

Each test declares `// compile-flags: --edition 2021`. Compiletest parses the
header in `tools/compiletest/src/header.rs` and sets `RUSTFLAGS` in
`tools/compiletest/src/runtest.rs::run_kani`. The standalone driver forwards
`RUSTFLAGS` to rustc in `kani-driver/src/call_single_file.rs`. The regression
script supplies no default edition, and the standalone invocation requires
these explicit compiler flags for `use core::...`. The runner passes
`RUSTFLAGS="--edition 2021"` for every row and records it in the process data.
The issue body, imports, array elements and drop operations are preserved.

The owner reports that run 43878900159, trigger dbfb4d8bd8, returned six UNKNOWN
rows with E0433 at the `core` import. The corrected package has not run in CI.
Python regression checks exercise the subprocess environment, matching source
headers, rejection of a missing edition, and preservation of E0433 as UNKNOWN.
