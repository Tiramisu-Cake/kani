# KANI5085 — coordinator handoff, PREPARED / NOT_RUN

Worker15 prepared this correctness replay locally. No build, Cargo, rustc, Kani,
CBMC execution, push, dispatch, issue, comment or PR was performed. Only the
coordinator may publish the CI overlay and run it. This request does not grant
additional CI/Cloud authority. Research commit has `[skip ci]`.

## Exact inputs

- Kani upstream `model-checking/kani` main observed 2026-11-13:
  `0aac16ef62da9e9d5645782d458593e5d78143ba`. Fresh shallow clone at
  `/root/kani-5085-replay`; no Part 1/B3 patch is applied. Runtime compilation
  uses a separate checkout of this exact upstream commit, not the CI overlay.
- CBMC fix `Tiramisu-Cake/cbmc`, `fix/array-zero-width-elements-v2`:
  `9f2d01ec2bf115879c86e22203d403ba156d22e5`.
- Base is its parent `107a1e504cd69a2f3483717c8bcfcfa59814c557`.
  Static inspection confirms the only production change is `> bitst{0}` to
  `>= bitst{0}` in the array branch of `bits2expr`. Vector guard stays positive.
  Remaining changes are regression/unit tests, which this workflow does not build.
- Issue snapshot: `issue-5085.json`, fetched read-only using
  `gh issue view 5085 -R model-checking/kani --json number,title,body,url,updatedAt`.
  `issue-5085.md` is the exact decoded UTF-8 body, with no added newline.
  SHA256: `22f137d6e4eea60a7e0f24dd55ffeeffe6bf88aa3f372e0975fb410dd87e5259`.
  Upstream updatedAt: `2026-11-06T02:03:19Z`. Source hashes are in `INPUTS.json`;
  the full prepared package is covered by `PACKAGE-SHA256SUMS`.

## Publication layout (coordinator only)

Create a CI-only branch from exact Kani upstream SHA above in **Tiramisu-Cake/kani**:
`uninit-ci/kani5085-patched-cbmc-20261113` (or another `uninit-ci/kani5085-*`).
Put the entire package at `ci/kani5085/` and copy its `workflow.yml` to
`.github/workflows/kani5085-patched-cbmc.yml`. Remove all other workflow files
**in this CI-only branch** to avoid triggering unrelated upstream jobs. Do not
include these workflow deletions in a source patch/PR. The source used by the
job is separately checked out from upstream, so overlay changes do not enter Kani.
Commit the overlay with author Tiramisu-Cake <igkharin@gmail.com> via Git `-c`.
The CI-only commit must not use `[skip ci]`, since its branch-filtered push starts
this single workflow. Push only that CI branch; no upstream/default branch/PR.
Record the resulting overlay commit, workflow hash and run URL in RESULT.
Worker performs none of these publication steps.

One job, `ubuntu-24.04` x86_64, hard timeout 90 minutes. `contents: read` only;
no matrix, PR trigger, dispatch, cache, retries or external messages. Kani setup
uses the pinned upstream composite action (including stock CBMC 6.11.0 helper
tools), then `cargo build-dev -- --release` with two build jobs. Setup/downloads
and builds happen only in GitHub CI, never on the VPS. Source is checked clean
before replay. Root runs add only `--verbose`, keeping default verification checks,
solver and output format; no `--output-format=old`, assumptions or exclusions.

## Paired CBMC recipe and binary selection

The same source directory, CMake build directory, GCC/G++ 13, Ninja and Release
configuration first build the exact base `cbmc` target, copy the resulting binary,
then check out exact fix and incrementally rebuild that same target. This avoids
a second full build while rebuilding the changed translation unit and relinking.
No `all`, unit, regression, Java or packaging target is built. This follows the
focused upstream `.github/workflows/profiling.yaml` Release recipe, with explicit
`WITH_JBMC=OFF`, `WITH_MEMORY_ANALYZER=OFF`, `sat_impl=minisat2;cadical` to support
Kani's default CaDiCaL. Library-check stamps are not forged. Both binary copies
are preserved independently; exact source/tree, cache SHA, binary SHA and version
are recorded immediately after each build. CMakeCache files and compiler/version
output are retained. Changed test sources are irrelevant to the selected target.
The static source-delta check gates the build. No local CBMC source is modified.

At pinned Kani SHA, `kani-driver/src/call_cbmc.rs:176` constructs
`TokioCommand::new("cbmc")`, and `kani-driver/src/version.rs:49` constructs
`Command::new("cbmc")` for the version. No `KANI_CBMC` override or bundled
absolute CBMC path participates in this development installation. `scripts/kani`
executes `target/kani/bin/kani-driver`; it does not replace PATH. Prepending a
one-command `cbmc` shim therefore selects the base/fix executable. Other helpers
(`goto-instrument`, `goto-cc`, etc.) stay from the same upstream setup for both
variants. This is a CBMC executable replacement experiment, not a full rebuilt
CBMC helper suite or a claim that the two pipeline versions are identical.

The shim runs the selected absolute binary, forwards its stdout/stderr to Kani,
and records actual argv/cwd, resolved path, binary SHA, original exit/signal and
bounded raw stdout/stderr. This records the real model-checking invocation, not
only a `--version` probe. The binary hash must match its build receipt.
Kani version/driver/compiler hashes and the pinned Rust toolchain are retained.
Build and invocation receipts are provenance observations, not independent proof
of compiler correctness or a general formal proof credit.

## Roots and expected observations

Each root runs against both binaries in separate fresh directories, including:

| Root | Construction and purpose |
|---|---|
| `static_zst_arr` | Byte-for-byte Rust block from #5085, including `main`. |
| `const_zst_arr` | Same tuple/type/value as issue, `const S` passed through `black_box`, matching the issue's const claim. |
| `tail_typed_copy` | `repr(C) Tail { b: u8, z: [(); 2] }` inside an eight-byte union; typed `ptr::read` then field read. This instantiates the B3 limitations shape with nonzero sibling/padding. |
| `tail_nondet` | Same typed-copy path, all eight source bytes from `kani::any()`, preventing a compile-time constant initializer. The assertion compares the read byte with the original symbolic byte. No assumptions. |
| `runtime_control` | Byte-for-byte successful runtime/`black_box` control from issue. |

Hypothesis only: roots 1–3 show the bits2expr array invariant on base and verify
on fix. Root 4 may fail in earlier Kani lowering, independently of this CBMC fix.
Runtime control should verify on both. These expectations do not affect row
selection or classification. No root is removed or changed after observing a
failure. `Tail` is a specified representation variant, not an issue-verbatim root.

Outer Kani cap: 60 seconds/root; nested CBMC cap: 50 seconds; retained output cap:
8 MiB per invocation, continued drain on overflow. Timeouts kill the process group
for the outer invocation. Original nonzero exits/signals are retained. No
RLIMIT_FSIZE. Every row starts NOT_RUN, is atomically updated to IN_PROGRESS, and
keeps its exact exit, Kani verdict lines, CBMC receipts and `invariants.txt`.
Cancellation/setup failure leaves NOT_RUN/IN_PROGRESS, never PASS. All ten rows
are attempted even if the hypothesis fails; no adaptive retries. A green
collection job means complete collection, not that the patch hypothesis passed.
Identity/capture failures make collection incomplete. NO_CBMC_MODEL_INVOCATION
records an earlier failure and does not prove CBMC ran or that a lowering bug
was causally established. Preserve its diagnostic before attributing a stage.

`RESULT.json`, short Actions summary and per-case invariant blocks are uploaded
with `always()`, retention 14 days. Use the bounded summary/receipts for reporting;
no GCS/raw-archive or historical-ledger changes are involved. If infrastructure
stops before replay, all dependent rows stay NOT_RUN. Upload errors/cancellation
can still prevent delivery; no absent artifact is accepted as a result.

## Assessment after CI

First check identities and receipt completeness, then record each actual verdict
and exit. To confirm #5085 specifically, require the literal static reproducer to
reach the selected base binary and fail with the bits2expr array invariant, then
reach the selected fix binary and report `VERIFICATION:- SUCCESSFUL`, exit 0,
with no invariant, timeout, truncation or capture errors. Apply the same distinct
assessment to const and Tail. If base no longer reproduces, record NOT_REPRODUCED
at this Kani SHA; do not declare the patch tested against the original failure.
If fix reaches another failure, report that failure rather than saying fixed.
Absence of an invariant alone is not proof of successful verification. Separate
observed runtime-control results and root-4 lowering limitations. B1/B2/full
proof/general #3300 or uninit-checks credit is not requested.

Local validation: Python input/hash/verbatim/static-delta checks, shell syntax,
workflow structure, and isolated Python service tests. No actual tool outcome is
available; RESULT-template is deliberately NOT_RUN. No comment text has been sent.
