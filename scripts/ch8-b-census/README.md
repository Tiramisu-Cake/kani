# B P-prime batch census — preparation only

Input control `4d7e34383a3af504a261228fdee59e6c7093e633`; coordinator batch note
at g0 `82cc48368e`. No publication, dispatch, CI, ledger or local compiler execution.
Only the coordinator can authorize a future run and create its same-tree trigger.
The isolated Kani-host control retains only this workflow; pristine Kani/compiler/models
remain `model-checking/kani@0aac16ef62da9e9d5645782d458593e5d78143ba`.
P-prime std remains `c5ff36ff433692140605891f646043f991db05de`.

`roots.json` is byte-identical: all235 selectors, classes and invalid-value oracles.
Historical shard2=183/shard4=52 fields remain row metadata. All roots have identical
flags/cfg/RUSTFLAGS, so there is ONE `verify-std ./library` invocation,235 `--harness`
selectors, `--exact`, `--jobs=1`, `--harness-timeout 600s`, and one export-json path.
No list/metrics/global inventory, cfg controls, autoharness, uninit-checks, unwind
override, check suppression, compiler/model/runtime patch or retries are added.
The organizer feature set plus valid-value-checks and export-json stays unchanged.

The group uses fresh target/export scratch outside the three sibling checkouts
control/export/std. Std compilation is entered once through this invocation;
there is no compile-only warmup and no root-specific rebuild invocation.
A2100s compile/preparation cap lasts until the fresh stock export marker appears.
Pinned Kani writes this marker in `main.rs::verify_project` after project construction
and selection, before `check_all_harnesses`. This is a sampled stage boundary,
not independent proof of compiler-internal work. `std-compile.json` records the
boundary, elapsed time, cap, bounded4096-byte head/tail, truncation and failure.
It is persisted before spawn and on the marker boundary so a later runner loss
still retains the completed preparation receipt. Prefix/tail attribution has0.1s
sampling granularity and may include boundary-adjacent output.

Kani enforces600s per harness. The wrapper group cap is2100+235*600=143100s.
The existing host job210min ceiling remains an independent scheduling bound;
it can cut the group short, yielding PARTIAL with no invented row successes.
It is not a promise that the sum of all worst-case harness budgets fits one host job.
Setup<=25min, tool build<=2100s, one job; original420 runner-min maximum becomes210.
Group RSS cap<=min(12GiB, available minus2GiB), sampled0.1s; no process is started
without the reserve. Group process-tree RSS sums shared pages and can overshoot
between samples. Precise per-harness attribution is unavailable: every root RSS
is explicitly UNKNOWN, with group peak recorded separately. No6GiB per-root
measurement or enforcement is claimed in this fallback.

A16MiB group export is split into per-root structured receipts. Selection must
match the whole group exactly, with no unmatched filters, unique core/manual
harness names, correct tool/target/features/checks and harness_timeout_s=600.
Each selected entry preserves `contract` (null or validated stock structure),
its own outcome/verdict/checks/covers/failed_properties/warnings. B has no separate
expected target oracle: the retained contract is source-reported metadata, not
independently established target binding. Group exit0/1 is checked against the
whole group's outcomes; a successful root can coexist with a failing/timed-out
neighbour and group exit1. Missing/duplicate/wrong-name/automatic/ill-typed entries
cannot pass. A completed root in a valid PARTIAL export can retain its diagnostic
class; missing rows and the overall census remain PARTIAL.

Classification is unchanged: PASS; copy Unsupported; casts; other Unsupported;
intended invalid-value failure; compile-resource-not-run. Mixed failures retain
all classes/properties; precedence remains catchall, other Unsupported, casts,
copy Unsupported, intended failure. Unknown/undetermined properties make the
row incomplete, preserving observed failure families. Ordinary235 have no
source-qualified intentional invalid-value oracle; names never imply intent.
STOP B design boundaries from the original package remain binding.

Original exits/signals/exceptions and bounded4096-byte output head/tail are in
`group.json`; total output cap64MiB. Only curated JSON is uploaded (<128MiB bound),
with source/tree/clean and binary hashes before/after. Missing, malformed, oversized,
INCOMPLETE, NOT_RUN, timeout/crash/resource/output-cut exports never create PASS.
Raw output, target, archives and binaries are not uploaded. All runtime proof
results here remain NOT_RUN; diagnostic completion gives no independent B1/B2 credit.

Offline validation only:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/ch8-b-census -v
PYTHONDONTWRITEBYTECODE=1 python3 scripts/ch8-b-census/static_check.py
actionlint -shellcheck= .github/workflows/ch8-b-census.yml
git diff --check
```
