# B-01 diagnostic census — preparation only

Coordinator request: one B dispatch (lane cap3; item1 cap18; combined cap32),
not reserved or charged here. No retry. User authorization is package preparation;
coordinator alone reviews current ledger/slots, reserves, publishes and creates the
same-tree non-skip trigger on `uninit-ci/ch8-b-census-*`. Package commits use `[skip ci]`.
Never push this work branch as a trigger. No Cloud or compiler patch is included.

Inputs: unchanged std `872d5a43380752786415bc00d2a12ce0e930cb37`, pristine Kani
`0aac16ef62da9e9d5645782d458593e5d78143ba`, worker14 inventory from g0
`904bc1e4583800a8152cbe5296bfc48c56b8643e`. All235 roots retained;
183 in historic shard2 and52 in shard4. Shards1/3 contain zero SmallSort roots.
Ubuntu24.04 only. This diagnostic does not qualify macOS, R8 costs, or B2 proof.

The organizer semantic flags are copied from pinned std `scripts/run-kani.sh`:
`-Z unstable-options -Z function-contracts -Z mem-predicates -Z float-lib -Z c-ffi
-Z loop-contracts -Z quantifiers -Z stubbing --no-assert-contracts`, CBMC
`--object-bits 12`. Add exactly the diagnostic `-Z valid-value-checks`.
`-Z export-json --export-json PATH` is report transport through the unchanged stock
exporter; it does not add a proof premise/check. Use exact full root selectors and
terse text as in the organizer runner. No default-unwind override, check suppression,
uninit-checks, std autoharness, cfg-on controls, patch or model change.

Two root invocations per shard run concurrently, each `--jobs=1`, with separate
reusable target directories. This preserves the Ubuntu organizer jobs2 upper bound
and historic shard membership, while keeping an independent receipt for each root
if compilation fails. It changes scheduling and is not a matched cost measurement.
Each invocation has a600s outer wall cap (including compile) and stock600s harness
timeout. No shortened last-root envelope. Each shard verification stage<=7200s,
build<=2100s, setup<=25min; job<=210min, max-parallel shards1, total<=420 runner-min.
Root process-tree summed RSS<=6GiB; aggregate concurrently observed process-tree
RSS<=min(12GiB, available-at-stage minus2GiB), tightened before invocation.
Sampling0.1s can overshoot; RSS sums shared pages and is not PSS or kernel enforcement.
Kernel OOM/runner loss remains PARTIAL, never success. `/proc` figures are bytes.

The three checkouts are siblings `control/`, `export/`, `std/`. Build cwd is pristine
`export`; verify cwd is pristine `std` and library path `./library`. Target/export
scratch is in runner temp, outside all Cargo workspaces. All checkout depths>=2;
`runner.*` expressions appear only in step env. Setup is the exact export's action.
Only a same-tree child of the `[skip ci]` package on attempt1 is accepted.

Every shard seeds all expected NOT_RUN receipts before setup. Each attempted root
records actual argv/cwd, exit/signal/exception, wall/RSS/output caps and full stock
checks/covers/failures/warnings when a bounded, bound export is available. Root export
cap256KiB; output cap2MiB with4096-byte diagnostic tail. Oversize/malformed/missing
exports cannot become PASS. No raw logs, target trees, evidence archives or binaries
are uploaded. Curated JSON upper bound<128MiB per shard (static checked).
All source SHA/tree/clean checks and binary SHA256 are recorded before/after execution.

Classification: PASS; copy Unsupported; casts; other Unsupported; intended invalid-value
failure; compile-resource-not-run. Mixed failures retain every observed class/property;
primary order is catchall, other Unsupported, casts, copy Unsupported, intended failure.
All completed unsupported properties are diagnostics, never proof acceptance.
Unknown/undetermined property buckets make the census PARTIAL while preserving observed
failure families. The catchall includes unexpected assertions/invalid-value failures
and requires review; its reason is never an assertion that compilation failed.
There is no source-qualified intentional invalid-value root among ordinary235;
all manifest oracles are false. Do not infer intent from a name or classify an unexpected
validity failure as intended. A future canary needs separate scope/GO and an explicit oracle.

Overall COMPLETE requires both shard summaries COMPLETE, exactly183+52 unique bound
receipts, post-source checks and no failure of setup/upload. Any missing shard/root,
time/resource/output cut, runner loss, unknown schema/identity or unclassified failure
means PARTIAL. Do not fill remaining rows with PASS. Workflow success is diagnostic
execution completeness, not all-root PASS or independent correctness credit.

STOP B from plan§8 remains binding: Unknown treated as NoConstraints, rejection of legal
delayed raw copy, premature uninitialized read, lost intentional validity check, a new
shadow model, or overlap with active upstream design requires STOP/design note. This
package implements no compiler fast path or canary and cannot claim those gates passed.

Offline validation (no rustc/Cargo/Kani/CBMC):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts/ch8-b-census -v
PYTHONDONTWRITEBYTECODE=1 python3 scripts/ch8-b-census/static_check.py
actionlint -shellcheck= .github/workflows/ch8-b-census.yml
git diff --check
```

Coordinator handoff: bind CI package SHA/tree, g0 report SHA, exact request SHA256,
manifest SHA256 and review before reserving B-01. Create the trigger only after GO.
No reservation, trigger, push or CI was performed by worker14.
