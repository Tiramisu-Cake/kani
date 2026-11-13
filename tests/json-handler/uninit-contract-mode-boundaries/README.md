# Unclaimed contract modes with initialization shadow transfers

The six roots in `roots.json` are preparation fixtures, not qualification of Replace or
RecursiveCheck. All source contracts describe legal identity transfers. The Replace ordinary
and SimpleCheck companions, and the bounded recursive SimpleCheck companion, must succeed,
including the valid uninitialized-storage path. Replace remains unclaimed: its completed
outcome is retained without a failure golden.

`recursive_ordinary` and `recursive_check` exercise real `#[kani::recursion]` and must report
exactly one failing `unsupported_construct`, whose diagnostic is
`Kani delayed uninitialized-memory analysis detected an interprocedural cycle` (optionally
followed by its active-frame/path detail). The failed-property and active Unsupported inventories
must agree, with no additional failures. SUCCESS, a different Unsupported, or an extra failure
fails collection. This is the documented
[delayed-analysis limitation](../../../docs/src/reference/experimental/contracts.md#limitations),
not a successful proof: both roots retain their FAILURE verdict and full failure sets,
`expected_unsupported: true`, and `companion_pass: null`.

`test.sh` runs synthetic Python collector tests, then the six isolated Kani roots. A successful
script means collection matched the manifest expectations, including the two expected
Unsupported results. It does **not** qualify or accept a contract mode. Every collected result
retains `BINDING_PENDING`, `UNREVIEWED` and
`mode_qualification: false` until coordinator review of transformed bodies and property mappings.
Unsupported, frame failures and unreached source paths remain recorded as gaps, not qualifying
negatives. Expected Unsupported roots receive no PASS credit even when collection succeeds.

Coordinator invocation, after approving the exact six roots/caps:

```sh
python3 run.py --kani /path/to/kani --output /path/to/new/evidence-directory
```

The output directory must not exist. Each root gets a fresh copied source, retained model files,
argv/source SHA, full export, log and observation. `observations.json` retains all completed
outcomes and complete failure sets; build/export/incomplete-result errors stop downstream roots
as NOT_RUN. A successful companion must have SUCCESS and satisfy every required source cover
in `roots.json`. The regular `run.log` supplies cover descriptions and file/line/column metadata;
its cover IDs and statuses must exactly match the export inventory. Copies of a cover are grouped
by description and source location, ignoring function names: any SATISFIED copy covers that source
path, even if the original function's copy is UNREACHABLE. A missing cover, a different description
or location, or a source path with no satisfied copy fails a successful companion. Raw inventories
and all parsed cover records are retained. This source-path accounting does not establish
transformed-mode binding. Review full check/cover inventories and source→transformed
body/mode/transfer binding before claiming qualification.
Do not substitute harness metadata alone for the latter binding. No worker14 checker is used.

The profile preserves default solver/slicing/checks and uses unwind 8, proposed per-harness timeout
120 seconds (outer process cap 180 including compilation), and upstream b12 policy: `-Z unstable-options`
precedes consuming `--cbmc-args --object-bits 12`. JSON reports include metadata and contract trackers;
source recursion covers precede the actual self-call, and return covers follow transfer consumption.

The payload helper is called only for `initialized == true`, whose source input is `MaybeUninit::new(42)`.
For false, `MaybeUninit::uninit()` storage travels by value without a payload read. Replace havocs its
return before evaluating the ensures assumption; instrumentation may check the payload before that
assumption. RecursiveCheck's real self-call uses reentry replacement; depth 0 and 1 exercise both
source branches, but do not bound delayed initialization analysis. The two genuinely recursive
roots therefore expect the documented interprocedural-cycle Unsupported, without proof credit.

The RecursiveCheck target and SimpleCheck companion have identical requires/ensures. The latter
explicitly unrolls the one permitted recursive step, preserving the legal identity-transfer
behavior without depending on checking recursion without its attribute. Its base and unrolled-edge
covers may execute inside a contract closure. Ordinary companions call the same target as their
respective boundary root with default Assert semantics; the recursive ordinary root still reaches
the delayed-analysis cycle.

Marker diagnostics are deferred; no compiler semantics changed. The separate
[required-state design note](https://github.com/Tiramisu-Cake/verify-rust-std/blob/cee401ec22bd96e2b91733e6e2a275618b55f37e/research/challenge-8/kani-k1/kani3300/marker-modes/REQUIRED-STATE.md)
records that follow-up. Research links refer to separately prepared commits; publication belongs
to the coordinator.
