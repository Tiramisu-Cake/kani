# Unclaimed contract modes with initialization shadow transfers

The six roots in `roots.json` are preparation fixtures, not qualification of Replace or
RecursiveCheck. All source contracts describe legal identity transfers. The ordinary and
SimpleCheck companions are expected to pass, including the valid uninitialized-storage path.
The target modes have no guessed failure golden: a particular SUCCESS is retained as SUCCESS.

`test.sh` runs synthetic Python collector tests, then the six isolated Kani roots. A successful
script means collection and the legal companions passed. It does **not** establish a boundary
or accept a mode. Every collected result retains `BINDING_PENDING`, `UNREVIEWED` and
`mode_qualification: false` until coordinator review of transformed bodies and property mappings.
Unsupported, frame failures and unreached path covers are recorded as gaps, not qualifying negatives.

Coordinator invocation, after approving the exact six roots/caps:

```sh
python3 run.py --kani /path/to/kani --output /path/to/new/evidence-directory
```

The output directory must not exist. Each root gets a fresh copied source, retained model files,
argv/source SHA, full export, log and observation. `observations.json` retains all completed
outcomes and complete failure sets; build/export/incomplete-result errors stop downstream roots
as NOT_RUN. Companions failing or missing path covers fail the collection check. Review full
check/cover inventories and source→transformed body/mode/transfer binding before setting goldens.
Do not substitute harness metadata alone for the latter binding. No worker14 checker is used.

The profile preserves default solver/slicing/checks and uses unwind 8, proposed per-harness timeout
120 seconds (outer process cap 180 including compilation), and upstream b12 policy: `-Z unstable-options`
precedes consuming `--cbmc-args --object-bits 12`. JSON reports include metadata and contract trackers;
source recursion covers precede the actual self-call, and return covers follow transfer consumption.

The payload helper is called only for `initialized == true`, whose source input is `MaybeUninit::new(42)`.
For false, `MaybeUninit::uninit()` storage travels by value without a payload read. Replace havocs its
return before evaluating the ensures assumption; instrumentation may check the payload before that
assumption. RecursiveCheck's real self-call uses reentry replacement; depth 0 and 1 exercise both
source branches. Neither observation is assigned an exact failure expectation before CI.

The RecursiveCheck target and SimpleCheck companion have identical requires/ensures. The latter
explicitly unrolls the one permitted recursive step, preserving the legal identity-transfer
behavior without depending on checking recursion without its attribute. Ordinary companions call
the same target as their respective boundary root with default Assert semantics.

Marker diagnostics are deferred; no compiler semantics changed. The separate
[required-state design note](https://github.com/Tiramisu-Cake/verify-rust-std/blob/cee401ec22bd96e2b91733e6e2a275618b55f37e/research/challenge-8/kani-k1/kani3300/marker-modes/REQUIRED-STATE.md)
records that follow-up. Research links refer to separately prepared commits; publication belongs
to the coordinator.
