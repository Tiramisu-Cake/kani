# Part 1 mixed-root JSON composition

This JSON-handler suite adds small roots for immutable initialized and hole
statics, ordinary assertion plus ensures, legal and negative proof-for-contract
(PFC), a repeated nonrecursive callee, a genuine recursive cycle, and an
unrelated legal root. Every root is scheduled in its own fresh Kani process;
the cycle/legal pair is then selected in both CLI selector orders, again in
fresh processes, with `--jobs 1` and a fresh target/export directory per run.

Run `./test.sh` with the matching Kani binary on `PATH`. Run
`python3 test_compare.py` and `python3 test_bindings.py` for Python-only
synthetic checks. The shared immutable
JSON export schema validator and the existing exact regular-output parser are
loaded read-only from `scripts/validate_json_export.py` through the existing
uninit contract-oracle checker. Existing suites and validators are not changed.

Property paths are checkout-relative, including paths inside closure IDs and
cycle diagnostics. External rustup source paths use the checker's
`rust-toolchain:<toolchain>/library/<source>` namespace, retaining the exact
toolchain, source suffix and coordinates while removing installation roots and
relative traversal depth. IDs, descriptions, statuses and all failure metadata
still compare exactly after this normalization. Warnings outside RESULTS are
ignored; verification checks and backend configuration remain enforced.

`roots.json` pins the Rust input SHA-256 and intended root/mode/verdict/source
line map. All seven roots have exact `REGRESSION_BOUND` inventories. Six use
reviewed isolated R3 capture run `43504302188` (`binding_evidence` at the manifest
level); `cycle_root` uses R4 run `43506774865` (its own `binding_evidence`).
The cycle binding pins every check/status, failure kind, full failed-property
metadata and exact Unsupported inventory, including the stable readable cycle
path. All four R4 mixed selections retain that cycle inventory exactly. Evidence
pins the capture digests and source commits; R4's CI wrapper commit differs from
the source commit only in workflow files. No output is learned during a run.
The ordinary `./test.sh` path fails closed before invoking Kani if any binding
is pending. The fresh observation path is `./test.sh --collect-unbound --keep-output`;
it skips comparisons against manifest golden inventories even when they are marked
bound, then runs isolated roots,
then all seven selectors in both orders and the focused cycle/legal pair in
both orders. It prints and retains `capture.json`, each invocation's
`receipt.json`, exports, and regular output. Capture exits 2 with
`UNBOUND_CAPTURE`, never PASS, and reports `binding_status: NOT_CHECKED_CAPTURE`.
Inventory differences do not stop capture: it records all per-root/order diffs
in `mixed_root_comparisons` and continues through all 11 invocations. Each diff
retains exact added/removed rows and an `accepted` oracle result.
`mixed_root_oracle` is `EXACT_MATCH` or `MISMATCH`. Every added or removed check,
and every metadata, status, verdict, failure, Unsupported, or cover difference,
is a mismatch. A captured `MISMATCH` still exits 2 and supplies no regression credit. Process,
schema, incomplete-output, and root-binding errors still stop the run.
Any caught stop reports its invocation/order and
phase plus the exception type and reason on stderr, before and after regular
logs. Failed captures retain a `capture.json` with `status: FAIL`, the failing
step, and available receipts; unreadable receipts cannot hide the original
reason. Preflight stops report their reason before a capture directory exists.
Review the full inventories and operation/root
bindings, including complete regular check IDs/statuses, failure kind, full
failed-property metadata, and the exact Unsupported inventory. Commit exact
identities to `roots.json` with status
`REGRESSION_BOUND`, then freeze that reviewed package into C1 and run ordinary
`./test.sh` as the C1 qualification. No output is auto-learned or written into
the manifest. The runner rejects incomplete exports/selections, un-attributable
inventories, failure counter/kind drift, wrong-root results, and
unsupported/failure metadata drift. The mixed-root oracle requires exact full
multiset equality for checks, failed-property metadata, Unsupported properties,
and covers, plus equal verdict and failure kind. Root harness and target-function
checks stay exact, including status and metadata; reached covers retain their
exact identities, descriptions, and locations. Every inventory change is
rejected, including changes to shared safety instrumentation. Fixtures currently
have no covers; a future reviewed
binding with covers must also supply `expected_covers`.

The A/B and B/A labels describe only selector argument order. Source/CLI order
does not establish producer or codegen order. `ROOT-ORDER-MAP.json` records
`ORDER_UNCONTROLLED`; no matched-order contamination credit is available until
the coordinator supplies an exact bounded producer-order receipt with both
selected-body identities and observed order. This suite cannot establish
source-to-transformed-body causality or proof credit by itself. Cycle
`Unsupported` is an expected mode-boundary observation only after exact
inventory review; it is not a legal proof result and must not contaminate the
unrelated legal root.

The fixtures intentionally stay small and cover root-local export composition.
They do not implement the broader transfer matrix (offset/stride/raw extent,
reset/reseed, Move/call handoff) or qualify shared-cache architecture. The
required CI request is a fresh process/model run of this suite in both full selector
orders and both focused pair orders plus isolated roots, alongside the existing eight strong uninit
oracles, mode-boundary roots, and Quick suite. Use object-bits 12. CI status is
`NOT_RUN` until the coordinator submits and reviews that request.
