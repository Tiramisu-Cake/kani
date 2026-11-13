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

`roots.json` pins the Rust input SHA-256 and intended root/mode/verdict/source
line map. Six roots have exact `REGRESSION_BOUND` inventories from the reviewed
isolated R3 capture (run `43504302188`); `binding_evidence` pins its digest. `cycle_root` remains `BINDING_PENDING`: its `all_A_then_B`
Unsupported/check diagnostic contains unstable internal identity data, so it must
wait for a new capture after the diagnostic uses the stable message schema recorded
in the manifest. The pending cycle inventory is not inferred from current runtime
output. The ordinary `./test.sh` path fails closed before invoking Kani while any
binding is pending. The coordinator's pre-C1 capture
path is `./test.sh --collect-unbound --keep-output`; it runs isolated roots,
then all seven selectors in both orders and the focused cycle/legal pair in
both orders. It prints and retains `capture.json`, each invocation's
`receipt.json`, exports, and regular output. Capture exits 2 with
`UNBOUND_CAPTURE`, never PASS, including when bindings are already reviewed.
Inventory differences do not stop capture: it records all per-root/order diffs
in `mixed_root_comparisons` and continues through all 11 invocations. Each diff
retains exact added/removed rows, an `accepted` oracle result, and `t1b_evidence`.
`mixed_root_oracle` distinguishes `EXACT_MATCH`, `MATCH_WITH_T1B`, and `MISMATCH`;
even a captured `MISMATCH` exits 2 and supplies no regression credit. Process,
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
unsupported/failure metadata drift. The mixed-root oracle requires the same
verdict, exact multiset of failures (IDs, descriptions, locations and remaining
metadata), Unsupported inventory, and useful checks/covers as isolation. Root
harness and target-function checks stay exact, including their statuses;
reached covers retain their exact identities, descriptions and locations.
It does not accept a match based on the word `FAILED`.

**Known limitation T1b:** DelayedUbPass writes instrumentation into the unit's
shared cache. Mixed roots can therefore gain or lose SUCCESS/UNREACHABLE safety
checks in a shared monomorphized function. The explicit reviewed allowlist is
currently only `std::ptr::read::<u8>`: both its exact regular-output function
location and its `.safety_check.N` property ID must match. Extra/missing rows
there are accepted and retained as T1b evidence. Existing IDs may not change
status, description or location; failures, Unsupported, assertions, reachability
checks and covers are never exempted. Other functions fail closed until
explicitly reviewed. In capture r2 (`43502450916`), `immutable_legal` acquired
six successful checks `.safety_check.5`–`.10` in that shared function, with the
same SUCCESS verdict and zero failures. This oracle allowance does not repair
T1b or qualify shared-cache isolation; that remains a separate upstream
mechanism (R3 answer 7/11). Isolated binding review remains exact. Fixtures
currently have no covers; a future reviewed binding with covers must also
supply `expected_covers`.

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
