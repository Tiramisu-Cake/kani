# Part 1 mixed-root JSON composition

This JSON-handler suite adds small roots for immutable initialized and hole
statics, ordinary assertion plus ensures, legal and negative proof-for-contract
(PFC), a repeated nonrecursive callee, a genuine recursive cycle, and an
unrelated legal root. Every root is scheduled in its own fresh Kani process;
the cycle/legal pair is then selected in both CLI selector orders, again in
fresh processes, with `--jobs 1` and a fresh target/export directory per run.

Run `./test.sh` with the matching Kani binary on `PATH`. Run
`python3 test_compare.py` for Python-only synthetic checks. The shared immutable
JSON export schema validator and the existing exact regular-output parser are
loaded read-only from `scripts/validate_json_export.py` through the existing
uninit contract-oracle checker. Existing suites and validators are not changed.

`roots.json` pins the Rust input SHA-256 and intended root/mode/verdict/source
line map. Every property binding intentionally remains `BINDING_PENDING`: exact
generated property identities and per-root complete check inventories require
review of actual exports. The ordinary `./test.sh` path fails closed before
invoking Kani while any binding is pending. The coordinator's pre-C1 capture
path is `./test.sh --collect-unbound --keep-output`; it runs isolated roots,
then all seven selectors in both orders and the focused cycle/legal pair in
both orders. It prints and retains `capture.json`, each invocation's
`receipt.json`, exports, and regular output. Capture exits 2 with
`UNBOUND_CAPTURE`, never PASS. Review the full inventories and operation/root
bindings, including complete regular check IDs/statuses, failure kind, full
failed-property metadata, and the exact Unsupported inventory. Commit exact
identities to `roots.json` with status
`REGRESSION_BOUND`, then freeze that reviewed package into C1 and run ordinary
`./test.sh` as the C1 qualification. No output is auto-learned or written into
the manifest. The runner rejects incomplete exports/selections, un-attributable
inventories, lost/extra or status-swapped checks, failure counter/kind drift,
wrong-root results, unsupported/failure metadata drift, and any root inventory
change between isolated and combined runs. It does not accept a match based on
the word `FAILED`.

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
