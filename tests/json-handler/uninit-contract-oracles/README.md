# Uninit contract exact oracles

This is one `json-handler exec` scenario using the existing Kani CLI and JSON
0.1 export. It reads the eight existing input/root selections in `oracles.json`;
there are no copied Rust bodies or expected-suite runner/schema changes.

`python3 test_checker.py` runs Python-only adversarial tests. `test.sh` also
invokes Kani and belongs in coordinator CI only. It uses sequential jobs1,
`RUSTFLAGS='--edition 2021 -D warnings'`, regular output, the four explicit
unstable features and final backend arguments `--object-bits 12`. No global
object-bit/solver/slicing/check default changes. The existing CI capture owns
resource limits and must retain the printed unique artifact directory (including
`target` for selected GOTO evidence). No scheduler or CBMC interceptor is added.

Each invocation retains its original exit/signal, source hashes before/after,
argv/environment recipe, regular output and unique JSON export. Missing,
malformed, stale or incomplete exports fail. A negative exit1 is accepted only
with a completed, consistent export and exact inventory. Observations are PASS
or FAIL, and the scenario exits 0 or 1. Missing/pending oracle bindings fail;
there is no manual confirmation step or UNKNOWN result in CI.

Kani runs with the checkout root as its recorded `cwd`: the existing JSON
exporter makes source paths relative to the process working directory. Target,
export and regular output still use the unique invocation directory. The checker
requires this cwd and keeps the exact input/root comparison. Synthetic subprocess
tests model the exporter's cwd-relative paths for all eight cases, including
wrong input/root and pending bindings. Console observations have a text prefix
because compiletest's error renderer parses lines starting with `{` as rustc
diagnostics; the complete structured observation remains in `observation.json`.

The eight `REGRESSION_BOUND` oracles pin reviewed CI r3 run `43430797896`
export/regular identities. Input hashes and retained file hashes were checked
against each invocation receipt. Exact useful regular records include `id`,
`status`, `description` and full `location`; failures also pin class, file and
line. The manifest retains evidence SHA256/selectors and explicit operation
associations. CI never learns IDs or rewrites expectations from its observations.
These are regression expectations: independent source-to-GOTO causality,
private-write target qualification and proof credit remain `NOT_RUN`. In
particular, a library read's source-to-helper causal binding is not established
by an exact library property ID. This replaces the former conflation of CI
regression acceptance with manual semantic qualification.

| Case | Committed regression expectation |
| --- | --- |
| p1 | No failures; useful outer ensures SUCCESS. |
| ordinary | No failures; actual generated body assertions, ensures and harness assertions SUCCESS. Original-function UNREACHABLE copies are not the useful assertions. |
| pfc | No failures; useful body/ensures/harness assertions and selected out assigns SUCCESS. |
| lawful-modifies | No failures; useful ensures, result29/out29/outside41 and selected out assigns SUCCESS. |
| p2 | Exactly two required ptr::read u8 uninit failures; only the exact outer ensures assertion additionally permits FAILURE or UNREACHABLE at line14. |
| postcondition-hole | Independently reviewed input: same two required uninit failures; its exact outer ensures permits FAILURE or UNREACHABLE at line16. |
| frame | Exactly the user assigns failure at line22 (`*var_7`); selected line23 out write SUCCESS. |
| clause | Exactly one transmute_neo MU<u16>→u16 safety-check failure, with exact library source and line. No assumed second layer. |

All eight retained r3 invocations pass offline with these fixed expectations.
Future CI needs the same source/tool/property identities and complete consistent
exports/regular output; it needs no manual binding. A changed identity, missing
required check, unrelated failure or useful positive assertion becoming
UNREACHABLE fails. A compiler/toolchain change requires a reviewed oracle update,
not automatic ID or source-path wildcarding. Only the exact checkout prefix is
normalized; Rust library paths and generated names remain exact.

The checker validates complete regular counts/statuses against JSON; successful
checks absent from JSON are matched in the same invocation's regular output.
Unrelated UNREACHABLE service properties are allowed. Unsupported properties are
assert(false): SUCCESS proves that the unsupported path was not executed;
SUCCESS/UNREACHABLE are allowed and crosschecked with regular output. FAILURE,
UNDETERMINED and UNKNOWN are reached Unsupported and trigger the lawful-modifies
STOP; other nonterminal/error statuses fail validation without claiming reach.

For offline rechecking of the retained invocation after reviewed binding updates:
`python3 checker.py --case CASE --directory ARTIFACT_DIRECTORY`.
This checks retained export/regular hashes and current input identity before
applying the regression oracle. No compiler/verifier is needed for offline replay.
