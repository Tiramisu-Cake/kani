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
with a completed, consistent export and exact inventory. Exit2 of the scenario
means UNKNOWN, not an expected negative success; the exec gate must fail it.

All initial bindings are `BINDING_PENDING`. The first CI capture cannot qualify
any case. Review the selected complete regular/GOTO evidence of that invocation,
then commit exact failure identities and selected useful successful regular
records (`id`, `status`, `description`, full `location`), every required operation
mapping and artifact SHA256/selectors under `binding`. Set `BOUND` only after
that review. Never learn an oracle automatically from observed failures. P2 and
postcondition-hole have distinct case identities despite identical root names.
Postcondition-hole and clause counts remain unset until independently mapped;
P2 must retain its two known instrumentation obligations. No generated ID is
guessed here. Evidence references/operation mappings are reviewed declarations;
the Python checker does not independently prove the source-to-GOTO mapping.

The checker validates complete regular counts/statuses against JSON; successful
checks absent from JSON are matched in the same invocation's regular output.
Unrelated UNREACHABLE service properties are allowed. A required useful positive
assertion must be SUCCESS. Reached Unsupported fails; an unreachable Unsupported
service property is allowed and crosschecked with the unreachable inventory.
A reached lawful-modifies Unsupported stops further selections for that scenario.

For offline rechecking of the retained invocation after reviewed binding updates:
`python3 checker.py --case CASE --directory ARTIFACT_DIRECTORY`.
This checks retained export/regular hashes and current input identity before
applying the oracle. Actual compilation, semantic qualification, private target
binding and proof credit are NOT_RUN until coordinator CI/review establishes them.
