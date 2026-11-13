# Uninitialized-memory contract oracles

This JSON-handler regression runs eight existing Rust inputs using the Kani CLI
and JSON 0.1 export. Run `./test.sh` with Kani on PATH, or run
`python3 test_checker.py` for synthetic Python-only checker tests.

| Case | Required result |
| --- | --- |
| p1 | No failures; useful outer ensures SUCCESS. |
| ordinary | No failures; generated body, ensures and harness assertions SUCCESS. |
| pfc | No failures; useful body, ensures, harness assertions and selected out assigns SUCCESS. |
| lawful-modifies | No failures; useful ensures, result29/out29/outside41 and selected out assigns SUCCESS. |
| p2 | Two exact instrumentation checks for the same intended uninitialized ptr::read u8; the exact outer ensures may additionally be FAILURE or UNREACHABLE at line14. |
| postcondition-hole | The same two required read checks; the exact outer ensures may additionally be FAILURE or UNREACHABLE at line16. |
| frame | Only the user outside assigns failure at line22; selected line23 out write SUCCESS. |
| clause | One exact transmute_neo MaybeUninit<u16> to u16 safety-check failure at its library location. |

`oracles.json` fixes input hashes, exact roots and lines, operation associations,
full failure identities, useful SUCCESS rows and the two specific allowed
consequences. The two read checks do not claim two distinct undefined operations.
Verifier-private writes cannot replace the expected user frame failure. No
arbitrary assertion or Unsupported can replace a listed failure.

The checker validates the shared JSON schema, complete run and selection,
source hashes, process exit and export time, enabled checks and configuration.
It crosschecks the full regular property inventory with JSON, rejects duplicate
keys/IDs, missing/extra failures and unknown statuses, and compares exact failure
multisets. Useful assertions must be SUCCESS; UNREACHABLE is insufficient.
Unused service properties may be UNREACHABLE. Unsupported properties may be
SUCCESS or UNREACHABLE only; a reached Unsupported fails the test and stops the
lawful-modifies run. Only the exact checkout prefix is normalized; generated
names and Rust library paths remain exact. Changed identities require a reviewed
manifest update; the runner never learns expectations from its output.

Invocations use the checkout root as cwd so export paths are checkout-relative,
with sequential jobs, edition 2021, warnings denied, explicit unstable features,
and final backend arguments `--cbmc-args --object-bits 12`. Each run has fresh
temporary target/export/output files and an in-memory invocation record binding
source, export and regular hashes. Temporary files are removed on success or
failure; failed runs print the checker reason, original exit and regular output
with text prefixes compatible with compiletest. CI artifact capture is separate
from this regression test.
