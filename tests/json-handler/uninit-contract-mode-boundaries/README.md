# Contract modes with initialization shadow transfers

This JSON-handler regression exercises six roots in `roots.json`. Run `./test.sh`
with Kani on PATH, or `python3 run.py --kani /path/to/kani`. Run
`python3 test_observe.py` for synthetic Python-only collector tests.

| Root | Expected result |
| --- | --- |
| replace_transfer | Completed SUCCESS or FAILURE is observed without a failure golden; Replace support is unclaimed. |
| replace_ordinary | SUCCESS with both required return-path covers. |
| replace_simple_check | SUCCESS with both required return-path covers. |
| recursive_check | Exactly the interprocedural-cycle Unsupported failure. |
| recursive_ordinary | Exactly the interprocedural-cycle Unsupported failure. |
| recursive_simple_check | SUCCESS with required initialized/uninitialized return and base/unrolled-edge covers. |

All source contracts describe legal identity transfers. Initialized storage
contains 42; uninitialized storage travels by value without a payload read.
Replace havocs its return before the ensures assumption, so instrumentation may
check the payload before that assumption. The recursive roots use actual
`#[kani::recursion]`; depth 0 and 1 do not bound delayed initialization analysis.
The SimpleCheck companion explicitly unrolls the permitted recursive step with
identical requires/ensures.

The two recursive failures must be the sole active Unsupported and sole failed
property, with diagnostic `Kani delayed uninitialized-memory analysis detected an
interprocedural cycle` with its active-frame/path detail. Frames use readable
function names and `provenance=source`, `provenance=registration-override`
(with a readable origin), or `provenance=discarded-closure-override`. Calls
include `file:line`; internal `AnalysisKey`, `Instance` and `DefId` Debug
identities are rejected by the boundary oracle.
A different Unsupported, extra failure or SUCCESS fails collection. These are
expected results for the documented
[delayed-analysis limitation](../../../docs/src/reference/experimental/contracts.md#limitations).
Matching an expected Unsupported does not prove the root correct or qualify a
contract mode. Replace outcomes likewise establish no mode qualification.

Successful companions require complete inventories and every specified source
cover. Regular-output cover IDs/statuses must match JSON exactly. Covers group
by description and source file/line/column across generated/original function
copies: one SATISFIED copy covers that path even if another is UNREACHABLE.
Missing or changed covers, or a group with no satisfied copy, fail a companion.
Check SUCCESS and cover SATISFIED remain distinct. Harness metadata and source
covers alone do not establish source-to-transformed-body binding.

Each root uses a fresh source/export/log directory, default solver and checks,
unwind 8, a 120-second harness timeout, a 180-second outer process cap, and
`-Z unstable-options` before `--cbmc-args --object-bits 12`. The runner checks
source hashes across invocation. Build, export, timeout and incomplete-result
errors stop later roots as NOT_RUN; unexpected completed outcomes fail the suite.
Temporary files are removed on exit, with observations and failing logs printed
for diagnosis. CI artifact capture is separate from the regression test.
