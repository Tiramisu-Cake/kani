# Slice havoc MRE v2 — ALL_NOT_RUN

Pinned clean upstream: 0aac16ef62da9e9d5645782d458593e5d78143ba.
Four standalone files; seven exact-harness invocations. No union or MaybeUninit.
All allocations use Layout::array::<u8>(2), alloc, identical null-return handling,
and dealloc on each non-null completing path. initialize is unsafe: its caller
must provide a live exclusively owned two-byte allocation. These harnesses do so.
This is a concrete diagnostic experiment, not a general contract theorem.

| Row | Predicted outcome | Desired behavior | Failure oracle |
| --- | --- | --- | --- |
| slice_uninit_check_body | SUCCESS | SUCCESS | no failed properties |
| slice_uninit_check_slice_havoc | UNINIT_FAILURE | SUCCESS | safety_check in write_any_slice; exact description below |
| slice_initialized_check_body | SUCCESS | SUCCESS | no failed properties |
| slice_initialized_check_slice_havoc | SUCCESS | SUCCESS | no failed properties |
| thin_uninit_check_body | SUCCESS | SUCCESS | no failed properties |
| thin_uninit_check_slice_havoc | SUCCESS | SUCCESS | no failed properties |
| actual_uninit_read | UNINIT_FAILURE | UNINIT_FAILURE | safety_check; exact byte-read description below |

Slice diagnostic: ``Undefined Behavior: Reading from an uninitialized pointer of type `*mut [u8]` ``.
Byte-read diagnostic: `Undefined Behavior: Reading from an uninitialized pointer of type `*const u8``.
rows.json is the machine-readable, predeclared oracle. Slice reproduction also
requires each failed property ID to identify the function write_any_slice as a
complete path component (not an arbitrary substring). Actual generated property
IDs and source locations are unknown until execution and preserved in receipts.
Wrong class/function/message, extra unrelated failure, timeout, incomplete/missing/
null/wrong-type export, compile error, identity or stage mismatch gives no
reproduction credit. Export inventories must account for every failed check.
A SUCCESS observation has zero failures and all checks successful. Failure may
include inventoried unreachable follow-on checks; no undetermined/unknown checks.

Initialized comparison changes only two writes immediately before initialize
in each harness. Thin comparison changes only modifies to (p, p.wrapping_add(1));
for this live two-byte allocation that is the same target as p.add(1), and avoids
an unsafe pointer-arithmetic expression inside generated contract closures.
The negative control performs read_volatile on the same allocation without writes;
it has no value assertion that could add an unrelated failure.
The null-return path is ordinary allocation-failure handling, not an assumption.

Exact invocation template:

    <tool>/scripts/kani -Z function-contracts -Z uninit-checks -Z stubbing --harness <harness> --exact <source.rs> -Z export-json --export-json <row-dir>/export.json

All other Kani options/checks remain default. No local compiler/verifier invocation.
External caps retained from v1: row30s, phase330s, build720s, setup4min, job30min,
RSS6GiB, log heads1MiB/tails4096B, export8MiB. Incomplete rows remain UNKNOWN/NOT_RUN;
the caps do not guarantee completion. Fallback preserves original exits, errors,
RUNNING/EXECUTED snapshots, argv/cwd and all source/request/tool identities.
All expectations are source predictions, not runtime evidence. proof_credit NONE.

Preparation authorizes no push, CI, publication or ledger update. A separately
authorized coordinator may activate a same-tree sibling without skip-ci, sole
parent upstream0aac, fresh uninit-ci/ch8-issue-mre2-* branch, attempt1 only.
Issue text and v1 fixtures remain unchanged; no valid-value runs are repeated.
