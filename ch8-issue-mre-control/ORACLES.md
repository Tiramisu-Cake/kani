# Upstream issue MRE package — NOT_RUN

Only pinned upstream 0aac16ef62da9e9d5645782d458593e5d78143ba.
Seven standalone .rs files, ten separate exact-harness Kani invocations.
The original slice candidate retains both harnesses byte for byte; initialized
and thin variants change only the respective declarations or modifies clause.
No std preparation or source/tool model patch. No SEL1.

`rows.json` freezes each expected outcome and exact failure description before
any execution. Expected outcomes are source predictions, never observed facts:

| Rows | Predicted verification | Desired Rust/model behavior | Exact failure oracle |
| --- | --- | --- | --- |
| copy_integer | FAILURE / COPY_UNSUPPORTED | SUCCESS | copy validity Unsupported for `*const u8` |
| raw_bool_overwrite | FAILURE / COPY_UNSUPPORTED | SUCCESS | copy validity Unsupported for `*const bool` |
| raw_bool_read | FAILURE / COPY_UNSUPPORTED | invalid-value FAILURE at typed read | copy validity Unsupported for `*const bool`; does not qualify invalid-value control |
| slice_uninit check_body | SUCCESS | SUCCESS | no failed properties |
| slice_uninit check_slice_havoc | FAILURE / UNINIT_FAILURE | SUCCESS | `Undefined Behavior: Reading from an uninitialized pointer of type \`*mut [u8]\`` |
| slice_initialized both harnesses | SUCCESS | SUCCESS | no failed properties |
| thin_uninit both harnesses | SUCCESS | SUCCESS | no failed properties |
| actual_uninit_read | FAILURE / UNINIT_FAILURE | same FAILURE | `Undefined Behavior: Reading from an uninitialized pointer of type \`*const u8\`` |

The full copy descriptions are exactly
`Kani currently doesn't support checking validity of \`copy_nonoverlapping\` for \`*const u8\``
and the same text with `*const bool`. There is no wildcard message matcher.
Generated CBMC property IDs cannot be known before the first run. For failures,
require an exhaustive failure-ID inventory with the exact frozen description;
export/receipt preserves every actual ID, class, description and location.
A different diagnostic, extra failed property, partial export, missing result,
wrong identity or timeout is UNKNOWN/UNEXPECTED, never reproduction credit.
An accounted unreachable follow-on check after a diagnostic is allowed only
for FAILURE observations. SUCCESS requires all checks successful.
These are diagnostic receipts, proof_credit NONE throughout.

Exact command template (absolute paths resolved and recorded at runtime):

    <tool>/scripts/kani <row.flags...> --harness <row.harness> --exact <source.rs> -Z export-json --export-json <row-dir>/export.json

Copy flags are exactly `-Z valid-value-checks`; slice comparisons and the real
uninit-read control use exactly `-Z function-contracts -Z uninit-checks`.
Only the JSON export transport is appended. No timeout/jobs/unwind/object-bits,
solver, no-checks or other semantic override. The row process has an external
30-second cap; incomplete rows stay UNKNOWN. Build cap720s, phase330s, job30min.
All ten cases need not finish inside their caps; remaining rows are NOT_RUN.
Future submission must assess exact runtime versions, results and IDs before
editing either issue. This package does not test floating/current upstream;
that draft checklist item remains open for a separately authorized stage.

Only coordinator authorization can publish/activate a same-tree control
sibling without [skip ci], sole parent clean upstream, fresh matching branch,
attempt1. This preparation commit itself authorizes no dispatch.
