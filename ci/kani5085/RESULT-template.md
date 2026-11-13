# KANI5085 — RESULT template

Status: NOT_RUN. Prepared by worker15; no verifier/build executed locally.
No CI publication/dispatch or upstream message was performed.

Research commit: FILL_AFTER_COMMIT
CI overlay commit / workflow SHA256: NOT_RUN
CI branch / run URL / attempt / artifact identity: NOT_RUN
Runner image / platform / GCC/G++ / CMake / Ninja: NOT_RUN
Kani source: `0aac16ef62da9e9d5645782d458593e5d78143ba`
Kani actual version / driver+compiler hashes / Rust toolchain: NOT_RUN
CBMC base source: `107a1e504cd69a2f3483717c8bcfcfa59814c557`
CBMC fix source: `9f2d01ec2bf115879c86e22203d403ba156d22e5`
CBMC versions / binaries / SHA256 / cache hashes / build exits: NOT_RUN
Issue body SHA256: `22f137d6e4eea60a7e0f24dd55ffeeffe6bf88aa3f372e0975fb410dd87e5259`

| Root | Base: Kani exit / CBMC exit / verdict / invariant receipt | Fix: Kani exit / CBMC exit / verdict / invariant receipt |
|---|---|---|
| static_zst_arr (issue verbatim) | NOT_RUN | NOT_RUN |
| const_zst_arr | NOT_RUN | NOT_RUN |
| tail_typed_copy | NOT_RUN | NOT_RUN |
| tail_nondet | NOT_RUN | NOT_RUN |
| runtime_control (issue verbatim) | NOT_RUN | NOT_RUN |

For each executed row copy its actual invocation path/hash, argv, source hash,
verdict, exits/signals and exact File/Condition/Reason block when present.
Do not mix invariant fields from different builds/rows/versions. Record capture
completeness, timeout/overflow and whether CBMC's model invocation was reached.
Any NOT_RUN, missing receipt, incomplete capture or source/target mismatch stays
explicit. Earlier lowering failures are not CBMC outcomes; absence of the
invariant does not imply VERIFICATION SUCCESSFUL.

Literal #5085 paired result: UNKNOWN / NOT_RUN.
Const paired result: UNKNOWN / NOT_RUN.
Tail paired result: UNKNOWN / NOT_RUN.
Symbolic-byte lowering/control result: UNKNOWN / NOT_RUN.
Runtime control result: UNKNOWN / NOT_RUN.

Conclusion for owner (fill from actual paired results only): UNKNOWN.
No independent full-proof, B1/B2, uninitialized-memory, general #3300 or general
CBMC correctness claim. Any issue comment is an owner action, not this workflow.
