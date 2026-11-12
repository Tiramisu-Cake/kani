# D0 CI diagnostics

Source inputs: candidate `5eec235e3d0eeb99d7e432fcaef3a3135747b789`, baseline
`a0a2386001a15fecfe2facc2f6cd87f3dee13b60`. Request: g0 D0-P publication
`5956660766`, `research/challenge-8/kani-k1/kani3300/d0/CI-REQUEST.md`.

Only a push to `uninit-ci/**` triggers the workflow. Publication and execution
belong to the coordinator. This preparation does not dispatch CI.

Both source checkouts use the template setup action and
`cargo build-dev -- --release`. Each build records tool, source, fixture,
binary, target and sysroot identities. Baseline verification consumes the exact
candidate-built Kani libraries, after checking that library source files match;
both use the same pinned Rust sysroot and solver executables. Each case has a
fresh process/output directory. Normal compiler prewarm stays enabled.

The compiler launcher wraps only the built artifact and records the actual
compiler child's wait status. It preserves argv and forwards signals. The copied
CBMC capture shim preserves solver stdout, options, exits and signals. Case
supervision kills/reaps the process group at 600 seconds. The job is limited to
240 minutes, each release build to 2400 seconds, and read-only inventory commands
to 60 seconds. There are no retries.

`d0-curated` contains bounded JSON, exact identities, compressed SHA256 manifests
and `SUMMARY.md`, at most 5 MiB including workflow outcomes.
`d0-private` contains original captures, models, sidecars and private logs, with
seven-day retention. GitHub artifact permissions follow repository permissions:
artifact names do not provide separate access controls. The coordinator must
give D0-A only `d0-curated` and retain `d0-private` itself.

Original setup/build/compiler/solver/verification/inventory/curation exits are
recorded separately. A verification FAIL neither aborts collection nor counts as
infrastructure success. The final gate checks setup, compilation and curation;
verification verdicts remain in the report. Unknown/missing/capped source,
property, operand or runtime bindings stop the affected inference and remain
`UNKNOWN`/`INCOMPLETE`. Full trace/GOTO files are never copied into the curated
packet. An infrastructure success makes no verification or causal claim.

No dynamic pointer decoding, last-writer inference or normalized model
equivalence is invented from property suffixes, CLI order or symbol names.
`controls.json` explicitly records comparison gates that remain UNKNOWN and
the observed candidate prewarm sequences. A/B/D are compared to baseline
A/B/pair by exact per-harness property inventories and GOTO listings, normalizing
only recorded absolute checkout/output paths. Emitted MIR files are compared
when present. A strict mismatch stops the comparison; matching inventories do
not establish full original/final/consumed MIR or model equivalence.
A precise follow-up packet is needed
when required observations exceed the curated cap or a binding is unavailable.

Local checks use Python synthetic executables only:

```sh
python3 -m unittest discover -s .github/d0 -p 'test_*.py'
actionlint -shellcheck= .github/workflows/d0-diagnostics.yml
git diff --check
```

The inventory decoder follows the pinned CBMC 6.11.0 producers:
[properties](https://github.com/diffblue/cbmc/blob/cbmc-6.11.0/src/goto-programs/show_properties.cpp),
[GOTO instructions](https://github.com/diffblue/cbmc/blob/cbmc-6.11.0/src/goto-programs/show_goto_functions_json.cpp),
and [JSON UI events](https://github.com/diffblue/cbmc/blob/cbmc-6.11.0/src/util/ui_message.cpp).
