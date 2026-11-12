# D1-P capture contract

SOURCE_READY/NOT_COMPILED. Coordinator-only manual workflow; no normal SAT.
One `--program-only` spawn per P1/pin; no second symex view, retries, P2 or solver replay.
All unchanged model/check/solver/slicing/target/object-bit options come from the driver;
the receipt at the wrapper is actual argv, not a reconstructed normal invocation.
`-Z unstable-options --cbmc-args --program-only` is the sole diagnostic addition.

Both pinned drivers have identical `call_goto_instrument.rs`, `harness_runner.rs`,
`call_cbmc.rs`. `instrument_model` specializes, applies restrictions, then calls
`instrument_contracts` with `--dfcc ROOT ... FILE FILE`. Wrapper snapshots input
before that in-place call and output afterwards; subsequent add-library,
undefined-function/drop-unused and backedge transformations remain unchanged.
Actual CBMC input is captured independently at its sole actual spawn.
Missing/duplicate/failed DFCC/CBMC capture is an error; no arbitrary file selection.

Stock CBMC 6.11 `show_program.cpp` writes plain `Program constraints:` and
`// PC source location`, `(number)` / `(sliced)` expressions even with JSON UI.
Kani's JSON consumer may reject this stream. Bytes, backend status, Kani status,
and offline parser status remain separate. No fabricated JSON or proof verdict.
A frontend that cannot reach the diagnostic spawn stops with the exact boundary
receipts. CI may fail after a complete diagnostic capture. Exit zero is no proof.

Limits: binary snapshot 64 MiB (exclusive create; oversize STOP), each captured
stdout/stderr 8 MiB, aggregate JSON failure inventory 2 MiB, selected projection
well below 16 MiB, at most 200 selected lines and 30 term excerpts per view.
Stock inspection views (symbol table and functions for each of three snapshots)
are read-only, each 30s/2 GiB sampled RSS; no extra symex. Symex 60s, RLIMIT_AS
2 GiB plus sampled descendant RSS 2 GiB; Kani case 300s/2 GiB sampled descendant
RSS. Shared pages may be double counted in aggregate samples; peaks may occur
between samples. CBMC address-space ceiling is hard and inherited by children.
Existing setup scripts/submodule recipe run through bounded phase collectors
(1200s/12 GiB per setup subphase). Build 5400s/12 GiB sampled RSS; job 120min. Watchdog interval 0.05s; old
6291456 KiB/2s/300s is historical only. All RSS/maxrss in KiB; GiB = KiB/1048576.
`wait4_maxrss_kib` (child plus kernel child accounting) is separate from sampled
max and `time_v_maxrss_kib` (UNKNOWN: time-v is not run). No comparison substitutes
one measure for another. Each subprocess has an owned session; nested owned
sessions are discovered by /proc ancestry with a Linux child-subreaper, so
orphaned setsid descendants remain owned and bounded. No global process-name kill.

Collectors drain capped streams, retain original exits/signals, and forward
unmodified bytes to the parent with bounded backpressure; downstream EPIPE is
recorded and collector keeps draining. No shell eval or full environment dump.
Logs are original bounded prefixes with exact emitted/dropped counters. Final
outcome is in independent receipts; first100/final100 textual milestone records
are retained independently of byte-prefix caps, never a grep/head tail. All artifacts have a
relative path/bytes/SHA256 manifest. --keep-temps work is outside the artifact
tree; only explicitly capped snapshots and selected views are uploaded. Upload always runs; its native failure and
separate upload-status artifact are visible, and never green a failed step.

Offline parser reads at most 8 MiB, 65536 bytes/line, 100000 records, 200000
character-work units, 5s/view. It counts only visible show_program records;
`sliced` means ignored. Other SSA categories, widths, full guards, type extent,
Layout N, backing object, pointer width and metadata, target/write/property
bindings remain explicit UNKNOWN unless established from saved model views in
D1-A. Offsets/indices and operators are textual heuristics; no scalar P1 inference.
Whitespace-only SHA256 fingerprints preserve SSA suffixes; they are not IREP
DAG nodes, converter calls or cache misses. VCC prefixes are not parsed as SSA.
Repeated equal text records remain occurrences. Unknown-width top30 is UNKNOWN.
Coordinates/excerpt hashes bind bounded observations to the model hash, not to
semantic feasibility. Partial/truncated output has incomplete coverage.

JSON inventory retains complete property objects even from a partial enclosing
array, under bytes/depth/objects/time budgets; failures are not capped at top30.
This stage has no SAT: failure inventory NOT_RUN/UNKNOWN, no total failure claim,
no semantic verdict completeness. Selected projections are an evidence index;
absence of a selected line establishes nothing about source/model bindings.

Synthetic commands (Python fake children only):
`PYTHONDONTWRITEBYTECODE=1 python3 diagnostics/kani3300-d1p/test_synthetic.py`
and `PYTHONDONTWRITEBYTECODE=1 python3 diagnostics/kani3300-d1p/test_workflow.py`.
`test_workflow.py` needs PyYAML; capture/runner/parser use only stdlib in CI.
