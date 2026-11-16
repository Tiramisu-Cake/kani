# Handoff

Control parent: `0aac16ef62da9e9d5645782d458593e5d78143ba`.

Tool pins: stock `model-checking/kani` `0aac16ef62da9e9d5645782d458593e5d78143ba`, tree `9d8bc9312bf955ef126d32b819b3cd0ed105ed2b`; prototype `Tiramisu-Cake/kani` `8e299aa6243bc5f06a29c51e98aafa9564478220`, tree `9829702c1aa0ecb73c860fc0ad5451757917d6cb`.

Both source trees use nightly-2026-10-23, CBMC 6.11.0, and Kissat 4.0.1. `CI-REQUEST.json` freezes these pins, source hashes, expected observations, and execution caps.

The six proof invocations are three exact harnesses per pin. The stock matrix row is an unsupported-layout oracle; the prototype row gates initialized-slot success and read-in-drop failure. The original empty Drop row is diagnostic and preserves either completed prototype outcome as an observation. No local Rust, Cargo, Kani, or CBMC tool was run for this package. Static Python and workflow checks are the only local validation.

CI artifacts retain per-row command, cwd, source and tool identities before/after, versions, process exit and timeout data, bounded stdout/stderr, and JSON export when produced. Runtime proof credit remains `NONE`.

Edition correction for owner-reported run 43878900159 (trigger dbfb4d8bd8):
all three fixtures declare `// compile-flags: --edition 2021`; their standalone
commands receive the same flags through `RUSTFLAGS`. The issue body remains
byte-identical after the test header. The new candidate remains NOT_RUN.
Compiletest parses the compiler flags and forwards them through RUSTFLAGS;
the standalone driver passes them to rustc. Python tests verify that transport
using Python subprocesses, without invoking a Rust tool.
