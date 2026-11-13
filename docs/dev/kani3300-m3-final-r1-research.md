# M3-FINAL Quick R1: worker14 stop report

Base: `34d54caf145d433cdf603433f26604f573cc3868`.
Reported Quick run: `43488479150`; kani 22/0, ui 14/0, script 1/0,
expected 198/3, json-handler 2/1. These are supplied CI results, not a local rerun.

## Offset fixtures

Both `origin-offset-{legal,hole}.rs` passed raw pointers to the reference-taking
`raw_eq` intrinsic. Replace each argument with `&*pointer.cast::<[MaybeUninit<u8>; 3]>()`.
The reference is to MaybeUninit storage, so forming it does not require its
payload bytes to be initialized. Source offset 1, destination offset 2, extent
3, both possible origins, both comparison operand orders, and the negative
payload hole remain unchanged. Neither expectation is changed.

## Move/return: STOP, retain the legal expectation

The supplied bounded excerpt `/root/kani3300-h1-ci/m3-r1-failures.log` shows the
negative root failing, then only the beginning of the legal root's output.
The existing full local log `/root/kani3300-h1-ci/m3-r1.log` contains the missing
legal-root result. Targeted inspection establishes:

| Root | Failed property | Result |
| --- | --- | --- |
| `move_return_source_hole` | Check 62, `std::mem::transmute_neo::<std::mem::MaybeUninit<u8>, u8>.safety_check.1` | 1/198 failed, 8 unreachable |
| `move_return_reinit_legal` | Check 82, same property ID | 1/200 failed, 6 unreachable |

Both failures describe `Undefined Behavior: Reading from an uninitialized pointer
of type u8` (the actual description puts backticks around `u8`). Both property
locations are `core/src/mem/mod.rs:1279:14` in `transmute_neo`, not the source
location of `read_source`. In the full log, the legal failed property is at
lines 4585-4588, and its summary/verdict at lines 5149-5155. The final summary
reports zero successful harnesses and two failures.

The negative root deliberately reads the source after the explicit custom-MIR
`Move(source)` into `relay`, without repairing it. That rejection is expected.
The legal root takes the repair edge, writes 23 through the saved source
pointer before reading it, and retains the initialized value 42 returned from
`relay`. It must succeed: replacing its expected SUCCESS with FAILURE, removing
either payload assertion, or bypassing the composed return would hide a real
false rejection. The fixture and its expectations are left intact.

The legal root's `read_source` pointer checks all succeed; both harness value
assertions also succeed. The failing property belongs to the shared conversion
helper used by multiple `assume_init` calls. No trace or generated model was
uploaded (`m3-art/` is empty). The property output alone therefore cannot identify
which dynamic conversion failed; attributing it specifically to
`read_source` line 26 would exceed the evidence.

Static inspection identifies a concrete shadow-transfer gap relevant to this
fixture: `handoff` returns `(MaybeUninit<u8>, u8)`, but
`CheckUninitVisitor::transfers_shadow` in
`kani-compiler/src/kani_middle/transform/check_uninit/ptr_uninit/uninit_visitor.rs`
recognizes only a top-level union or `maybe_uninit_storage`. The latter in
`ty_layout.rs` recognizes a slot or flat array/slice, not a tuple containing a
slot. Consequently this tuple return does not receive the paired return
`StoreArgument`/`LoadArgument` instrumentation, although its `.0` is assigned
from the initialized `returned` slot. This is a source-established omitted
transfer, and a candidate cause of the legal false rejection; the available
log does not prove dynamic causality. Compiler/model repair requires a separate
task. Stop here as requested, without changing the legal verdict.

## JSON composition: pre-binding gate, no runtime evidence

The 24 Python synthetic tests pass. The subsequent ordinary `test.sh` invocation
rejects at `run.py:312`, before Kani starts: all seven roots in `roots.json` are
`BINDING_PENDING`, with null expected inventories/failure metadata. This matches
the documented fail-closed behavior. It is not a Kani verdict or evidence that
the mixed-root fixture failed verification.

The documented coordinator capture command is
`./test.sh --collect-unbound --keep-output`; successful capture exits 2 with
`UNBOUND_CAPTURE`, never PASS. Complete isolated and combined inventories,
failure details/kinds and Unsupported inventories must be reviewed before
committing `REGRESSION_BOUND` entries and running ordinary qualification.
With no uploaded captures, fabricating those entries or accepting capture as
PASS would weaken the test. Runner, manifest, and expectations remain intact.

## Local validation and limits

- Python-only `test_compare.py`: 24 tests pass; fixture SHA matches the manifest.
- `git diff --check`: clean.
- No Cargo, Kani, build submission, push, or expectation blessing performed.
- Offset changes have not been compiled or verified; M3 remains blocked by the
  legal false rejection and pending JSON binding.
