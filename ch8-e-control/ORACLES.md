# E controls: fixture and oracle notes

These are isolated, single-harness diagnostic roots for the E prep stage. They are
source artifacts only; they have not been compiled or run. Cover labels are proposed
reachability oracles, not measured results. The Kani implementation
reference is pinned to U `0aac16ef62da9e9d5645782d458593e5d78143ba` as identified
in the stage design. Companion rows are intended for matched S/ON and S/OFF runs;
E-Q's ON refusal is expected from the pinned frontend guard, not a measured result.

## E-Q — quantified pointer gate and scalar alternative

`e_q_isolated_witness.rs` isolates the pointer dereference in an existential
predicate. `e_q_pointer_loop.rs` adds the exact bounded loop-contract shape with
explicit invariant, modifies, and decreases. The matched false mutant uses the
same pointer predicate with a value absent from `[1, 2]`; OFF must fail the
invariant base so a dropped or unconstrained predicate cannot masquerade as a
pass. The ON oracle for these three roots is the pinned diagnostic:

> quantifier predicates containing safety checks are not supported with -Z valid-value-checks or -Z uninit-checks

`e_q_scalar_invariant.rs` reads one pointer directly in an ordinary scalar loop
invariant and post-loop assertion. It has no quantified expression and checks
that the fallback form works with the ON safety checks active. Constant two-byte
storage is only a diagnostic witness, not an arbitrary-length property.

## E-S — uncapped storage generation

`e_s_unbounded_slice.rs` calls the alloc-enabled `kani::any_slice_mut_unbounded::<u8>()`
model directly. It imposes no length assumption or cap. It performs a direct raw
read from an arbitrary valid index and covers an interior zero-valued read and
`len > 32`; a return cover follows the read. It has no loop or frame, so this root
isolates storage generation and read validity. It does not prove the actual core
insertion routine or a generic-T validity/init summary.

## E-H — initialization shadow and aliases

Each H root is independent and uses a small raw slice frame over `MaybeUninit<u8>`
payload bytes. No fixture invokes `can_dereference`, sets initialization shadow
state, or supplies a modeled initialization summary.

- `e_h_live_after_havoc.rs` has the loop write live byte 0 inside the two-byte frame,
  then reads fixed initialized byte 1 through an alias created before the loop.
  ON success is the positive preservation control; the body and read-result covers
  witness the transition and the post-loop read.
- `e_h_hole_inside_alias.rs` writes byte 0 but leaves byte 1 unwritten inside the
  frame, then directly dereferences its pre-existing alias. The required ON outcome
  is an uninitialized-read safety check at that exact source line. OFF is `OBSERVE`,
  not evidence about initializedness.
- `e_h_outside_false_alias.rs` writes byte 0, checks an initialized sentinel alias
  outside the frame, then directly dereferences the unwritten byte just outside
  the frame. The ON uninitialized-read failure is the expected preservation of
  its false bit; OFF is `OBSERVE` only.
- `e_h_write_then_read.rs` and `e_h_copy_then_read.rs` exercise actual raw write
  and non-overlapping copy operations inside the loop body, each followed there
  by an immediate read. ON success checks that the operation makes the destination
  readable without relying on post-havoc initialization assumptions.

For H negatives, a failure only counts if it is the specified uninitialized-read
check. An assigns failure, compile failure, timeout, or unrelated assertion is not
the intended oracle. Cover reachability and all root outcomes remain unmeasured
until the separately authorized stage.
