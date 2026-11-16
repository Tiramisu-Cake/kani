# Expected observations

The stock oracle accepts only the exact issue diagnostic, `Checking memory initialization of type [std::mem::MaybeUninit<D>; 2] is not supported. Cannot determine layout for a type that contains union of type std::mem::MaybeUninit<D> as a field.`, paired with a nonzero process exit. Any other error, compile failure, timeout, missing output, or export mismatch is `UNKNOWN`.

Prototype JSON exports must identify the exact pinned commit, completed run, exact harness selection, and exact source path. `SUCCESS` requires all checks successful, no failed or indeterminate checks, no unsupported constructs, and a zero process exit. `UNINIT_FAILURE` requires completed failed safety checks whose description is the uninitialized pointer read diagnostic and whose property IDs identify the selected harness. A failed process without that structured result is `UNKNOWN`.

`original-empty-drop` accepts a fully validated `SUCCESS` or `UNINIT_FAILURE` observation. The expected semantic target is recorded as `UNINIT_FAILURE`; a validated success means this empty Drop body did not expose the invalid drop. `read-in-drop` supplies the strict negative criterion. No observation establishes runtime proof credit.
