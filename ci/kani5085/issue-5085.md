
Found by comparing the semantics described in [the Rust Reference](https://doc.rust-lang.org/reference/) with how Kani implements them. An AI agent found this bug, reproduced it with Kani 744b3e84d and drafted this report. A second agent tried to refute it and searched upstream for duplicates. The methodology is described [here](https://reports.robben.io/methodology/).

**What went wrong:** Crash (CBMC aborts, Kani reports `VERIFICATION:- FAILED` for a correct program).

**Version:** kani 0.68.0, CBMC 6.11.0, default flags. Also reproduces at upstream main 9461e07af7ec929f050aa4192f29363c9be07779.

**Preconditions:** none, default configuration, safe code.

### Input

`static_zst_arr.rs`:
```rust
#[cfg_attr(kani, kani::proof)]
fn check() { static S: ([[u8; 0]; 2], u8) = ([[], []], 5); let x = S; assert!(x.1 == 5); }
fn main() { check() }
```
`runtime_control.rs` builds the same value at run time (`black_box(([[], []], 5))`) and verifies.

### Command

```
./run.sh     # or: kani static_zst_arr.rs
```

### Output

```
--- begin invariant violation report ---
Invariant check failed
File: ../src/util/simplify_utils.cpp:345 function: bits2expr
Condition: el_size_opt.has_value() && *el_size_opt > 0
Reason: Check return value
Kani Rust Verifier 0.68.0 (standalone)
```
`./run.sh` prints `runtime_control: OK` and `static_zst_arr: CBMC invariant failure`. A `const` of the same type passed through `black_box` fails the same way.

### Expected

The program is UB-free and the assertion holds (it passes natively and under Miri). The Rust Reference (Type layout) says: "An array of `[T; N]` has a size of `size_of::<T>() * N` and the same alignment of `T`", so `[[u8; 0]; 2]` is a valid zero-sized type. Kani should report `VERIFICATION:- SUCCESSFUL`. Likely Kani should skip zero-sized components when it builds the constant initialiser, or CBMC's `bits2expr` should accept element size 0.

<details><summary>Reproducer files</summary>

`run.sh`

```bash
#!/usr/bin/env bash
# exit 0 = OK (both verify), 1 = bug present (CBMC invariant failure), 2 = tool not found / harness error
KANI=${KANI:-kani}
command -v "$KANI" >/dev/null 2>&1 || { echo "tool not found: $KANI"; exit 2; }
D=$(cd "$(dirname "$0")" && pwd); W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
bug=0
for f in runtime_control static_zst_arr; do
  cp "$D/$f.rs" "$W/"
  (cd "$W" && "$KANI" "$f.rs" > "$f.log" 2>&1)
  if grep -q '^VERIFICATION:- SUCCESSFUL' "$W/$f.log"; then echo "$f: OK"
  elif grep -q 'Invariant check failed' "$W/$f.log"; then echo "$f: CBMC invariant failure"; bug=1
  else echo "$f: unexpected"; tail -n 5 "$W/$f.log"; exit 2; fi
done
exit $bug
```

`runtime_control.rs`

```rust
#[cfg_attr(kani, kani::proof)]
fn check() { let x: ([[u8; 0]; 2], u8) = std::hint::black_box(([[], []], 5)); assert!(x.1 == 5); }
fn main() { check() }
```

`static_zst_arr.rs`

```rust
#[cfg_attr(kani, kani::proof)]
fn check() { static S: ([[u8; 0]; 2], u8) = ([[], []], 5); let x = S; assert!(x.1 == 5); }
fn main() { check() }
```

</details>

---

*If this is intended behaviour or a duplicate, feel free to close it, and I'll use that as feedback to improve future reports. For questions, or to have this re-checked on a newer version of Kani, mention @JeroenRobben or email jeroen@robben.io.*
