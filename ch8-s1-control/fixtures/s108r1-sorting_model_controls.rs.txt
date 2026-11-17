//! Opt-in model controls; register only with sorting AND controls cfgs.
//! These roots test the checker, not the six real SmallSort method contracts.

use super::sorting_model::{KeyLess, NonCopyByte, enabled, post, snapshot};
use crate::cell::Cell;
use crate::kani;
use crate::mem::{MaybeUninit, align_of, needs_drop, size_of};

fn byte(value: u8) -> u8 { value }

// Independent, tiny fixture constructor, not a replacement for actual sort proofs.
fn sorted_prefix(mut values: [u8; 3], len: usize) -> [u8; 3] {
    let mut i = 1;
    while i < len {
        let mut j = i;
        while j > 0 && values[j] < values[j - 1] {
            values.swap(j, j - 1);
            j -= 1;
        }
        i += 1;
    }
    values
}

macro_rules! positive {
    ($name:ident, $ty:ty, $new:path) => {
        #[kani::proof]
        #[kani::unwind(5)]
        fn $name() {
            let input: [u8; 3] = kani::any();
            let len: usize = kani::any();
            kani::assume(len <= 3);
            let values = [$new(input[0]), $new(input[1]), $new(input[2])];
            kani::assert(enabled::<$ty, KeyLess<$ty>>(), concat!(stringify!($name), "::model_enabled"));
            let before = snapshot::<$ty, KeyLess<$ty>>(&values[..len]);
            let mut ordered = true;
            let mut i = 1;
            while i < len {
                ordered = ordered && input[i - 1] <= input[i];
                i += 1;
            }
            kani::assert(post::<$ty, KeyLess<$ty>>(before, &values[..len]) == ordered, concat!(stringify!($name), "::identity_checker"));
            let sorted = sorted_prefix(input, len);
            let output = [$new(sorted[0]), $new(sorted[1]), $new(sorted[2])];
            kani::assert(post::<$ty, KeyLess<$ty>>(before, &output[..len]), concat!(stringify!($name), "::constructed_sorted_permutation"));
            let mut less = KeyLess::<$ty>::new();
            kani::assert(less(&values[0], &values[1]) == (input[0] < input[1]), concat!(stringify!($name), "::fnmut_two_projections"));
            kani::assert(FnOnce::call_once(KeyLess::<$ty>::new(), (&values[1], &values[0]))
                == (input[1] < input[0]), concat!(stringify!($name), "::fnonce_two_projections"));
            kani::assert(size_of::<$ty>() == 1 && align_of::<$ty>() == 1, concat!(stringify!($name), "::element_layout"));
            kani::assert(size_of::<KeyLess<$ty>>() == 0 && !needs_drop::<$ty>(), concat!(stringify!($name), "::comparator_zst_element_no_drop"));
            kani::cover(len == 0, "S1_model_N0_return");
            kani::cover(len == 1, "S1_model_N1_return");
            kani::cover(len == 2, "S1_model_N2_return");
            kani::cover(len == 3, "S1_model_N3_return");
            kani::cover(len == 3 && input[0] == input[1], "S1_duplicate_return");
            kani::cover(len == 3 && input[0] > input[1], "S1_unsorted_input_return");
        }
    };
}
positive!(model_u8_n0_3, u8, byte);
positive!(model_cell_n0_3, Cell<u8>, Cell::new);
positive!(model_noncopy_n0_3, NonCopyByte, NonCopyByte::new);

fn inactive<T, F>(values: &[T], _comparator: &F) {
    assert!(!enabled::<T, F>(), "S1_INACTIVE_PAIR");
    let invalid = snapshot::<T, F>(values);
    assert!(post::<T, F>(invalid, values), "S1_INACTIVE_GUARDED_NO_CLAIM");
    assert!(!post::<u8, KeyLess<u8>>(invalid, &[]), "S1_INACTIVE_TOKEN_INVALID");
}

#[kani::proof]
fn inactive_pairs_read_free() {
    let values: [u8; 2] = kani::any();
    inactive(&values, &|a: &u8, b: &u8| a > b);
    let mut touched = false;
    {
        let effectful = |a: &u8, b: &u8| { touched = true; a < b };
        inactive(&values, &effectful);
    }
    assert!(!touched, "S1_INACTIVE_NEVER_CALLS_COMPARATOR");
    // The reference is valid: MaybeUninit itself is initialized, its payload is not.
    // No invalid Rust reference or reference to an uninitialized u8 is constructed.
    let storage = [MaybeUninit::<u8>::uninit(); 2];
    inactive(&storage, &KeyLess::<MaybeUninit<u8>>::new());
    kani::cover(true, "S1_inactive_legal_storage_return");
}

fn require_active<T, F>(_values: &[T], _comparator: &F) {
    assert!(enabled::<T, F>(), "S1_ACTIVATION_UNSUPPORTED_PAIR");
}

#[kani::proof]
fn activation_descending_rejected() {
    require_active(&[0u8, 1], &|a: &u8, b: &u8| a > b);
}

#[kani::proof]
fn activation_effectful_rejected() {
    let mut touched = false;
    let effectful = |a: &u8, b: &u8| { touched = true; a < b };
    require_active(&[0u8, 1], &effectful);
}

#[kani::proof]
fn activation_unsupported_type_rejected() {
    let storage = [MaybeUninit::<u8>::uninit(); 2];
    require_active(&storage, &KeyLess::<MaybeUninit<u8>>::new());
}

fn strict_pair() -> [u8; 2] {
    let a: u8 = kani::any();
    let b: u8 = kani::any();
    kani::assume(a < b);
    [a, b]
}

#[kani::proof]
#[kani::unwind(4)]
fn corruption_companion() {
    let values = strict_pair();
    let before = snapshot::<u8, KeyLess<u8>>(&values);
    assert!(post::<u8, KeyLess<u8>>(before, &values), "S1_CORRUPTION_LEGAL_COMPANION");
    assert!(!post::<u8, KeyLess<u8>>(before, &[values[1], values[0]]),
        "S1_ORDER_REJECTED_WITH_COUNTS_PRESERVED");
    assert!(!post::<u8, KeyLess<u8>>(before, &[values[0], values[0]]),
        "S1_COUNTS_REJECTED_WITH_ORDER_PRESERVED");
    kani::cover(true, "S1_corruption_companion_return");
}

#[kani::proof]
#[kani::unwind(4)]
fn order_corruption_rejected() {
    let values = strict_pair();
    let before = snapshot::<u8, KeyLess<u8>>(&values);
    assert!(post::<u8, KeyLess<u8>>(before, &[values[1], values[0]]),
        "S1_ORDER_CORRUPTION_ACCEPTED");
}

#[kani::proof]
#[kani::unwind(4)]
fn count_corruption_rejected() {
    let values = strict_pair();
    let corrupt = [values[0], values[0]];
    assert!(corrupt[0] <= corrupt[1], "S1_COUNT_FIXTURE_STAYS_SORTED");
    let before = snapshot::<u8, KeyLess<u8>>(&values);
    assert!(post::<u8, KeyLess<u8>>(before, &corrupt),
        "S1_COUNT_CORRUPTION_ACCEPTED");
}

#[kani::proof]
#[kani::unwind(34)]
fn snapshot_guards_companion() {
    let invalid = snapshot::<u8, ()>(&[]);
    assert!(!post::<u8, KeyLess<u8>>(invalid, &[]), "S1_ACTIVE_INVALID_REJECTED");
    let full = [7u8; 32];
    let before = snapshot::<u8, KeyLess<u8>>(&full);
    assert!(post::<u8, KeyLess<u8>>(before, &full), "S1_CAP32_IDENTITY");
    assert!(!post::<u8, KeyLess<u8>>(before, &full[..31]), "S1_LENGTH_CHANGE_REJECTED");
    let overflow = [7u8; 33];
    let overflow_snapshot = snapshot::<u8, KeyLess<u8>>(&overflow);
    assert!(!post::<u8, KeyLess<u8>>(overflow_snapshot, &[]), "S1_OVERFLOW_TOKEN_INVALID");
    assert!(!post::<u8, KeyLess<u8>>(before, &overflow), "S1_OVERFLOW_OUTPUT_REJECTED");
    // Mutating Cell after snapshot must not mutate the owned pre-state.
    let cells = [Cell::new(1u8), Cell::new(2u8)];
    let cell_before = snapshot::<Cell<u8>, KeyLess<Cell<u8>>>(&cells);
    cells[1].set(1);
    assert!(!post::<Cell<u8>, KeyLess<Cell<u8>>>(cell_before, &cells),
        "S1_CELL_SNAPSHOT_OWNS_PRESTATE");
    kani::cover(true, "S1_snapshot_guard_companion_return");
}

#[kani::proof]
fn invalid_snapshot_rejected() {
    let invalid = snapshot::<u8, ()>(&[]);
    assert!(post::<u8, KeyLess<u8>>(invalid, &[]), "S1_ACTIVE_INVALID_TOKEN_ACCEPTED");
}
