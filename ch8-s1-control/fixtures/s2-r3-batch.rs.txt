//! Three cost probes. Assumed consumers are DIAGNOSTIC_ASSUMED, never proof credit.
use super::super::{bidirectional_merge, sort13_optimal, small_sort_general,
    swap_if_less, sort8_stable, insert_tail};
use super::sorting_model::{KeyLess, snapshot, post, enabled};
use super::{sorting_s2_span as span, sorting_s2_swap as pair};
use crate::{kani, mem::MaybeUninit, ptr};

fn ordered(v: &[u8]) -> bool {
    let mut i = 1;
    while i < v.len() { if v[i] < v[i-1] { return false; } i += 1; }
    true
}
fn merge() -> ([u8;32],[u8;32]) {
    let src: [u8;32] = kani::any();
    kani::assume(ordered(&src[..16]) && ordered(&src[16..]));
    let original = src;
    let mut dst = [MaybeUninit::<u8>::uninit();34];
    dst[0].write(0xa5); dst[33].write(0x5a);
    unsafe { bidirectional_merge(&src,dst.as_mut_ptr().add(1).cast(),&mut KeyLess::<u8>::new()) };
    let mut out = [0u8;32];
    for i in 0..32 { out[i] = unsafe { dst[i+1].assume_init() }; }
    assert!(src == original, "S2_MERGE_SOURCE_FRAME");
    assert!(unsafe { dst[0].assume_init() == 0xa5 && dst[33].assume_init() == 0x5a }, "S2_MERGE_CANARIES");
    (src,out)
}
#[kani::proof]
#[kani::unwind(34)]
fn merge32_real() {
    assert!(enabled::<u8,KeyLess<u8>>() && span::active::<u8,KeyLess<u8>>() && pair::enabled::<u8,KeyLess<u8>>(), "S2_ACTIVE_MERGE32_REAL");
    let (src,out) = merge();
    assert!(post::<u8,KeyLess<u8>>(snapshot::<u8,KeyLess<u8>>(&src),&out), "S2_MERGE32_SORTED_FULL_COUNT");
    kani::cover(src[0] > src[16], "S2_MERGE_RIGHT_FIRST");
    kani::cover(src[0] < src[16], "S2_MERGE_LEFT_FIRST");
    kani::cover(src[15] == src[16], "S2_MERGE_TIE");
    kani::cover(out[0] < out[31], "S2_MERGE_NONCONSTANT");
    kani::cover(true, "S2_MERGE_USEFUL_RETURN");
}
#[kani::proof]
#[kani::stub_verified(swap_if_less)]
#[kani::unwind(34)]
fn sort13_assumed() {
    assert!(enabled::<u8,KeyLess<u8>>() && span::active::<u8,KeyLess<u8>>() && pair::enabled::<u8,KeyLess<u8>>(), "S2_ACTIVE_SORT13_ASSUMED");
    let mut v: [u8;15] = kani::any();
    let before = v;
    sort13_optimal(&mut v[1..14],&mut KeyLess::<u8>::new());
    assert!(post::<u8,KeyLess<u8>>(snapshot::<u8,KeyLess<u8>>(&before[1..14]),&v[1..14]), "S2_SORT13_SORTED_FULL_COUNT");
    assert!(v[0] == before[0] && v[14] == before[14], "S2_SORT13_CANARIES");
    kani::cover(before[1] > before[13], "S2_SORT13_UNSORTED");
    kani::cover(before[1] == before[13], "S2_SORT13_DUPLICATE");
    kani::cover(v[1] < v[13], "S2_SORT13_NONCONSTANT");
    kani::cover(true, "S2_SORT13_USEFUL_RETURN");
}
#[kani::proof]
#[kani::stub(sort8_stable,diagnostic_sort8)]
#[kani::stub_verified(insert_tail)]
#[kani::stub_verified(bidirectional_merge)]
#[kani::unwind(34)]
fn general32_assumed() {
    assert!(enabled::<u8,KeyLess<u8>>() && span::active::<u8,KeyLess<u8>>() && pair::enabled::<u8,KeyLess<u8>>(), "S2_ACTIVE_GENERAL32_ASSUMED");
    let mut v: [u8;34] = kani::any();
    let before = v;
    small_sort_general(&mut v[1..33],&mut KeyLess::<u8>::new());
    assert!(post::<u8,KeyLess<u8>>(snapshot::<u8,KeyLess<u8>>(&before[1..33]),&v[1..33]), "S2_GENERAL32_SORTED_FULL_COUNT");
    assert!(v[0] == before[0] && v[33] == before[33], "S2_GENERAL32_CANARIES");
    kani::cover(before[1] > before[32], "S2_GENERAL32_UNSORTED");
    kani::cover(before[1] == before[32], "S2_GENERAL32_DUPLICATE");
    kani::cover(v[1] < v[32], "S2_GENERAL32_NONCONSTANT");
    kani::cover(true, "S2_GENERAL32_USEFUL_RETURN");
}
// Same candidate, actual swap; qualification remains NOT_RUN until exact evidence.
#[kani::proof_for_contract(swap_if_less)]
#[kani::unwind(34)]
fn swap_pfc() {
    assert!(enabled::<u8,KeyLess<u8>>() && span::active::<u8,KeyLess<u8>>() && pair::enabled::<u8,KeyLess<u8>>(), "S2_ACTIVE_SWAP_PFC");
    let mut v: [u8;15] = kani::any();
    let before = v;
    let a: usize = kani::any(); let b: usize = kani::any();
    kani::assume(a < 13 && b < 13);
    let pre = pair::capture::<u8,KeyLess<u8>>(v[1..].as_ptr(),a,b);
    unsafe { swap_if_less(v.as_mut_ptr().add(1),a,b,&mut KeyLess::<u8>::new()) };
    assert!(pair::post::<u8,KeyLess<u8>>(pre,v[1..].as_ptr(),a,b), "S2_SWAP_EXACT_TRANSFER");
    for i in 0..15 { assert!(i == a+1 || i == b+1 || v[i] == before[i], "S2_SWAP_FULL_FRAME"); }
    kani::cover(a == b, "S2_SWAP_EQUAL");
    kani::cover(a == 0 && b == 12 && before[13] < before[1], "S2_SWAP_TAKEN");
    kani::cover(a == 12 && b == 0 && before[13] <= before[1], "S2_SWAP_REVERSE");
    kani::cover(true, "S2_SWAP_USEFUL_RETURN");
}
// Constructive witness over each summary length, with no assumed sorting oracle.
// This sorts only a ghost fixture; all actual runtime bodies remain unchanged.
fn witness(input: &[u8]) {
    let mut output = [0u8;32];
    output[..input.len()].copy_from_slice(input);
    for i in 1..input.len() {
        let mut j = i;
        while j > 0 && output[j] < output[j-1] { output.swap(j,j-1); j -= 1; }
    }
    assert!(span::post::<u8,KeyLess<u8>>(span::capture::<u8,KeyLess<u8>>(input.as_ptr(),input.len()),output.as_ptr(),input.len()), "S2_SUMMARY_WITNESS_FULL_COUNT");
}
#[kani::proof]
#[kani::unwind(34)]
fn summary_witness() {
    assert!(enabled::<u8,KeyLess<u8>>() && span::active::<u8,KeyLess<u8>>() && pair::enabled::<u8,KeyLess<u8>>(), "S2_ACTIVE_SUMMARY_WITNESS");
    let input: [u8;32] = kani::any();
    // sort8; each insert-tail p8..15; final merge32. This witness is stronger
    // than the corresponding sorted-prefix/halves premises and shares full values.
    for n in 8..17 { witness(&input[..n]); }
    witness(&input);
    let pairpre = pair::capture::<u8,KeyLess<u8>>(input.as_ptr(),0,1);
    let outpair = if input[1] < input[0] { [input[1],input[0]] } else { [input[0],input[1]] };
    assert!(pair::post::<u8,KeyLess<u8>>(pairpre,outpair.as_ptr(),0,1), "S2_PAIR_WITNESS");
    kani::cover(input[0] > input[31], "S2_WITNESS_UNSORTED");
    kani::cover(input[0] != input[31], "S2_WITNESS_NONCONSTANT");
    kani::cover(true, "S2_WITNESS_USEFUL_RETURN");
}
#[kani::proof]
#[kani::unwind(34)]
fn merge_order_corrupt() {
    let (src,mut out) = merge();
    kani::assume(out[0] < out[31]); out.swap(0,31);
    assert!(post::<u8,KeyLess<u8>>(snapshot::<u8,KeyLess<u8>>(&src),&out), "S2_NEG_MERGE_ORDER");
}
#[kani::proof]
#[kani::unwind(34)]
fn merge_count_corrupt() {
    let (src,mut out) = merge();
    kani::assume(src == [1u8;32]); out[31] = 2;
    assert!(post::<u8,KeyLess<u8>>(snapshot::<u8,KeyLess<u8>>(&src),&out), "S2_NEG_MERGE_COUNT");
}
#[kani::proof]
#[kani::unwind(34)]
fn checker_count_corrupt() {
    let input = [1u8;32]; let mut out = input; out[31] = 2;
    assert!(post::<u8,KeyLess<u8>>(snapshot::<u8,KeyLess<u8>>(&input),&out), "S2_NEG_CHECKER_COUNT");
}
#[kani::proof]
#[kani::unwind(34)]
fn checker_order_corrupt() {
    let input = [1u8,2]; let out = [2u8,1];
    assert!(post::<u8,KeyLess<u8>>(snapshot::<u8,KeyLess<u8>>(&input),&out), "S2_NEG_CHECKER_ORDER");
}
unsafe fn weak_swap<T,F:FnMut(&T,&T)->bool>(_v:*mut T,_a:usize,_b:usize,_f:&mut F) {}
#[kani::proof]
#[kani::stub(swap_if_less,weak_swap)]
#[kani::unwind(34)]
fn sort13_weak() {
    let mut v = [12u8,11,10,9,8,7,6,5,4,3,2,1,0]; let before = v;
    sort13_optimal(&mut v,&mut KeyLess::<u8>::new());
    assert!(post::<u8,KeyLess<u8>>(snapshot::<u8,KeyLess<u8>>(&before),&v), "S2_NEG_SORT13_WEAK");
}
// Copy is safety/frame-compatible, but contains no sorting guarantee.
unsafe fn weak_merge<T:crate::slice::sort::shared::FreezeMarker,F:FnMut(&T,&T)->bool>(v:&[T],dst:*mut T,_f:&mut F) {
    unsafe { ptr::copy_nonoverlapping(v.as_ptr(),dst,v.len()) };
}
#[kani::proof]
#[kani::stub(sort8_stable,diagnostic_sort8)]
#[kani::stub_verified(insert_tail)]
#[kani::stub(bidirectional_merge,weak_merge)]
#[kani::unwind(34)]
fn general32_weak() {
    let mut v = [2u8;32]; for i in 16..32 { v[i] = 1; } let before = v;
    small_sort_general(&mut v,&mut KeyLess::<u8>::new());
    assert!(post::<u8,KeyLess<u8>>(snapshot::<u8,KeyLess<u8>>(&before),&v), "S2_NEG_GENERAL32_WEAK");
}

// Ordinary DIAGNOSTIC_ASSUMED relation, restricted to u8/KeyLess<u8>.
// Same signature as the actual callee; no Copy bound or comparator invocation.
// Read only initialized source8. Havoc only dst8/temp8, then constrain the full
// sorted permutation of the owned pre-state. Never read uninitialized outputs.
unsafe fn diagnostic_sort8<T:crate::slice::sort::shared::FreezeMarker,F:FnMut(&T,&T)->bool>(
    v_base:*mut T,dst:*mut T,scratch_base:*mut T,_is_less:&mut F,
) {
    assert!(span::active::<T,F>());
    assert!(crate::ub_checks::can_dereference(ptr::slice_from_raw_parts(v_base,8))
        && crate::ub_checks::can_write(ptr::slice_from_raw_parts_mut(dst,8))
        && crate::ub_checks::can_write(ptr::slice_from_raw_parts_mut(scratch_base,8))
        && super::super::merge_contract_regions_disjoint(v_base,dst,8)
        && super::super::merge_contract_regions_disjoint(v_base,scratch_base,8)
        && super::super::merge_contract_regions_disjoint(dst,scratch_base,8));
    // active is true exactly for u8/KeyLess<u8>; these casts never admit another T.
    let before = span::capture::<T,F>(v_base,8);
    for i in 0..8 {
        unsafe {
            dst.cast::<u8>().add(i).write(kani::any::<u8>());
            scratch_base.cast::<u8>().add(i).write(kani::any::<u8>());
        }
    }
    kani::assume(span::post::<T,F>(before,dst,8));
}
