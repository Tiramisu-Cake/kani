# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Finite r3-to-r4 mapping and exact operation correspondence, offline only."""
import hashlib
from pathlib import Path
import cfg_pfc as c

HERE = Path(__file__).resolve().parent
SMALLSORT = c.BASE + 'slice/sort/shared/smallsort.rs'
BATCH = c.BASE + 'slice/sort/shared/smallsort/verify/sorting_s2_batch.rs'
R3 = '00abe964a5e2eac63f1f864455d6f9be1903422a0c5b28398360cf2039cc08d5'


def fn(text, name):
    entries = [i for i in c.items(text)[1] if c.kind(i, 'fn') is not None and i['head'][c.kind(i, 'fn')][0] == name]
    c.need(len(entries) == 1, 'correspondence: missing/ambiguous function ' + name)
    return entries[0]


def check(text, smallsort):
    old = (HERE/'fixtures/s2-r3-batch.rs.txt').read_text()
    c.need(hashlib.sha256(old.encode()).hexdigest() == R3, 'r3 fixture drift')
    # Every existing harness/model prefix is unchanged except exact declared routes.
    expected = old[:old.index('// Ordinary DIAGNOSTIC_ASSUMED relation')]
    expected = expected.replace('swap_if_less, sort8_stable, insert_tail};',
        'swap_if_less, sort8_stable, sort4_stable, insert_tail, CopyOnDrop, SMALL_SORT_GENERAL_SCRATCH_LEN};')
    expected = expected.replace('use crate::{kani, mem::MaybeUninit, ptr};',
        'use crate::{kani, mem::{self, MaybeUninit, size_of}, ptr, slice, intrinsics};\nuse crate::slice::sort::shared::FreezeMarker;')
    expected = expected.replace('#[kani::stub(sort8_stable,diagnostic_sort8)]','#[kani::stub_verified(sort8_stable)]')
    expected = expected.replace('#[kani::stub(swap_if_less,weak_swap)]','#[kani::stub(s2_swap_seam,weak_swap)]')
    expected = expected.replace('#[kani::stub(bidirectional_merge,weak_merge)]','#[kani::stub(s2_merge_seam,weak_merge)]')
    a = expected.index('fn sort13_weak()'); b = expected.index('fn general32_weak()')
    expected = expected[:a]+expected[a:b].replace('sort13_optimal(&mut v,','sort13_fault_network(&mut v,')+expected[b:].replace('small_sort_general(&mut v,','general_fault_copy(&mut v,',1)
    c.need(text.startswith(expected), 'r4 harness/domain/frame/oracle prefix drift')
    copies = [('sort13_optimal','sort13_fault_network', {'sort13_optimal':'sort13_fault_network','swap_if_less':'s2_swap_seam'}),
              ('small_sort_general','general_fault_copy', {'small_sort_general':'general_fault_copy','small_sort_general_with_scratch':'general_fault_scratch'}),
              ('small_sort_general_with_scratch','general_fault_scratch', {'small_sort_general_with_scratch':'general_fault_scratch','bidirectional_merge':'s2_merge_seam'})]
    receipts = []
    for original, copy, mapping in copies:
        a, b = fn(smallsort, original), fn(text, copy)
        for part in ('head','body'):
            translated = [(mapping.get(t,t),n) for t,n in a[part]]
            c.need(c.spelling(translated) == c.spelling(b[part]), 'operation correspondence drift: '+copy+':'+part)
        c.need(not b['attrs'], 'copy must be uncontracted: '+copy)
        receipts.append({'original': original, 'copy': copy, 'renames_only': mapping,
                         'original_line': a['line'], 'copy_line': b['line'],
                         'operation_tokens': 'EXACT_AFTER_RENAMES'})
    seams = {
      's2_swap_seam': 'unsafe fn s2_swap_seam<T,F:FnMut(&T,&T)->bool>(v:*mut T,a:usize,b:usize,f:&mut F) { unsafe { swap_if_less(v,a,b,f) }; }',
      's2_merge_seam': 'unsafe fn s2_merge_seam<T:crate::slice::sort::shared::FreezeMarker,F:FnMut(&T,&T)->bool>(v:&[T],dst:*mut T,f:&mut F) { unsafe { bidirectional_merge(v,dst,f) }; }'}
    for name, reference in seams.items():
        a, b = fn(text,name), fn(reference,name)
        c.need(not a['attrs'] and all(c.spelling(a[k]) == c.spelling(b[k]) for k in ('head','body')), 'uncontracted seam drift: '+name)
    registration = (HERE/'fixtures/s2-r1-batch.rs.txt').read_text().split("// Registration for Kani's stub_verified lookup",1)[1]
    reference = fn("// Registration for Kani's stub_verified lookup" + registration, 'sort8_registration_only'); actual = fn(text,'sort8_registration_only')
    c.need(all(c.spelling(actual[k]) == c.spelling(reference[k]) for k in ('head','body')) and
           [c.spelling(a) for a in actual['attrs']] == [c.spelling(a) for a in reference['attrs']], 'same-cfg sort8 registration drift')
    # No additional opaque model, assertion, contract or function may be appended.
    expected_names = {i['head'][c.kind(i,'fn')][0] for i in c.items(expected)[1] if c.kind(i,'fn') is not None}
    expected_names |= set(seams) | {x[1] for x in copies} | {'sort8_registration_only'}
    actual_items = c.items(text)[1]
    c.need(all(c.kind(i,'fn') is not None or c.kind(i,'use') is not None for i in actual_items), 'unexpected r4 item')
    names = [i['head'][c.kind(i,'fn')][0] for i in actual_items if c.kind(i,'fn') is not None]
    c.need(len(names) == len(expected_names) and set(names) == expected_names, 'r4 function inventory drift')
    return {'copies': receipts, 'sort8_relation': 'UNCHANGED_ORIGINAL_CONTRACT_FULL_VALUE_POST_AND_TWO_SPAN_MODIFIES',
            'registration': 'ACTIVE_SAME_CFG_ONLY_NOT_SELECTED_NOT_QUALIFIED',
            'negative_coverage_change': 'LOCAL_OPERATION_IDENTICAL_COPIES_INSTEAD_OF_ORIGINAL_CALLER_IDENTITIES',
            'native_execution': 'NOT_RUN', 'proof_credit': 'NONE'}
