# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Source representation correspondence only; no compiler or native proof claim."""
from pathlib import Path
import hashlib
BASE='library/core/src/slice/sort/shared/smallsort/'
OLD=BASE+'verify/sorting_s4_network_partition.rs'
NEW=BASE+'verify/sorting_s4_network_r2.rs'
OLD_SHA='051e869d52f78f43ee8c1faaf5bad0a91c4e8d9ea21a1e8c1d83991a89e0f574'

def expected(old):
    assert hashlib.sha256(old.encode()).hexdigest()==OLD_SHA, 'old harness identity drift'
    text=old.replace('//! S4P2 exact network partitions:', '//! S4P2 r2 concrete-call network partitions:').replace('fn s4p2_network_', 'fn s4p2r2_network_').replace('"S4P2_N_', '"S4P2R2_N_')
    for n in (2,3,4):
        start=text.index(f'fn s4p2r2_network_b01_n{n:02}_fullbyte')
        end=text.index('\n}',start)
        body=text[start:end].replace(f'let n: usize = kani::any();\n    kani::assume({n} <= n && n <= {n});',f'let n: usize = {n};').replace('[1..1 + n]',f'[1..{n+1}]')
        text=text[:start]+body+text[end:]
    text=text.replace('let n: usize = kani::any();\n    kani::assume(0 <= n && n <= 1);','let one: bool = kani::any();\n    let n: usize = if one { 1 } else { 0 };')
    return text.replace('    small_sort_network(&mut v[1..1 + n], &mut KeyLess::<u8>::new());','    if one {\n        small_sort_network(&mut v[1..2], &mut KeyLess::<u8>::new());\n    } else {\n        small_sort_network(&mut v[1..1], &mut KeyLess::<u8>::new());\n    }')

def check_text(old,new):
    assert new==expected(old), 'network r2 representation/domain/role correspondence drift'
    return {'status':'STATIC_SOURCE_CORRESPONDENCE','singleton_lengths':[2,3,4],
            'N01_bool_union':[0,1],'all34_full_u8_unchanged':True,
            'shared_oracles_frame_canary_roles':True,'callee':'small_sort_network',
            'native_compile_MIR':'NOT_RUN','proof_credit':'NONE'}

def check(std):
    std=Path(std)
    return check_text((std/OLD).read_text(),(std/NEW).read_text())
