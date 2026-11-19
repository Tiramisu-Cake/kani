# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Finite source correspondence to the unchanged network-r2 singleton template."""
from pathlib import Path
import hashlib
BASE='library/core/src/slice/sort/shared/smallsort/'
OLD=BASE+'verify/sorting_s4_network_r2.rs'
NEW=BASE+'verify/sorting_s4_full_lengths_next.rs'
OLD_SHA='25fcbfa26052727a47c9628e0c41f33c80a57f06971fa61efcc36f4af77d838c'
LENGTHS=(8,9,13,17)

def expected(old):
    assert hashlib.sha256(old.encode()).hexdigest()==OLD_SHA, 'network-r2 template drift'
    header=old[:old.index('#[kani::proof]')].replace('S4P2 r2 concrete-call network partitions','S4P3 concrete-call network boundaries')
    start=old.index('#[kani::proof]');end=old.index('\n#[kani::proof]',start+1)
    template=old[start:end]
    return header+''.join(template.replace('s4p2r2_','s4p3_')
        .replace('S4P2R2_N_02_',f'S4P3_N_{n:02}_')
        .replace('n02_fullbyte',f'n{n:02}_fullbyte')
        .replace('let n: usize = 2;',f'let n: usize = {n};')
        .replace('[1..3]',f'[1..{n+1}]').replace('n == 2',f'n == {n}')
        .replace('_N02"',f'_N{n:02}"') for n in LENGTHS)

def check_text(old,new):
    assert new==expected(old), 'S4P3 source/domain/oracle/frame/role correspondence drift'
    return {'status':'STATIC_SOURCE_CORRESPONDENCE','singleton_lengths':list(LENGTHS),
            'all34_full_u8_unchanged':True,'shared_oracles_frame_canary_roles':True,
            'callee':'small_sort_network','N17_final_merge':False,
            'native_compile_MIR':'NOT_RUN','lowered_unwind_sufficiency':'UNKNOWN',
            '600_second_fit':'UNKNOWN','proof_credit':'NONE'}

def check(std):
    std=Path(std)
    return check_text((std/OLD).read_text(),(std/NEW).read_text())
