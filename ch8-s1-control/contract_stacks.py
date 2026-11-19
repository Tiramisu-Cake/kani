# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Pinned S2 source annotation audit. Does not expand macros or establish MIR credit."""
import hashlib
import re
import shlex
from pathlib import Path

import cfg_pfc as c

SMALLSORT = c.BASE + 'slice/sort/shared/smallsort.rs'
FROZEN_SHA = '603762bb0cabb64e82114501b8da686f6e7d941f8e2227eebb956bc7062e7fe0'
GUARD = 'all(kani, kani_smallsort_sorting, kani_smallsort_s2_assumed)'
ACTIVE = {'kani', 'kani_smallsort_sorting', 'kani_smallsort_s2_assumed'}
OPS = {'requires', 'modifies', 'ensures'}
HERE = Path(__file__).resolve().parent


def digest(data):
    return hashlib.sha256(data).hexdigest()


def frozen():
    data = (HERE / 'fixtures/s2-r2-smallsort.rs.txt').read_bytes()
    c.need(digest(data) == FROZEN_SHA, 'r2 annotation baseline identity drift')
    return data.decode()


def normalize(text):
    """Finite source rewrite, applied only to the SHA-pinned r2 fixture."""
    pattern = r'#\[safety::requires\((?:[^\n]*\)\]|.*?\n\)\])'

    def clause(m):
        pred = m.group()[len('#[safety::requires('):-2]
        return ('#[cfg_attr(' + GUARD + ', crate::kani::requires(' + pred + '))]\n'
                '#[cfg_attr(not(' + GUARD + '), safety::requires(' + pred + '))]')

    result, count = re.subn(pattern, clause, text, flags=re.S)
    c.need(count == 12, 'expected all twelve original safety clauses')
    return result


def contracts(attrs):
    result = []
    for ts in attrs:
        words = [t for t, _ in ts]
        if '(' not in words:
            continue
        pos = words.index('(')
        path = c.spelling(ts[:pos])
        op = words[pos - 1]
        if op not in OPS:
            continue
        c.need(path in {p + '::' + op for p in ('safety', 'crate::kani', 'kani')},
               'unknown contract macro path: ' + path)
        pred, end = c.group(ts, pos)
        c.need(end == len(ts), 'contract trailing syntax')
        result.append({'path': path, 'op': op, 'line': ts[0][1],
                       'predicate_tokens': c.spelling(pred),
                       'family': 'safety_wrapper' if path.startswith('safety::') else 'direct_kani'})
    return result


def declarations(text, active, parent=()):
    """Inspect impl methods and inline modules too; function bodies remain opaque."""
    inner, items = c.items(text)
    enabled, _ = c.attributes(inner, active)
    if not enabled:
        return
    for item in items:
        enabled, attrs = c.attributes(item['attrs'], active)
        if not enabled:
            continue
        pos = c.kind(item, 'fn')
        if pos is not None:
            yield parent + (item['head'][pos][0],), item, attrs
        elif c.kind(item, 'mod') is not None and item['delimiter'] == '{':
            name = item['head'][c.kind(item, 'mod')][0]
            # Token-based recursion preserves original line coordinates.
            yield from token_declarations(item['body'], active, parent + (name,))
        elif item['head'] and item['head'][0][0] == 'impl':
            label = '<' + c.spelling(item['head']) + '>'
            yield from token_declarations(item['body'], active, parent + (label,))


def token_declarations(ts, active, parent):
    # Reconstruct whitespace with the original line offsets; literals are tokens,
    # so comments/attribute-looking strings are never reinterpreted as syntax.
    chunks, line = [], 1
    for value, at in ts:
        chunks.append('\n' * max(0, at - line) + value + ' ')
        line = at + value.count('\n')
    yield from declarations(''.join(chunks), active, parent)


def check(std, request):
    std = Path(std)
    baseline = frozen()
    actual = (std / SMALLSORT).read_text()
    c.need(actual == normalize(baseline),
           'S2 contract stack differs from exact r2-preserving normalization')
    # Compare effective full declarations/contracts in all feature combinations.
    # This includes non-Kani/runtime, S1, and malformed partial S2 opt-ins.
    projections = []
    keys = sorted(ACTIVE)
    for mask in range(8):
        active = {key for i, key in enumerate(keys) if mask & (1 << i)}
        old = list(declarations(baseline, active))
        new = list(declarations(actual, active))
        c.need(len(old) == len(new), 'function availability changed')
        for (a, ai, aa), (b, bi, ba) in zip(old, new):
            c.need(a == b and c.spelling(ai['head']) == c.spelling(bi['head'])
                   and c.spelling(ai['body']) == c.spelling(bi['body']),
                   'signature/body changed: ' + str(a))
            ac, bc = contracts(aa), contracts(ba)
            semantic = lambda cs: [(x['op'], x['predicate_tokens']) for x in cs]
            c.need(semantic(ac) == semantic(bc), 'premise/frame/post drift: ' + str(a))
            if not ACTIVE <= active:
                c.need([c.spelling(x) for x in aa] == [c.spelling(x) for x in ba],
                       'outside-S2 effective annotations changed: ' + str(a))
        projections.append({'effective_cfg': sorted(active), 'functions': len(new),
                            'semantics': 'EXACT_TOKEN_MATCH',
                            'outside_s2_attrs': 'EXACT_TOKEN_MATCH' if not ACTIVE <= active else 'NORMALIZED'})

    flags = shlex.split(request['flags']['RUSTFLAGS'])
    c.need(all(x.startswith('--cfg=') for x in flags), 'unsupported S2 cfg flags')
    active = {'kani'} | {x[6:] for x in flags}
    c.need(ACTIVE <= active and len(request['rows']) == 11, 'missing S2 contexts')
    hashes, functions, stacks, modules = {}, [], [], []

    def walk(rel, module):
        path = std / rel
        c.need(path.is_file(), 'missing active module ' + rel)
        text = path.read_text()
        hashes[rel] = digest(path.read_bytes())
        modules.append({'module': '::'.join(module), 'file': rel})
        for name, item, attrs in declarations(text, active):
            fullname = '::'.join(module + name)
            cs = contracts(attrs)
            record = {'function': fullname, 'file': rel, 'line': item['line'],
                      'source_sha256': hashes[rel], 'effective_attrs': [c.spelling(a) for a in attrs],
                      'signature_sha256': digest(c.spelling(item['head']).encode()),
                      'body_sha256': digest(c.spelling(item['body']).encode()),
                      'selected': fullname in {r['source_qualified_selector'] for r in request['rows']}}
            functions.append(record)
            if cs:
                c.need(all(x['family'] == 'direct_kani' for x in cs),
                       'active mixed/wrapper contract stack: ' + fullname)
                basename = name[-1]
                stacks.append({**record, 'contracts_expansion_order': cs,
                               'expected_single_marker_group': {
                                   key: '__kani_' + purpose + '_' + basename for key, purpose in
                                   [('recursion_check', 'recursion_check'), ('checked_with', 'check'),
                                    ('replaced_with', 'replace'), ('asserted_with', 'assert'),
                                    ('modifies_wrapper', 'modifies')]},
                               'closure_creation_and_MIR_lookup': 'EXPECTED_NOT_EXECUTED'})
        _, children = c.items(text)
        for item in children:
            pos = c.kind(item, 'mod')
            if pos is None or item['delimiter'] != ';' or not c.attributes(item['attrs'], active)[0]:
                continue
            name = item['head'][pos][0]
            parent = path.parent if path.name == 'mod.rs' else path.with_suffix('')
            candidates = [parent / (name + '.rs'), parent / name / 'mod.rs']
            matches = [p for p in candidates if p.is_file()]
            c.need(len(matches) == 1, 'missing/ambiguous active module ' + name)
            walk(str(matches[0].relative_to(std)), module + (name,))

    walk(SMALLSORT, c.SM)
    c.need(hashes == request['contract_stack_source_sha256'], 'active contract-slice source bindings drift')
    names = {x['function'].split('::')[-1]: x for x in stacks}
    for name, count in [('swap_if_less', 5), ('insert_tail', 2), ('sort8_stable', 1),
                        ('bidirectional_merge', 5), ('insertion_sort_shift_left', 1), ('sort4_stable', 1)]:
        c.need(name in names and sum(x['op'] == 'requires' for x in names[name]['contracts_expansion_order']) == count,
               'missing/incomplete active contract ' + name)
    return {'schema': 'ch8-s2-contract-stacks-r3-v1', 'source_sha': request['std_sha'],
            'source_tree': request['std_tree'], 'source_files_sha256': hashes,
            'contexts': [{'row': r['id'], 'effective_cfg': sorted(active),
                          'scope': 'ALL_ACTIVE_ITEMS_INCLUDING_UNSELECTED',
                          'stack_functions': [s['function'] for s in stacks]} for r in request['rows']],
            'modules': modules, 'functions': functions, 'contract_stacks': stacks,
            'cfg_projection_invariance': projections, 'status': 'STATIC_PASS',
            'compilation': 'NOT_RUN', 'causal_fix': 'UNVERIFIED_SOURCE_SUPPORTED_CANDIDATE',
            'proof_credit': 'NONE'}
