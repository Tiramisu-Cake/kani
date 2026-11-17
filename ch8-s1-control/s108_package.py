# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Offline S1-08 package checks. Not imported by runner/collector/admission.

The label matcher is an interface fixture, not an acceptance classifier. Legacy
semantic sets still require the existing independent offline source/instance audit.
"""
import hashlib
import re

ROLE_SUFFIX = {
    'S1_ENTRY_MODEL_ENABLED': 'model_enabled',
    'S1_EXACT_TRAIT_THRESHOLD': 's1_exact_trait_threshold',
    'S1_ENTRY_TYPE_LAYOUT': 'type_layout',
    'S1_ENTRY_POST_INDEPENDENT_CALLER': 'post_independent_caller',
    'S1_LEFT_CANARY': 'left_canary', 'S1_RIGHT_CANARY': 'right_canary',
    'S1_N1_VALUE_UNCHANGED': 'n1_value_unchanged',
    'S1_N0_EMPTY_UNCHANGED': 'n0_empty_unchanged',
    'S1_MODEL_ENABLED': 'model_enabled', 'S1_IDENTITY_CHECKER': 'identity_checker',
    'S1_CONSTRUCTED_SORTED_PERMUTATION': 'constructed_sorted_permutation',
    'S1_FNMUT_TWO_PROJECTIONS': 'fnmut_two_projections',
    'S1_FNONCE_TWO_PROJECTIONS': 'fnonce_two_projections',
    'S1_ELEMENT_LAYOUT': 'element_layout',
    'S1_COMPARATOR_ZST_ELEMENT_NO_DROP': 'comparator_zst_element_no_drop',
}
PLACEHOLDER = "This is a placeholder message; Kani doesn't support message formatted at runtime"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tokens(source):
    # Bounded lexical comparison, not a Rust parser. Strings/comments remain
    # indivisible, so whitespace inside messages/comments cannot disappear.
    return re.findall(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/|\w+|[^\s]', source, re.S)


def region(source, macro):
    start = source.index('macro_rules! ' + macro + ' {')
    # In these frozen files each macro ends on its own column-zero brace.
    end = source.index('\n}', start) + 2
    return start, end


def labelled_sites(source, macro):
    lo, hi = region(source, macro)
    pattern = r'kani::assert\((.*?),\s*concat!\(stringify!\(\$name\), "::([a-z0-9_]+)"\)\);'
    out = {}
    for m in re.finditer(pattern, source[lo:hi], re.S):
        role = m[2]
        assert role not in out, 'duplicate role in macro'
        start, end = lo + m.start(), lo + m.end()
        out[role] = {'expression': m[1], 'line': source.count('\n', 0, start)+1,
                     'end_line': source.count('\n', 0, end)+1,
                     'text': source[start:end]}
    return out


def equivalent(base, candidate, macros):
    """Verify entire file tokens after exactly the permitted diagnostic rewrite.

    This retains assertion operands/order, branches, assumptions, types, covers,
    invocation geometry, and all negative/helper functions outside the macros.
    """
    expected = base
    counts = {}
    for macro, count in macros.items():
        lo, hi = region(expected, macro)
        def rewrite(m):
            role = ROLE_SUFFIX[m[2]]  # unknown original diagnostics fail closed
            return 'kani::assert(' + m[1] + ', concat!(stringify!($name), "::' + role + '"));'
        body, found = re.subn(r'assert!\((.*?),\s*"(S1_[A-Z0-9_]+)"\);', rewrite,
                              expected[lo:hi], flags=re.S)
        assert found == count, (macro, found, count)
        expected = expected[:lo] + body + expected[hi:]
        counts[macro] = found
    assert tokens(expected) == tokens(candidate), 'non-diagnostic source change'
    return counts


def validate_map(manifest, request):
    assert manifest['std_sha'] == request['std_sha']
    assert manifest['std_tree'] == request['std_tree']
    entries = manifest['required_success_bindings']
    expected = [(r['id'], msg) for r in request['rows'] for msg in r['required_success_messages']]
    assert [(e['row_id'], e['expected_message']) for e in entries] == expected
    assert len(entries) == 127 and len(set(expected)) == 127
    labelled = [e for e in entries if e['binding_kind'] == 'EXACT_ROLE_LABEL']
    assert len(labelled) == 111 and len({e['row_id'] for e in labelled}) == 21
    assert len({e['expected_message'] for e in labelled}) == 111
    assert len([e for e in entries if e['binding_kind'].startswith('EXACT_SUCCESS_SEMANTIC')]) == 16
    byid = {r['id']: r for r in request['rows']}
    for e in entries:
        row = byid[e['row_id']]
        assert e['selector'] == row['selector'] and e['root'] == row['selector'].rsplit('::', 1)[-1]
        assert e['source']['sha256'] == request['changed_file_sha256'][e['source']['file']]
        assert e['applicability'] == {'N': row.get('N'), 'predicate': 'true_for_this_row'}
        assert e['observed_s108_property_ids'] is None and e['observed_s108_status'] == 'NOT_RUN'
        assert e['source']['sites']
        if e['binding_kind'] == 'EXACT_ROLE_LABEL':
            assert e['expected_description'] == e['expected_message'] == e['root'] + '::' + e['role']
            assert e['cardinality'] == 'EXACTLY_ONE_ID_SUCCESS' and e['source']['macro']
        else:
            assert e['expected_description'] == PLACEHOLDER
            assert e['expected_message'] == e['legacy_s107']['message']
            assert e['binding_kind'] == e['legacy_s107']['binding']
            assert e['cardinality'] == ('COMPLETE_SOURCE_INSTANCE_SET' if e['binding_kind'].endswith('_SET')
                                        else 'EXACT_SOURCE_SEMANTIC_BINDING')
    # Extra conditional assertions are retained but never required at a different N.
    for e in manifest['supplemental_label_sites']:
        row = byid[e['row_id']]
        assert e['required_in_127'] is False
        if e['role'] in ('n0_empty_unchanged', 'n1_value_unchanged'):
            n = 0 if e['role'].startswith('n0') else 1
            assert e['applies'] == (row.get('N') == n or row.get('N') == 'symbolic0..3')
            assert e['guard'] == f'n == {n}'
    return {'required': 127, 'new_labels': 111, 'preserved_semantic_bindings': 16}


def label_fixture(entry, envelope, manifest, request_sha256):
    """Fail-closed synthetic contract for a future exact-label observation.

    The producer IDs are opaque: never derive an assertion ordinal. This result
    alone gives no proof credit and does not close other admission gates.
    """
    unknown = {'binding': 'UNKNOWN', 'proof_credit': 'NONE'}
    if entry.get('binding_kind') != 'EXACT_ROLE_LABEL' or not isinstance(envelope, dict):
        return unknown
    if (envelope.get('std_sha') != manifest['std_sha'] or
        envelope.get('std_tree') != manifest['std_tree'] or
        envelope.get('tool_sha') != manifest['tool_sha'] or
        envelope.get('row_id') != entry['row_id'] or
        envelope.get('request_sha256') != request_sha256 or
        envelope.get('source_sha256') != entry['source']['sha256'] or
        envelope.get('selector') != entry['selector'] or
        envelope.get('state') != 'COMPLETE' or not isinstance(envelope.get('properties'), list)):
        return unknown
    props = envelope['properties']
    if any(not isinstance(p, dict) for p in props):
        return unknown
    hits = [p for p in props if p.get('description') == entry['expected_description']]
    if len(hits) != 1:
        return unknown
    p = hits[0]
    if (p.get('class') != 'assertion' or p.get('status') != 'SUCCESS' or
        not isinstance(p.get('id'), str) or not p['id'].startswith(entry['selector'] + '.') or
        sum(q.get('id') == p['id'] for q in props) != 1 or
        p.get('file') != entry['source']['file'] or type(p.get('line')) is not int or
        p['line'] not in entry['source']['allowed_property_lines']):
        return unknown
    return {'binding': 'EXACT_LABEL_INTERFACE_MATCH', 'property_id': p['id'], 'proof_credit': 'NONE'}
