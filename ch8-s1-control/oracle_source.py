# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Offline source-coordinate preflight for the eight frozen S1-08 oracles.

Not imported by runner/collector/admission. Source-derived spans repair only
closure type coordinates. Existing assertion ordinals are never rediscovered
from failures; exact runtime matching in negative_oracle.py remains unchanged.
"""
import hashlib
import re

SOURCE_SHA = '99e8456d200fff1299ee5756279cddb23921dc65'
CLOSURE_COORD = re.compile(r'(?P<file>\{closure@[^{}]+?):(?P<sl>\d+):(?P<sc>\d+): (?P<el>\d+):(?P<ec>\d+)(?=\})')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def masked(source):
    # Preserve offsets/newlines, while preventing strings and comments from
    # supplying syntax for the small frozen-source lexical checks below.
    pattern = r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/'
    return re.sub(pattern, lambda m: ''.join('\n' if c=='\n' else ' ' for c in m[0]), source, flags=re.S)


def balanced_end(code, start, opening='(', closing=')'):
    assert code[start] == opening
    depth=0
    for i in range(start,len(code)):
        if code[i]==opening: depth+=1
        elif code[i]==closing:
            depth-=1
            if depth==0: return i+1
    raise AssertionError('unbalanced frozen source')


def function_body(source, name):
    code=masked(source)
    hits=list(re.finditer(r'(?m)^fn\s+'+re.escape(name)+r'\s*[<(]',code))
    assert len(hits)==1, 'missing/duplicate source function'
    lo=code.index('{',hits[0].end())
    hi=balanced_end(code,lo,'{','}')
    return lo,hi


def closure_span(source, root):
    lo,hi=function_body(source,root)
    # These two frozen closures have explicit, one-line argument declarations.
    # Accept no fallback shape and no ordinal/location guess on unknown syntax.
    hits=list(re.finditer(r'\|[^|\n]*\|',masked(source)[lo:hi]))
    assert len(hits)==1, 'expected one explicit closure argument span'
    start=lo+hits[0].start();end=lo+hits[0].end()
    line=source.count('\n',0,start)+1
    line_start=source.rfind('\n',0,start)+1
    line_end=source.find('\n',start)
    line_text=source[line_start:line_end if line_end>=0 else len(source)]
    assert line_text.isascii() and '\t' not in line_text, 'unsupported closure column encoding'
    assert '\n' not in source[start:end]
    return {'start_line':line,'start_column':start-line_start+1,
            'end_line':line,'end_column':end-line_start+1,
            'text':source[start:end]}


def span_text(span):
    return f"{span['start_line']}:{span['start_column']}: {span['end_line']}:{span['end_column']}"


def repair_id(property_id, source, root):
    hits=list(CLOSURE_COORD.finditer(property_id))
    if not hits: return property_id
    assert len(hits)==1, 'unknown multi-closure oracle shape'
    m=hits[0];span=closure_span(source,root)
    return property_id[:m.start('sl')]+span_text(span)+property_id[m.end('ec'):]


def assertion_at(source, line):
    lines=source.splitlines(keepends=True)
    assert type(line) is int and 1<=line<=len(lines)
    offset=sum(len(x) for x in lines[:line-1])
    code=masked(source)
    starts=list(re.finditer(r'assert!\s*\(',code[offset:offset+len(lines[line-1])]))
    if starts:
        assert len(starts)==1
        start=offset+starts[0].start();opening=code.index('(',start)
        end=balanced_end(code,opening)
        return source[start:end]+';'
    # Activation mutants are existing false ensures clauses, not Rust assert!.
    stripped=lines[line-1].strip()
    assert stripped.startswith('#[cfg_attr(') and 'kani::ensures(' in stripped
    return stripped


def validate(request, sources, baselines):
    """Check full declared IDs against independently pinned source bytes.

    sources maps (variant, repo-relative path) to exact bytes. The caller must
    obtain actual bytes from the pinned Git tree/overlay; tests use hash-checked
    copies of those same files. A coherent request/hash/ID shift cannot override
    the canonical source digests in the frozen baseline manifest.
    """
    assert request['std_sha']==baselines['std_sha']==SOURCE_SHA, 'wrong pinned source'
    assert request['std_tree']==baselines['std_tree'], 'wrong source tree'
    negatives=[r for r in request['rows'] if r.get('oracle') is not None]
    assert len(negatives)==8 and {r['id'] for r in negatives}==set(baselines['oracles']), 'negative inventory'
    checked=[]
    for row in negatives:
        b=baselines['oracles'][row['id']];o=row['oracle']
        assert row['expected']=='DETECTED' and o['class']=='assertion'
        assert {k:v for k,v in o.items() if k!='property_id'}==b['oracle_without_id'], 'logical oracle/context drift'
        assert row['variant']==b['variant'] and row['mode']==b['mode']
        assert row['selector']==o['selector']==b['oracle_without_id']['selector']
        key=(row['variant'],o['file']);data=sources[key]
        canonical=baselines['sources'][row['variant']][o['file']]
        assert sha(data)==o['source_sha256']==canonical, 'canonical source hash mismatch'
        effective=request['changed_file_sha256'] if row['variant']=='production' else {
            **request['changed_file_sha256'],**request['variants'][row['variant']]['changed_file_sha256']}
        assert effective[o['file']]==canonical, 'source-under-test mismatch'
        source=data.decode('utf-8');lines=source.splitlines();line=o['line']
        assert lines[line-1]==o['source_line'], 'assertion anchor'
        if 'assertion_context' in o:
            assert lines[line-1:line-1+len(o['assertion_context'])]==o['assertion_context'], 'assertion context'
        assert assertion_at(source,line)==b['assertion_text'], 'intended assertion expression/clause'
        template=b['property_id_template']
        if b['closure_root'] is not None:
            assert b['closure_root']==row['selector'].rsplit('::',1)[-1]
            span=closure_span(source,b['closure_root'])
            expected=template.replace('{source_closure_span}',span_text(span))
            match=list(CLOSURE_COORD.finditer(expected))
            assert len(match)==1 and match[0]['file']=='{closure@'+o['export_file']
        else:
            assert '{source_closure_span}' not in template
            expected=template;span=None
        assert o['property_id']==expected, 'stale/wrong full oracle ID'
        if 'proposal' in o:
            assert o['proposal']['property']['id']==expected
            assert o['status']=='FAILURE' and o['require_only_this_failure'] is True
        checked.append({'row_id':row['id'],'property_id':expected,'closure_span':span,
                        'source_sha256':canonical,'assertion_line':line,
                        'status':'SOURCE_DERIVED_EXPECTATION_NOT_OBSERVED','sole_failure':'EXACT_MATCHER_UNCHANGED'})
    return checked
