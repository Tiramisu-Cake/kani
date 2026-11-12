#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Narrow bounded program-only text grammar, never an IREP/converter profiler."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
import time
from capture import MIB, digest, save

LINE_LIMIT = 65536
NODE_LIMIT = 200000
RECORD_LIMIT = 100000
SELECT = re.compile(r'transfer|store_argument|load_argument|begin|return0|initialize|reset|Layout|ARGUMENT_BUFFER|assigns|__CPROVER|postcondition|ASSERT|Assert', re.I)
OPS = re.compile(r'byte_extract\w*|byte_update\w*|pointer_object|pointer_offset|object_size|\bwith\b|\[[^\]\n]{1,128}\]')


def bounded_lines(path, byte_limit=8*MIB):
    with open(path, 'rb') as f:
        offset = 0
        record = 0
        while offset < byte_limit:
            raw = f.readline(min(LINE_LIMIT+1, byte_limit-offset))
            if not raw:
                return
            record += 1
            yield record, offset, raw, len(raw)>LINE_LIMIT or not raw.endswith(b'\n')
            offset += len(raw)


def program(path, model_hash, upstream_complete):
    began = time.monotonic()
    counts = Counter()
    ops = Counter()
    roots = Counter()
    excerpts = []
    pc, function, location = None, None, None
    saw_header = False
    gaps = set(['exact widths/types/backing extent/payload/pointer/shadow: UNKNOWN',
                'DAG sharing, converter cache and workload: UNKNOWN',
                'source owner/DFCC target/write/property binding: UNKNOWN',
                'nonprinted SSA categories and full guard/auxiliary coverage: UNKNOWN'])
    nodes = records = 0
    parser_complete = True
    for record, offset, raw, broken in bounded_lines(path):
        records = record
        if record>RECORD_LIMIT or nodes>NODE_LIMIT or time.monotonic()-began>5:
            parser_complete = False
            gaps.add('parser time/node/record budget')
            break
        if broken:
            parser_complete = False
            gaps.add('long/partial line; no inferred record')
            continue
        text = raw.decode('utf-8', 'replace').rstrip('\n')
        if 'Program constraints:' == text.strip():
            saw_header = True
            continue
        if not saw_header:
            continue
        m = re.match(r'^// (\d+) (.*)$', text)
        if m:
            pc, location = int(m[1]), m[2]
            fn = re.search(r'\bfunction (.+?)(?: thread |$)', location)
            function = fn[1] if fn else None
            continue
        m = re.match(r'^\((sliced|\d+)\) (.*)$', text)
        if not m:
            if text.lstrip().startswith('guard:'):
                counts['visible_guard_lines'] += 1
            elif text.strip():
                counts['unparsed_lines'] += 1
                # Only exact structural framing is recognized. Never silently
                # discard an unknown program record while claiming COMPLETE.
                if text.strip() not in (']', '}', ',', '],', '},'):
                    parser_complete = False
                    gaps.add('unclassified program content')
            continue
        mark, term = m.groups()
        category = next((x for x in ['ASSERT','ASSUME','CONSTRAINT','SHARED_READ','SHARED_WRITE']
                         if term.startswith(x+'(')), 'assignment_or_UNKNOWN')
        counts['visible_all'] += 1
        counts['visible_ignored' if mark=='sliced' else 'visible_retained'] += 1
        counts[category] += 1
        if nodes+len(term)>NODE_LIMIT:
            parser_complete=False
            gaps.add('parser character-work budget')
            break
        tokens = OPS.findall(term)
        nodes += len(term)  # conservative character-work budget, not expression nodes
        for op in tokens:
            if op.startswith('['):
                counts['constant_index_text' if re.fullmatch(r'\[\d+\]', op) else 'symbolic_or_UNKNOWN_index_text'] += 1
                ops['index_text'] += 1
            else:
                ops[op] += 1
        # Only simple flat operands are classified; nested/cast syntax is UNKNOWN.
        offsets=re.findall(r'byte_(?:extract|update)\w*\([^,()\n]{1,128},\s*([^,()\n]{1,128})[,)]',term)
        for offset in offsets:
            offset=offset.strip()
            category=('constant_offset_text' if re.fullmatch(r'-?\d+',offset) else
                      'symbolic_offset_text' if re.fullmatch(r'[A-Za-z_][\w#!.$:]*',offset) else
                      'UNKNOWN_offset_text')
            counts[category] += 1
        counts['UNKNOWN_offset_text'] += max(0,sum(op.startswith(('byte_extract','byte_update')) for op in tokens)-len(offsets))
        normalized = re.sub(r'\s+', ' ', term).strip()
        fingerprint = hashlib.sha256(normalized.encode()).hexdigest()
        roots[fingerprint] += 1
        if len(excerpts)<30 and (tokens or SELECT.search(term)):
            excerpt = raw[:1024]
            excerpts.append(dict(record=record, byte_offset=offset, byte_length=len(raw),
                pc=pc, function=function, source_location=location, model_sha256=model_hash,
                excerpt=excerpt.decode('utf-8','replace'), excerpt_sha256=hashlib.sha256(excerpt).hexdigest(),
                textual_fingerprint=fingerprint, exact_width_bits=None, width_assurance='UNKNOWN',
                ignore=mark=='sliced', operators=tokens[:30]))
    if not saw_header:
        parser_complete = False
        gaps.add('program-only grammar header not found')
    return dict(grammar='CBMC 6.11 show_program: // PC location; (number|sliced) expression; optional guard',
        normalization='whitespace only; preserve SSA suffixes and constants; SHA256 UTF-8',
        counts=dict(counts), visible_operators=dict(ops), parsed_line_records=records,
        top30_textual_roots_by_occurrences=roots.most_common(30),
        top30_roots_by_exact_width='UNKNOWN', excerpts=excerpts,
        parser_complete=parser_complete, stream_complete=upstream_complete,
        semantic_verdict_complete=False, coverage='visible printed subset; not converter workload',
        denominator='printed program-only records only, includes sliced; no VCC prefixes counted',
        complete=parser_complete and upstream_complete, gaps=sorted(gaps), offender='NOT_ESTABLISHED')


def failures(path, upstream_complete, semantic_run=False, limit=2*MIB):
    """Bounded JSON leaf traversal; preserve known failures on malformed JSON.

    Streaming structural scan of complete JSON property objects; enclosing partial
    JSON does not discard known records. No semantic outcome is inferred.
    """
    parsed, found = 0, []
    size = Path(path).stat().st_size
    if size>8*MIB:
        return dict(status='UNKNOWN', complete=False, records_parsed=0, failures=[], reason='input cap')
    data = Path(path).read_bytes()
    valid = False
    try:
        # Full syntax check is bounded by input and depth precheck below.
        depth = 0
        in_string = escaped = False
        for byte in data:
            if escaped:
                escaped=False
            elif byte==92 and in_string:
                escaped=True
            elif byte==34:
                in_string=not in_string
            elif not in_string and byte in (91,123):
                depth += 1
                if depth>64:
                    raise ValueError('depth budget')
            elif not in_string and byte in (93,125):
                depth -= 1
        value = json.loads(data)
        valid = isinstance(value, (list,dict))
    except (ValueError, RecursionError, UnicodeError):
        pass
    # One structural scan, accepting only complete object records. A property
    # can start with any key; nested sourceLocation is retained verbatim.
    text = data.decode('utf-8','replace')
    stack=[]
    in_string=escaped=False
    began=time.monotonic()
    inspected=0
    inventory_bytes=0
    cap_hit=False
    for position, char in enumerate(text):
        if position % 65536 == 0 and time.monotonic()-began>5:
            valid=False
            break
        if escaped:
            escaped=False
        elif in_string and char=='\\':
            escaped=True
        elif char=='"':
            in_string=not in_string
        elif not in_string and char=='{':
            stack.append(position)
            if len(stack)>64:
                valid=False
                break
        elif not in_string and char=='}' and stack:
            start=stack.pop()
            inspected += 1
            if inspected>100000:
                valid=False
                break
            chunk=text[start:position+1]
            if len(chunk)>2*MIB:
                valid=False
                continue
            if '"property"' not in chunk or '"status"' not in chunk:
                continue
            try:
                item=json.loads(chunk)
            except (ValueError, RecursionError):
                valid=False
                continue
            if not isinstance(item,dict) or 'property' not in item or 'status' not in item:
                continue
            parsed += 1
            if item['status']=='FAILURE':
                pid=item['property']
                entry=dict(id=pid, status='FAILURE', description=item.get('description'),
                    location=item.get('sourceLocation'),
                    property_class=pid.rsplit('.',2)[-2] if isinstance(pid,str) and '.' in pid else None)
                size=len(json.dumps(entry).encode())+2
                if inventory_bytes+size>limit-2048:
                    valid=False
                    cap_hit=True
                    break
                inventory_bytes += size
                found.append(entry)
    return dict(status='NOT_RUN' if not semantic_run else 'OBSERVED', failures=found,
                failure_records_observed=len(found), total_failed_properties=None,
                records_parsed=parsed, complete=False,
                stream_complete=bool(valid and upstream_complete), semantic_verdict_complete=False,
                limit_bytes=limit, cap_hit=cap_hit, objects_examined=inspected, semantic_completeness='UNKNOWN')


def projection(path, out, model_hash):
    """Selected bounded text, with original coordinates; types stay verbatim."""
    records=[]
    examined=0
    began=time.monotonic()
    incomplete=False
    for record, offset, raw, broken in bounded_lines(path):
        examined=record
        if record>100000 or time.monotonic()-began>5:
            incomplete=True
            break
        if broken:
            incomplete=True
            continue
        line=raw.decode('utf-8','replace')
        if SELECT.search(line):
            if len(records)>=200:
                incomplete=True
                break
            excerpt=raw[:2048]
            records.append(dict(record=record, byte_offset=offset, bytes=len(raw),
                model_sha256=model_hash, excerpt=excerpt.decode('utf-8','replace'),
                excerpt_sha256=hashlib.sha256(excerpt).hexdigest()))
    save(out, dict(records=records, examined=examined, complete=False,
        selection_incomplete=incomplete, coverage='selected matching lines only; surrounding type/CFG binding UNKNOWN',
        layout_N=None, element=None, extent_bytes=None, width_bits=None,
        associated_type_callsite=None, cell_address_extent=None, pointer_value_pointee=None,
        symbol_target_write_guard_pc_property_binding='UNKNOWN'))
