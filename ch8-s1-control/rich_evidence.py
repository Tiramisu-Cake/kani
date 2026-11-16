"""Streaming decoder for stock 0aac regular property output; no acceptance rules.

Matches cbmc_property_renderer::format_result and SourceLocation::fmt. Results
are cross-checked against the SAME invocation's stock export, never counts alone.
"""
import codecs
import os
from pathlib import Path
import re

MAX_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024
CHECK_BUCKETS = ('failure', 'unreachable', 'undetermined', 'error', 'unknown', 'other')
COVER_BUCKETS = ('satisfied', 'unsatisfiable', 'unreachable', 'undetermined', 'error', 'unknown', 'other')


# Coordinator-authorized location-only exception. Exact same-row identities from
# S1-06; no source site is reconstructed and offline admission remains pending.
LOCATION_POLICY = 'S1-07_EXACT_STOCK_UNREACHABLE_LOCATION_ONLY_V1'
_SMALLSORT = 'slice::sort::shared::smallsort::'
_MODEL = _SMALLSORT + 'verify::sorting_model::'
_LOCATION_U8 = (_SMALLSORT + 'small_sort_general_with_scratch::<u8, ' +
                _MODEL + 'KeyLess<u8>>.unreachable.1')
_LOCATION_NONCOPY = (_SMALLSORT + 'small_sort_general_with_scratch::<' + _MODEL +
                     'NonCopyByte, ' + _MODEL + 'KeyLess<' + _MODEL +
                     'NonCopyByte>>.unreachable.1')
LOCATION_EXCEPTION_BINDINGS = {
    _SMALLSORT + 'verify::sorting_entry_smoke::' + family + '_n' + str(n): pid
    for family, pid in (('freeze_copy_u8', _LOCATION_U8),
                        ('freeze_default_noncopy', _LOCATION_NONCOPY),
                        ('stable_freeze_u8', _LOCATION_U8),
                        ('unstable_freeze_u8', _LOCATION_U8))
    for n in range(4)
}
LOCATION_EXCEPTION_BINDINGS[_SMALLSORT + 'verify::sorting_entry_controls::stable_freeze_activation'] = _LOCATION_U8



def location_exception(harness, p):
    pid = LOCATION_EXCEPTION_BINDINGS.get(harness)
    if pid is None:
        return False
    function = pid.removesuffix('.unreachable.1')
    return (p.get('id') == pid and p.get('display_id') == pid and
            p.get('class') == 'unreachable' and p.get('status') == 'SUCCESS' and
            p.get('description') == 'unreachable code' and
            p.get('file') is None and p.get('line') is None and
            p.get('location_display') == 'library/core/src/lib.rs:0:0 in function ' + function)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def bucket_ids(bucket, key):
    value = bucket.get(key)
    require(isinstance(value, list), 'missing/wrong bucket: ' + key)
    if key == 'other':
        require(all(isinstance(p, dict) and isinstance(p.get('id'), str)
                    and isinstance(p.get('status'), str) for p in value), 'other bucket shape')
        return [p['id'] for p in value]
    require(all(isinstance(p, str) and p for p in value), 'bucket ID type')
    return value


def validate_stock_inventory(h):
    checks, covers = h['checks'], h['covers']
    ids = []
    for bucket, names in ((checks, CHECK_BUCKETS), (covers, COVER_BUCKETS)):
        require(type(bucket.get('total')) is int and bucket['total'] >= 0, 'total')
        count = 0
        for key in names:
            items = bucket_ids(bucket, key); count += len(items); ids.extend(items)
        if bucket is checks:
            require(type(bucket.get('success')) is int and bucket['success'] >= 0, 'success count')
            count += bucket['success']
        require(count == bucket['total'], 'partition total')
    require(len(ids) == len(set(ids)), 'duplicate stock ID')
    require(type(h.get('n_properties')) is int and h['n_properties'] == checks['total'] + covers['total'], 'property total')
    named = h.get('failed_properties')
    require(isinstance(named, list) and all(isinstance(p, dict) for p in named), 'failed properties')
    require(type(h.get('n_failed')) is int and h['n_failed'] == len(checks['failure']) == len(named), 'failure total')
    require({p.get('id') for p in named} == set(checks['failure']), 'failed IDs')


class RegularEvidence:
    def __init__(self, selectors, cwd):
        self.selectors, self.cwd = selectors, Path(cwd)
        self.decoder = codecs.getincrementaldecoder('utf-8')('strict')
        self.buffer = ''; self.bytes = 0; self.current = None
        self.records = {}; self.in_results = False; self.block = []
        self.closed = set(); self.error = None; self.finished = False; self.complete = False
        self.missing_sites = []

    def feed(self, data):
        self.bytes += len(data)
        if self.error:
            return
        try:
            require(not self.finished and self.bytes <= MAX_BYTES, 'regular stream exceeds limit or already closed')
            self.buffer += self.decoder.decode(data)
            while '\n' in self.buffer:
                line, self.buffer = self.buffer.split('\n', 1)
                self._line(line)
            require(len(self.buffer.encode()) <= MAX_RECORD_BYTES, 'regular line exceeds limit')
        except (ValueError, UnicodeError) as exc:
            self.error = str(exc)

    def finish(self):
        if self.finished:
            return
        self.finished = True
        if self.error:
            return
        try:
            self.buffer += self.decoder.decode(b'', final=True)
            if self.buffer:
                self._line(self.buffer)
            require(not self.in_results and not self.block, 'partial regular RESULTS')
            require(set(self.records) == set(self.selectors) == self.closed, 'missing regular harness RESULTS')
        except (ValueError, UnicodeError) as exc:
            self.error = str(exc)

    def _line(self, line):
        if self.in_results:
            if line == 'SUMMARY:':
                self._record(); self.in_results = False; self.closed.add(self.current)
            elif line.startswith('Check '):
                self._record(); self.block = [line]
            elif self.block:
                self.block.append(line)
                require(sum(len(x.encode())+1 for x in self.block) <= MAX_RECORD_BYTES, 'property block exceeds limit')
            else:
                require(not line.strip(), 'unexpected RESULTS line')
            return
        marker = re.fullmatch(r'Checking harness (.+)\.\.\.', line)
        if marker:
            self.current = marker[1]
            require(self.current in self.selectors and self.current not in self.records, 'unexpected/duplicate harness marker')
            self.records[self.current] = []
        elif line == 'RESULTS:':
            require(self.current is not None and self.current not in self.closed, 'orphan/duplicate RESULTS')
            self.in_results = True

    def _record(self):
        if not self.block:
            return
        text = '\n'.join(self.block).rstrip('\n')
        self.block = []
        match = re.fullmatch(r'Check ([1-9][0-9]*): (.+)\n\t - Status: ([A-Z_]+)\n\t - Description: "([\s\S]*?)"(?:\n\t - Location: ([^\n]+))?', text)
        require(match is not None, 'missing/malformed description or location')
        ordinal, pid, status, desc, loc = match.groups()
        require(int(ordinal) == len(self.records[self.current])+1, 'property ordinal gap')
        require(bool(desc), 'missing description')
        cls = re.fullmatch(r'(?:.*\.)?(NaN|[a-z_-]+)\.([0-9]+)', pid)
        require(cls is not None, 'property class missing')
        site = (loc or '').split(' in function ', 1)[0]
        place = re.fullmatch(r'(.+?):([1-9][0-9]*)(?::([0-9]+))?', site)
        bound_site = place is not None and place[1] != 'Unknown file'
        if not bound_site:
            # Stock SourceLocation legitimately omits fields. Keep the property
            # and subsequent roots; never manufacture an admissible source site.
            self.missing_sites.append({'harness': self.current, 'display_id': pid,
                                       'location_display': loc, 'reason': 'file/line missing'})
        display_id = pid
        if cls[1] == 'missing_definition':
            pid = pid.rsplit('.missing_definition.', 1)[0] + '.' + cls[2]
        elif cls[1] == 'recursion' and cls[2] == '1':
            pid = pid[:-2]
            if pid == 'recursion': pid = '.recursion'
        file = os.path.normpath(str(self.cwd / place[1])) if bound_site else None
        self.records[self.current].append({'id': pid, 'class': cls[1], 'description': desc,
                                         'file': file, 'line': place[2] if bound_site else None, 'status': status,
                                         'location_display': loc, 'display_id': display_id})

    def validate(self, stock):
        self.complete = False
        require(self.finished and self.error is None, 'regular stream invalid: ' + str(self.error))
        require({h['name'] for h in stock['harnesses']} == set(self.records), 'regular/stock roots differ')
        for h in stock['harnesses']:
            validate_stock_inventory(h)
            records = self.records[h['name']]
            # Display maps UNKNOWN to UNDETERMINED. Restore only by exact same-row ID.
            unknown_ids = set(h['checks']['unknown'] + h['covers']['unknown'])
            for p in records:
                if p['id'] in unknown_ids:
                    require(p['status'] == 'UNDETERMINED' or
                            (p['status'] == 'UNKNOWN' and p.get('display_status') == 'UNDETERMINED'),
                            'UNKNOWN display mismatch')
                    p['display_status'] = 'UNDETERMINED'; p['status'] = 'UNKNOWN'
            byid = {p['id']: p for p in records}
            require(len(byid) == len(records) == h['n_properties'], 'regular inventory count/duplicate')
            for bucket, names, cover in ((h['checks'], CHECK_BUCKETS, False), (h['covers'], COVER_BUCKETS, True)):
                selected = [p for p in records if (p['class'] == 'cover') == cover]
                require(len(selected) == bucket['total'], 'regular class totals')
                if not cover:
                    require(sum(p['status'] == 'SUCCESS' for p in selected) == bucket['success'], 'regular SUCCESS count')
                known = {'SUCCESS'} if not cover else set()
                for key in names:
                    if key == 'other':
                        continue
                    known.add(key.upper())
                    require({p['id'] for p in selected if p['status'] == key.upper()} == set(bucket_ids(bucket, key)), 'regular bucket mismatch: ' + key)
                require({(p['id'], p['status']) for p in selected if p['status'] not in known} ==
                        {(p['id'], p['status']) for p in bucket['other']}, 'regular other statuses')
            for p in h['failed_properties'] + h['unsupported_constructs']:
                actual = byid.get(p['id'])
                require(actual is not None and all(actual[k] == p[k] for k in
                        ('id', 'class', 'description', 'file', 'line', 'status')), 'rich stock property mismatch')
        # Also inspect saved records: collector replay must not bypass this gate
        # merely because its decoder has no streaming missing_sites list.
        require(all(isinstance(p.get('file'), str) and p['file'] and
                    isinstance(p.get('line'), str) and re.fullmatch(r'[1-9][0-9]*', p['line'])
                    or location_exception(harness, p)
                    for harness, records in self.records.items() for p in records),
                'rich metadata incomplete: file/line missing')
        self.complete = True

    def location_exceptions(self):
        return [{'policy': LOCATION_POLICY, 'harness': name, 'property': dict(p),
                 'scope': 'LOCATION_ONLY', 'qualified_acceptance': 'PENDING_OFFLINE_ACCEPTANCE'}
                for name, records in self.records.items() for p in records
                if location_exception(name, p)]

    def document(self):
        return {'schema': 'ch8-s1-05-rich-v1', 'state': 'COMPLETE' if self.complete else 'INCOMPLETE',
                'error': self.error, 'observed_stdout_bytes': self.bytes,
                'missing_sites': self.missing_sites,
                'location_exceptions': self.location_exceptions(),
                'harnesses': [{'name': k, 'properties': v} for k, v in self.records.items()],
                'qualified_acceptance': 'PENDING_OFFLINE_ACCEPTANCE', 'proof_credit': 'NONE'}
