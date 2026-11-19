# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Bounded rustc text retention, independent of log previews and proof parsing.

Offsets are zero-based, half-open bytes in the original individual pipe. Text
has ANSI control sequences removed; it is not an exact byte reconstruction.
Completeness concerns observed textual diagnostics, never un-emitted producer data.
"""
import json
from pathlib import Path
import re

ANSI = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\))")
ERROR = re.compile(rb"^\s*error(?:\[[^]\r\n]+\])?:")
CONTEXT = re.compile(rb"^(?:[ \t]|[0-9]+[ \t]*[|+-]|note:|help:|--> |::: )")
COUNT = re.compile(rb"(?:aborting due to |Found )(\d+)(?: previous)? compilation errors?|aborting due to (\d+) previous errors?")
OMITTED = re.compile(rb"(?:errors?|diagnostics?) (?:were )?(?:omitted|suppressed)", re.I)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, ensure_ascii=False, separators=(',', ':'))+'\n')
    temporary.replace(path)


class Capture:
    def __init__(self, stream, cap, path):
        self.stream, self.cap, self.path = stream, cap, Path(path)
        self.pending = bytearray()
        self.line_bytes = self.offset = self.observed = self.kept = 0
        self.blocks = []
        self.active = None
        self.in_block = False
        self.headers = self.substantive_headers = self.dropped_blocks = 0
        self.dropped_bytes = self.unscanned_bytes = 0
        # Metadata must also stay bounded, even for a stream of empty headers.
        self.block_cap = max(1, cap // 512)
        self.reported_count = 0
        self.producer_omitted = False
        self.eof = False
        self.reason = 'IN_PROGRESS'
        self.persist()

    def feed(self, data):
        self.observed += len(data)
        # Split only on LF: CR and ANSI are original source bytes, not offsets.
        parts = data.split(b'\n')
        for i, part in enumerate(parts):
            segment = part + (b'\n' if i < len(parts)-1 else b'')
            room = max(0, self.cap-len(self.pending))
            self.pending.extend(segment[:room])
            self.line_bytes += len(segment)
            if i < len(parts)-1:
                self._line(bytes(self.pending), self.line_bytes)
                self.pending.clear()
                self.line_bytes = 0
        self.persist()

    def _close(self, complete=True):
        if self.active is not None:
            self.active['complete'] = complete and self.active['dropped_bytes'] == 0
        self.active = None
        self.in_block = False

    def _line(self, raw, size):
        clean = ANSI.sub(b'', raw)
        start, end = self.offset, self.offset + size
        self.offset = end
        self.unscanned_bytes += size-len(raw)
        for match in COUNT.finditer(clean):
            self.reported_count = max(self.reported_count, int(next(x for x in match.groups() if x)))
        self.producer_omitted |= bool(OMITTED.search(clean))
        header = bool(ERROR.match(clean))
        if header:
            self._close()
            self.headers += 1
            self.in_block = True
            if not re.match(rb'^\s*error: aborting due to ', clean):
                self.substantive_headers += 1
            if len(self.blocks) < self.block_cap and self.kept < self.cap:
                self.active = {'stream': self.stream, 'start_byte': start, 'end_byte': end,
                               'text': '', 'complete': False, 'dropped_bytes': 0}
                self.blocks.append(self.active)
            else:
                self.dropped_blocks += 1
        elif clean.strip() and not CONTEXT.match(clean):
            self._close()
        if self.active is not None:
            room = max(0, self.cap-self.kept)
            kept = raw[:room]
            self.kept += len(kept)
            dropped = size-len(kept)
            self.dropped_bytes += dropped
            self.active['dropped_bytes'] += dropped
            self.active['end_byte'] = end
            self.active['text'] += ANSI.sub(b'', kept).decode('utf-8', errors='replace')
        elif self.in_block:
            self.dropped_bytes += size

    def finish(self, reason=None, eof=True):
        if self.line_bytes:
            self._line(bytes(self.pending), self.line_bytes)
            self.pending.clear()
            self.line_bytes = 0
        self._close(complete=eof and reason in (None, 'AWAITING_EXECUTION_FINALIZATION'))
        if reason not in (None, 'AWAITING_EXECUTION_FINALIZATION') and self.blocks:
            self.blocks[-1]['complete'] = False
        self.reason, self.eof = reason, eof
        self.persist()

    def document(self):
        reasons = [self.reason] if self.reason else []
        if not self.eof and 'IN_PROGRESS' not in reasons:
            reasons.append('PIPE_EOF_NOT_ESTABLISHED')
        if self.dropped_blocks or self.dropped_bytes:
            reasons.append('DIAGNOSTIC_RETENTION_CAP')
        if self.unscanned_bytes:
            reasons.append('LINE_SCAN_CAP')
        if self.producer_omitted:
            reasons.append('PRODUCER_REPORTED_OMISSION')
        value = {'schema': 'ch8-rustc-diagnostics-v1', 'stream': self.stream,
                 'scope': 'OBSERVED_TEXTUAL_RUSTC_ERRORS_NOT_PER_ROOT',
                 'offset_unit': 'ORIGINAL_PIPE_BYTE_HALF_OPEN', 'ansi_removed': True,
                 'complete': not reasons, 'incomplete_reasons': reasons,
                 'status': 'INCOMPLETE' if reasons else 'ERROR_BLOCKS_RETAINED' if self.headers else 'NO_TEXTUAL_ERRORS',
                 'producer_completeness': 'UNKNOWN_UNEMITTED_DIAGNOSTICS_NOT_OBSERVABLE',
                 'producer_reported_error_count': self.reported_count,
                 'producer_reported_omission': self.producer_omitted,
                 'observed_bytes': self.observed, 'pipe_eof': self.eof,
                 'retention_cap_bytes': self.cap, 'block_cap': self.block_cap,
                 'retained_input_bytes': self.kept, 'error_headers_observed': self.headers,
                 'substantive_headers_observed': self.substantive_headers,
                 'dropped_blocks': self.dropped_blocks, 'dropped_bytes': self.dropped_bytes,
                 'unscanned_bytes': self.unscanned_bytes,
                 'unobserved_bytes': None if reasons else 0,
                 'dropped_counts_scope': 'OBSERVED_BYTES_ONLY; UNOBSERVED_COUNTS_UNKNOWN',
                 'blocks': self.blocks, 'proof_credit': 'NONE'}
        # The live snapshot also preserves a split/unterminated header or context
        # already received when the parent is SIGKILLed before pipe finalization.
        if self.pending and (self.in_block or ERROR.match(ANSI.sub(b'', self.pending))):
            value['pending_context'] = {'start_byte': self.offset,
                                       'observed_bytes': self.line_bytes,
                                       'text': ANSI.sub(b'', self.pending).decode('utf-8', errors='replace'),
                                       'complete': False}
        return value

    def persist(self):
        write(self.path, self.document())


def unavailable(reason):
    return {'schema': 'ch8-rustc-diagnostics-summary-v1', 'complete': False,
            'incomplete_reasons': [reason], 'unobserved_bytes': None,
            'proof_credit': 'NONE', 'streams': {}}


def summary(root):
    value = unavailable('DIAGNOSTIC_RECEIPTS_MISSING')
    reasons, streams = [], {}
    for stream in ('stdout', 'stderr'):
        path = Path(root) / ('rustc-'+stream+'-receipt.json')
        try:
            if path.is_symlink() or path.stat().st_size > 32*1024*1024:
                raise ValueError('diagnostic receipt resource/type boundary')
            doc = json.loads(path.read_text())
            if (not isinstance(doc, dict) or doc.get('schema') != 'ch8-rustc-diagnostics-v1'
                    or doc.get('stream') != stream or type(doc.get('complete')) is not bool
                    or not isinstance(doc.get('incomplete_reasons'), list)
                    or not all(isinstance(x, str) for x in doc['incomplete_reasons'])
                    or not isinstance(doc.get('blocks'), list)
                    or type(doc.get('pipe_eof')) is not bool
                    or any(type(doc.get(k)) is not int or doc[k] < 0 for k in
                           ('producer_reported_error_count', 'substantive_headers_observed',
                            'dropped_blocks', 'dropped_bytes', 'unscanned_bytes'))):
                raise ValueError('invalid diagnostic receipt')
            if doc['complete'] and (doc['incomplete_reasons'] or not doc.get('pipe_eof')
                    or doc.get('dropped_blocks') or doc.get('dropped_bytes') or doc.get('unscanned_bytes')
                    or doc.get('producer_reported_omission') or doc.get('pending_context')
                    or any(not isinstance(b, dict) or b.get('complete') is not True for b in doc['blocks'])):
                raise ValueError('contradictory diagnostic completeness')
            brief = {k: v for k, v in doc.items() if k not in ('blocks', 'pending_context')}
            brief['receipt'] = path.name
            streams[stream] = brief
            reasons.extend(doc['incomplete_reasons'])
            if not doc['complete'] and not doc['incomplete_reasons']:
                reasons.append(stream+':DIAGNOSTIC_RECEIPT_INCOMPLETE')
        except (OSError, ValueError, KeyError, TypeError):
            reasons.append(stream+':DIAGNOSTIC_RECEIPT_UNAVAILABLE')
    if streams:
        reported = max(s.get('producer_reported_error_count', 0) for s in streams.values())
        observed = sum(s.get('substantive_headers_observed', 0) for s in streams.values())
        if reported > observed:
            reasons.append('PRODUCER_ERROR_COUNT_EXCEEDS_OBSERVED_HEADERS')
    value.update(complete=not reasons, incomplete_reasons=sorted(set(reasons)), streams=streams,
                 unobserved_bytes=None if reasons else 0,
                 scope='OBSERVED_TEXTUAL_RUSTC_ERRORS; PRODUCER_COMPLETENESS_UNKNOWN')
    return value
