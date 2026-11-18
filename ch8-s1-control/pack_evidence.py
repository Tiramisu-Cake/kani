"""One deterministic compact structured artifact per job. Never reads raw logs."""
import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
import rustc_diagnostics

UNCOMPRESSED_CAP = 32 * 1024 * 1024
COMPRESSED_CAP = 8 * 1024 * 1024
NAME = 'group-evidence.json.gz'


def diagnostic_inventory(root):
    """Expected group coverage survives missing streams and fallback interruption.

    Row/compile receipts refer to a shared group capture, not a new execution.
    Only existing structured receipt inventories are consulted; no dispatch or
    proof/selection inference is performed.
    """
    directories = {p.parent: False for stream in ('stdout', 'stderr')
                   for p in root.rglob('rustc-'+stream+'-receipt.json')}
    reasons = []

    def read_receipt(path):
        if path.is_symlink() or path.stat().st_size > UNCOMPRESSED_CAP:
            raise ValueError('execution receipt boundary')
        value = json.loads(path.read_text())
        if not isinstance(value, dict):
            raise ValueError('execution receipt type')
        return value

    def expect_group(group):
        if not isinstance(group, str) or not group or group in ('.', '..') or '/' in group or '\\' in group:
            reasons.append('INVALID_EXPECTED_DIAGNOSTIC_GROUP')
        else:
            directories[root/'groups'/group] = True

    for directory in (root/'groups').glob('*'):
        if directory.is_dir() and not directory.is_symlink():
            directories[directory] = True
    for path in root.rglob('receipt.json'):
        relative = path.relative_to(root)
        try:
            value = read_receipt(path)
        except (OSError, ValueError, TypeError):
            reasons.append(str(relative)+':EXECUTION_INVENTORY_UNAVAILABLE')
            continue
        if 'selected_groups' in value:
            if not isinstance(value['selected_groups'], list):
                reasons.append(str(relative)+':INVALID_SELECTED_GROUPS')
            else:
                for group in value['selected_groups']:
                    expect_group(group)
        # Pending terminal envelopes can precede selected_groups; rows retain
        # the group assignment. Explicitly unselected rows create no obligation.
        if isinstance(value.get('rows'), list):
            for row in value['rows']:
                if isinstance(row, dict) and row.get('group') and row.get('status') != 'NOT_SELECTED':
                    expect_group(row['group'])
        is_row = 'status' in value and 'group' in value
        is_compile = len(relative.parts) >= 2 and relative.parts[-2] == 'compile'
        is_terminal = path.parent == root and ('rows' in value or 'selected_groups' in value)
        if not is_row and not is_compile and not is_terminal and any(
                k in value for k in ('execution', 'original_exit_code', 'rustc_diagnostics')):
            directories[path.parent] = True

    diagnostics = {}
    for directory, expected in sorted(directories.items()):
        summary = rustc_diagnostics.summary(directory)
        summary['expected_execution'] = expected
        path = directory/'receipt.json'
        if expected or path.exists():
            try:
                receipt = read_receipt(path)
                state = receipt.get('state', receipt.get('status', 'STATE_NOT_REPORTED'))
                summary['execution_state'] = state
                if state in ('NOT_RUN', 'NOT_RUN_OR_INTERRUPTED', 'IN_PROGRESS', 'INTERRUPTED'):
                    summary['incomplete_reasons'].append('EXECUTION_STATE:'+state)
                recorded = receipt.get('rustc_diagnostics')
                if isinstance(recorded, dict) and recorded.get('complete') is False:
                    summary['incomplete_reasons'].append('EXECUTION_DIAGNOSTICS_INCOMPLETE')
            except (OSError, ValueError, TypeError):
                summary['execution_state'] = 'RECEIPT_UNAVAILABLE'
                summary['incomplete_reasons'].append('EXECUTION_RECEIPT_UNAVAILABLE')
        summary['incomplete_reasons'] = sorted(set(summary['incomplete_reasons']))
        summary['complete'] = not summary['incomplete_reasons']
        if not summary['complete']:
            summary['unobserved_bytes'] = None
        diagnostics[str(directory.relative_to(root))] = summary
    return diagnostics, reasons


def pack(root):
    files = {}
    total = 0
    errors = []
    try:
        for path in sorted(root.rglob('*.json'), key=lambda p: (0 if p.name=='receipt.json' else 1 if p.name.startswith('rustc-') else 2, str(p))):
            if path.is_symlink():
                raise ValueError('symlink structured evidence')
            size = path.stat().st_size
            total += size
            if total > UNCOMPRESSED_CAP:
                raise ValueError('structured input cap')
            data = path.read_bytes()
            try:
                json.loads(data)
            except (ValueError, UnicodeError) as exc:
                # Preserve the exact partial text and continue to receipts/rich
                # inventory. The artifact remains INCOMPLETE and unqualified.
                errors.append(str(path.relative_to(root)) + ': ' + str(exc))
            try:
                text=data.decode('utf-8');encoding='utf-8'
            except UnicodeError:
                text=base64.b64encode(data).decode('ascii');encoding='base64'
            files[str(path.relative_to(root))] = {'sha256': hashlib.sha256(data).hexdigest(),
                                               'bytes': len(data), 'text': text, 'encoding':encoding}
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    error = '; '.join(errors) if errors else None
    diagnostics, coverage_reasons = diagnostic_inventory(root)
    doc = {'rustc_diagnostics': diagnostics, 'schema': 'ch8-s1-05-artifact-v1', 'state': 'INCOMPLETE' if error else 'PACKAGED',
           'error': error, 'files': files, 'proof_credit': 'NONE'}
    raw = json.dumps(doc, ensure_ascii=False, separators=(',', ':')).encode()
    compressed = gzip.compress(raw, mtime=0)
    if len(raw) > UNCOMPRESSED_CAP or len(compressed) > COMPRESSED_CAP:
        error = 'compact artifact cap'
        # Preserve identities/exits/snapshots in the small receipts when inventory cannot fit.
        kept = {k: v for k, v in files.items() if k.endswith('receipt.json')
                and (v['bytes'] <= 65536 or Path(k).name.startswith('rustc-'))}
        doc.update(state='INCOMPLETE', error=error, files=kept)
        raw = json.dumps(doc, ensure_ascii=False, separators=(',', ':')).encode()
        compressed = gzip.compress(raw, mtime=0)
    if len(raw) > UNCOMPRESSED_CAP or len(compressed) > COMPRESSED_CAP:
        # Retention itself can exceed the compact cap. Preserve coordinates and
        # counters, explicitly report omitted payload instead of silently losing it.
        for name, item in list(doc['files'].items()):
            if not Path(name).name.startswith('rustc-'):
                continue
            try:
                value = json.loads(item['text'])
                if not isinstance(value, dict) or not isinstance(value.get('blocks'), list):
                    raise ValueError('diagnostic shape')
                if not isinstance(value.get('incomplete_reasons'), list):
                    raise ValueError('diagnostic reasons')
                if any(not isinstance(b, dict) or not isinstance(b.get('text'), str) for b in value['blocks']):
                    raise ValueError('diagnostic block shape')
            except (ValueError, TypeError):
                value = {'complete': False, 'incomplete_reasons': ['INVALID_DIAGNOSTIC_RECEIPT'],
                         'blocks': [], 'original_bytes_omitted': item['bytes']}
            blocks = value.pop('blocks', [])
            pending = value.pop('pending_context', None)
            value.update(complete=False, blocks=[],
                         compact_omitted_blocks=len(blocks),
                         compact_omitted_text_bytes=sum(len(b['text'].encode('utf-8')) for b in blocks)
                            + (len(pending['text'].encode('utf-8')) if pending else 0),
                         incomplete_reasons=value['incomplete_reasons']+['COMPACT_ARTIFACT_CAP'])
            data = json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()
            doc['files'][name] = {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data),
                                  'text': data.decode(), 'encoding': 'utf-8',
                                  'original_sha256': item['sha256'], 'projection': 'DIAGNOSTIC_PAYLOAD_OMITTED'}
        raw = json.dumps(doc, ensure_ascii=False, separators=(',', ':')).encode()
        compressed = gzip.compress(raw, mtime=0)
    # Even if the input cap excluded a diagnostic file, its summary must not
    # promise a complete retained artifact. The source receipt is left untouched.
    for directory, value in diagnostics.items():
        for stream, brief in value['streams'].items():
            name = str(Path(directory) / brief['receipt'])
            item = doc['files'].get(name)
            if item is None or item.get('projection'):
                value.update(complete=False, incomplete_reasons=value['incomplete_reasons']+['COMPACT_ARTIFACT_CAP'])
                brief.update(complete=False, compact_payload_retained=False)
            else:
                brief['compact_payload_retained'] = True
    doc['diagnostic_retention'] = {
        'complete': bool(diagnostics) and not coverage_reasons and all(v['complete'] for v in diagnostics.values()),
        'scope': 'OBSERVED_TEXTUAL_ERRORS; PRODUCER_COMPLETENESS_UNKNOWN',
        'expected_directories': sorted(k for k, v in diagnostics.items() if v['expected_execution']),
        'incomplete_reasons': sorted(set(coverage_reasons) | {r for v in diagnostics.values() for r in v['incomplete_reasons']})
                             if diagnostics else sorted(set(coverage_reasons) | {'DIAGNOSTIC_RECEIPTS_UNAVAILABLE'}),
        'proof_credit': 'NONE'}
    raw = json.dumps(doc, ensure_ascii=False, separators=(',', ':')).encode()
    compressed = gzip.compress(raw, mtime=0)
    if len(raw) > UNCOMPRESSED_CAP or len(compressed) > COMPRESSED_CAP:
        raise ValueError('bounded fallback receipts exceed artifact cap')
    (root / NAME).write_bytes(compressed)
    return {'artifact': NAME, 'state': doc['state'], 'uncompressed_bytes': len(raw),
            'compressed_bytes': len(compressed), 'sha256': hashlib.sha256(compressed).hexdigest()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(); parser.add_argument('--root', type=Path, required=True)
    print(json.dumps(pack(parser.parse_args().root), sort_keys=True))
