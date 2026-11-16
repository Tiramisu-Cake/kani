"""One deterministic compact structured artifact per job. Never reads raw logs."""
import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path

UNCOMPRESSED_CAP = 32 * 1024 * 1024
COMPRESSED_CAP = 8 * 1024 * 1024
NAME = 'group-evidence.json.gz'


def pack(root):
    files = {}
    total = 0
    errors = []
    try:
        for path in sorted(root.rglob('*.json')):
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
    doc = {'schema': 'ch8-s1-05-artifact-v1', 'state': 'INCOMPLETE' if error else 'PACKAGED',
           'error': error, 'files': files, 'proof_credit': 'NONE'}
    raw = json.dumps(doc, ensure_ascii=False, separators=(',', ':')).encode()
    compressed = gzip.compress(raw, mtime=0)
    if len(raw) > UNCOMPRESSED_CAP or len(compressed) > COMPRESSED_CAP:
        error = 'compact artifact cap'
        # Preserve identities/exits/snapshots in the small receipts when inventory cannot fit.
        kept = {k: v for k, v in files.items() if k.endswith('receipt.json') and v['bytes'] <= 65536}
        doc.update(state='INCOMPLETE', error=error, files=kept)
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
