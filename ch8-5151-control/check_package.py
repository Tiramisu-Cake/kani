#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Validate frozen source, request identity, pins, and workflow guardrails."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent
REQUEST = json.loads((HERE / 'CI-REQUEST.json').read_text())

def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    assert REQUEST['status'] == 'READY' and REQUEST['attempt'] == 1
    assert REQUEST['proof_credit'] == 'NONE' and REQUEST['dispatch_authorized'] is False
    assert REQUEST['pins']['stock']['sha'] == '0aac16ef62da9e9d5645782d458593e5d78143ba'
    assert REQUEST['pins']['stock']['tree'] == '9d8bc9312bf955ef126d32b819b3cd0ed105ed2b'
    assert REQUEST['pins']['prototype']['sha'] == '8e299aa6243bc5f06a29c51e98aafa9564478220'
    assert REQUEST['pins']['prototype']['tree'] == '9829702c1aa0ecb73c860fc0ad5451757917d6cb'
    assert REQUEST['caps'] == {'attempt': 1, 'max_parallel': 1, 'fail_fast': False,
        'job_minutes': 55, 'build_seconds': 1800, 'row_seconds': 60, 'retries': 0}
    rows = json.loads((HERE / 'rows.json').read_text())
    assert len(rows) == 3 and REQUEST['invocation_count_per_pin'] == 3
    assert [(r['id'], r['harness'], r['expected_stock'], r['expected_prototype']) for r in rows] == [
        ('initialized-slot', 'drop_initialized_slot', 'UNSUPPORTED_UNION', 'SUCCESS'),
        ('original-empty-drop', 'drop_uninit_in_array', 'UNSUPPORTED_UNION', 'COMPLETED_WITHOUT_UNSUPPORTED'),
        ('read-in-drop', 'read_in_drop_of_uninit_slot', 'UNSUPPORTED_UNION', 'UNINIT_FAILURE')]
    payload = REQUEST['payload_sha256']
    for rel, wanted in payload.items():
        path = (ROOT / rel).resolve()
        assert ROOT.resolve() in path.parents and path.is_file() and digest(path) == wanted, rel
    assert digest(HERE / 'rows.json') == REQUEST['rows_sha256']
    for row in rows:
        assert row['flags'] == ['-Z', 'uninit-checks']
        assert row['compile_flags'] == ['--edition', '2021']
        source = ROOT / row['file']
        assert source.is_file() and payload[row['file']] == digest(source)
        assert '// compile-flags: --edition 2021' in source.read_text().splitlines()[:5]
    original = (ROOT / rows[1]['file']).read_text()
    for phrase in ('struct D(u8);', 'impl Drop for D { fn drop(&mut self) {} }',
                   'fn drop_uninit_in_array()', '// slot 1 uninit'):
        assert phrase in original
    workflow = (ROOT / '.github/workflows/ch8-5151.yml').read_text()
    for phrase in ('branches: ["uninit-ci/ch8-5151-*"]', 'Tiramisu-Cake/kani',
                   'max-parallel: 1', 'fail-fast: false', 'timeout-minutes: 55',
                   'repository: model-checking/kani', 'repository: Tiramisu-Cake/kani',
                   'actions/checkout@v6', './tool/.github/actions/setup',
                   'runner.py fallback', 'HEAD^1^{tree}', "[skip ci]", 'HEAD^1^1'):
        assert phrase in workflow, phrase
    runner = (HERE / 'runner.py').read_text()
    assert "['cargo', 'build-dev', '--', '--release']" in runner
    assert 'Cannot determine layout for a type that contains union' in runner
    assert 'workflow_dispatch' not in workflow
    workflows = list((ROOT / '.github/workflows').glob('*.yml')) + list((ROOT / '.github/workflows').glob('*.yaml'))
    assert [p.name for p in workflows] == ['ch8-5151.yml']
    print('package hashes, pins, source rows, and workflow guardrails: OK')

if __name__ == '__main__': main()
