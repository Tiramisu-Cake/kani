#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Always emit an A receipt, including setup failures and unstarted gates."""
import json
import os
from pathlib import Path

GATES = ('old-build', 'fmt', 'build', 'clippy', 'compiler-units', 'compiletest-build',
         'expected-uninit_', 'expected-function-contract_',
         'script-based-pre-autoharness_entry_reset_', 'script-based-pre-autoharness',
         'old-controls')


def finalize(out, request, steps, job_status, trigger):
    out.mkdir(parents=True, exist_ok=True)
    gates = []
    for gate in GATES:
        path = out / f'{gate}.json'
        value = {'gate': gate, 'status': 'NOT_RUN', 'exit_code': None}
        if path.is_file():
            try:
                value = json.loads(path.read_text())
                if (not isinstance(value, dict) or value.get('gate') != gate
                        or value.get('status') not in ('IN_PROGRESS', 'COMPLETED', 'TIMEOUT', 'ERROR')
                        or (value.get('exit_code') is not None and type(value['exit_code']) is not int)
                        or (value.get('status') == 'COMPLETED' and type(value.get('exit_code')) is not int)):
                    raise ValueError('receipt shape or identity mismatch')
            except (ValueError, OSError) as exc:
                value = {'gate': gate, 'status': 'MALFORMED', 'exit_code': None,
                         'error': f'{type(exc).__name__}: {exc}'}
        gates.append(value)
    result = {'schema': 'ch8-pr02-reset-a-result-v1', 'stage': 'A',
              'job_status_before_finalize': job_status, 'trigger': trigger,
              'source_pin': request['pins']['pr02'], 'patch': request['patch'],
              'expected_target': request['expected_target'],
              'steps': steps, 'gates': gates, 'proof_credit': 'NONE'}
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')


def main():
    request = json.loads(Path('CI-REQUEST.json').read_text())
    finalize(Path(os.environ['RUNNER_TEMP']) / 'ch8-pr02-reset-a', request,
             json.loads(os.environ['STEP_OUTCOMES']), os.environ['JOB_STATUS'],
             {key: os.environ.get(key) for key in
              ('GITHUB_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')})


if __name__ == '__main__':
    main()
