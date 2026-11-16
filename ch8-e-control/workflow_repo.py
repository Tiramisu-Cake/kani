# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Static check shared by control workflows with an explicit --repo argument.

Only literal relative paths and direct Python control commands are supported.
No shell, checkout, compiler or verifier is executed. Implicit repository roots
(as used by other control packages) require their own package-specific check.
"""
import argparse
import json
import posixpath
import re
import shlex
from pathlib import Path


def literal_path(value):
    assert isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_./-]+', value), 'literal relative path required'
    assert not value.startswith('/'), 'workspace-relative path required'
    return value


def check_control_repo_paths(doc):
    """Resolve every explicit check_package.py control --repo to path: control.

    GitHub run defaults apply at workflow, job, then step level. Resolution uses
    a synthetic workspace, so it is independent of the local checkout layout.
    Return no implicit-root claims; a workflow without explicit checks fails.
    """
    workspace = '/__ch8_workspace__'
    checked = []
    for job_id, job in doc['jobs'].items():
        steps = job['steps']
        for step_index, step in enumerate(steps):
            command = step.get('run', '')
            assert isinstance(command, str), 'run must be a string'
            for line in command.replace('\\\n', ' ').splitlines():
                # Avoid parsing unrelated shell/heredoc contents.
                if not re.search(r'check_package\.py\s+control(?:\s|$)', line):
                    continue
                argv = shlex.split(line, comments=True)
                if not argv:
                    continue
                assert (len(argv) >= 3 and argv[0] in ('python', 'python3')
                        and posixpath.basename(argv[1]) == 'check_package.py'
                        and argv[2] == 'control'), 'direct Python control command required'
                # Packages with no --repo use an internal root: do not infer it.
                if len(argv) == 3:
                    continue
                tail = argv[3:]
                assert ((len(tail) == 2 and tail[0] == '--repo')
                        or (len(tail) == 1 and tail[0].startswith('--repo='))), 'one --repo argument required'
                repo_arg = literal_path(tail[1] if len(tail) == 2 else tail[0].split('=', 1)[1])
                checkout = [s for s in steps[:step_index]
                            if s.get('uses', '').startswith('actions/checkout@')
                            and s.get('with', {}).get('path') == 'control']
                assert len(checkout) == 1, 'one preceding checkout path: control required'
                defaults = doc.get('defaults', {}).get('run', {})
                defaults = dict(defaults, **job.get('defaults', {}).get('run', {}))
                cwd = literal_path(step.get('working-directory', defaults.get('working-directory', '.')))
                resolved = posixpath.normpath(posixpath.join(workspace, cwd, repo_arg))
                expected = posixpath.join(workspace, 'control')
                assert resolved == expected, f'{job_id}: --repo resolves to {resolved}, expected {expected}'
                checked.append({'job': job_id, 'working_directory': cwd, 'repo': repo_arg,
                                'resolved_checkout': 'control'})
    assert checked, 'no explicit control --repo validation found'
    return checked


if __name__ == '__main__':
    import yaml
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('workflows', type=Path, nargs='+')
    args = parser.parse_args()
    for path in args.workflows:
        doc = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        print(json.dumps({'workflow': str(path), 'checks': check_control_repo_paths(doc)}, sort_keys=True))
