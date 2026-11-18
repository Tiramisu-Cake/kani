# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Bind a newly created confirmation branch event to its checked-out commit."""
import json
import os
from pathlib import Path
import re
import subprocess

REPOSITORY = 'Tiramisu-Cake/kani'
PREFIX = 'refs/heads/stub-contract-confirm-ci/'
SKIP = re.compile(r'\[(?:skip ci|ci skip|no ci|skip actions|actions skip)\]|^skip-checks\s*:\s*true\s*$',
                  re.IGNORECASE | re.MULTILINE)


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE).decode().strip()


def check_ref(ref):
    require(isinstance(ref, str) and ref.startswith(PREFIX) and len(ref) > len(PREFIX), 'push branch')
    subprocess.run(['git', 'check-ref-format', ref], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def push_event(root, control):
    require(os.environ.get('GITHUB_EVENT_NAME') == 'push', 'push event required')
    require(os.environ.get('GITHUB_REPOSITORY') == REPOSITORY, 'push repository')
    require(all(key not in os.environ for key in ('SC_CONTROL_HEAD', 'SC_CONTROL_TREE', 'SC_REQUEST_SHA256')),
            'dispatch inputs in environment')
    ref = os.environ['GITHUB_REF']
    check_ref(ref)
    head = os.environ['GITHUB_SHA']
    require(re.fullmatch('[0-9a-f]{40}', head) is not None and head == control['head'], 'push head')
    require(git(root, 'rev-parse', head + '^{tree}') == control['tree'], 'push tree')
    require(git(root, 'show', '-s', '--format=%P', head) == control['parent'], 'push sole parent')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    require(isinstance(event, dict) and 'inputs' not in event, 'push payload inputs')
    require(event['repository']['full_name'] == REPOSITORY, 'event repository')
    require(event['ref'] == ref and event['after'] == head, 'event ref/head')
    require(event['created'] is True and event['deleted'] is False and event['forced'] is False
            and event['before'] == '0' * 40, 'new branch topology')
    message = git(root, 'show', '-s', '--format=%B', head)
    require(event['head_commit']['id'] == head and event['head_commit']['message'] == message,
            'event head commit')
    require(not SKIP.search(message), 'skip directive in push head')
    return {'event': 'push', 'repository': REPOSITORY, 'ref': ref, 'head': head,
            'before': event['before'], 'created': True}
