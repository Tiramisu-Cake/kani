# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Check a proposed publication commit against an immutable review packet."""
import hashlib
import json
import re
import subprocess

from push_identity import SKIP, check_ref, git, require


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def check(root, final, ref, expected_request, pins):
    require(isinstance(final, str) and re.fullmatch('[0-9a-f]{40}', final) is not None, 'exact final SHA required')
    check_ref(ref)
    require(ref == pins['publication']['ref'], 'publication ref')
    stock, control = pins['stock'], pins['control']
    require(control['parent'] == stock['head'], 'reviewed stock parent')
    for commit, tree, parent in ((stock['head'], stock['tree'], stock['parent']),
                                 (control['head'], control['tree'], stock['head']),
                                 (final, control['tree'], stock['head'])):
        require(git(root, 'rev-parse', commit + '^{tree}') == tree, 'reviewed/final tree')
        require(git(root, 'show', '-s', '--format=%P', commit) == parent, 'reviewed/final sole parent')
    raw = subprocess.check_output(['git', '-C', str(root), 'show', final + ':.github/stub-contract-confirm/profile.json'])
    require(hashlib.sha256(raw).hexdigest() == pins['profile_sha256'], 'reviewed profile')
    commits = git(root, 'rev-list', stock['head'] + '..' + final).splitlines()
    require(commits == [final], 'publication range')
    require(not SKIP.search(git(root, 'show', '-s', '--format=%B', final)), 'skip directive in publication range')
    request = {'schema': 'stub-contract-request-v1', 'base': stock['head'], 'base_tree': stock['tree'],
               'base_parent': stock['parent'], 'control_head': final, 'control_tree': control['tree'],
               'control_parent': stock['head'], 'profile_sha256': pins['profile_sha256']}
    digest = hashlib.sha256(canonical(request)).hexdigest()
    if expected_request is not None:
        require(expected_request == digest, 'final request identity')
    return {'status': 'FINAL_HEAD_REQUEST_GATE_PASS' if expected_request is not None else 'DERIVED_REQUIRES_EXACT_REQUEST_GATE',
            'reviewed_head': control['head'], 'final_head': final, 'same_tree_sibling': final != control['head'],
            'ref': ref, 'tree': control['tree'], 'sole_parent': stock['head'],
            'range': commits, 'profile_sha256': pins['profile_sha256'],
            'request_binding': request, 'request_sha256': digest,
            'authority': 'READ_ONLY; SAME11_DELTA_AND_UPDATED_OWNER_GO_REQUIRED'}
