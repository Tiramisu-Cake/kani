# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Frozen cell-only scheduling/timeout profile; no proof or decoder policy."""
import copy
import hashlib
import json

ROW_IDS = ['stable_default_cell', 'unstable_default_cell']
SELECTORS = ['slice::sort::shared::smallsort::verify::sorting_entry_smoke::' + r for r in ROW_IDS]
SECONDS = 1200
GROUP = 'cell-u34'
FROZEN_KEYS = ['status', 'std_sha', 'std_tree', 'tool_sha', 'tool_tree', 'base_std_sha', 'model_source_sha', 'model_interface_sha256', 'changed_file_sha256', 'variants', 'flags', 'property_binding', 'selector_binding', 'pre_dispatch_gate', 'source_bindings', 'control_parent', 'legacy_symbolic_rows', 'replacement_unions', 'execution_groups', 'binary_snapshot_policy', 'location_exception_policy', 'binding_metadata_policy', 'binding_metadata_requirements_sha256', 'role_map']
FROZEN_SHA256 = 'ab66ffde598d3fe930be42e07315f3058eb413a8fdbc44e291253c5cbd0fd034'

def timeout_for(row_id):
    return SECONDS if row_id in ROW_IDS else 600

def validate_request(request):
    # Full 7c reference inventory and proof settings, modulo exactly two timeouts.
    frozen = {k: request.get(k) for k in FROZEN_KEYS}
    frozen['rows'] = copy.deepcopy(request.get('rows'))
    for row in frozen['rows']:
        if row['id'] in ROW_IDS:
            if type(row.get('timeout_seconds')) is not int or row['timeout_seconds'] != SECONDS:
                raise ValueError('cell retry requires exact timeout1200')
            row['timeout_seconds'] = 600
    digest = hashlib.sha256(json.dumps(frozen, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if digest != FROZEN_SHA256:
        raise ValueError('cell retry frozen7c inventory/proof settings drift')
    if request.get('execution_scope') != {'profile': 'cell-retry1200-v1',
            'declared_reference_groups': 14, 'declared_reference_rows': 35,
            'selected_groups': [GROUP], 'selected_row_ids': ROW_IDS, 'selectors': SELECTORS}:
        raise ValueError('cell retry scope drift')
    if request.get('workflow_stages') != {'s1_cell': [GROUP]}:
        raise ValueError('cell retry workflow scope drift')
    if request['budgets'] != {'jobs': 1, 'max_parallel': 1, 'workflow_minutes': 180, 'setup_seconds': 1800, 'phase_seconds': 8100, 'reserve_seconds': 900, 'row_seconds': 600, 'rss_kib': 6291456, 'stdout_bytes': 16777216, 'stderr_bytes': 1048576, 'export_bytes': 8388608, 'artifact_bytes': 268435456, 'planned_rows_seconds': 2400, 'rss_cap_kib': 6291456, 'compile_seconds': 900, 'planned_compile_seconds_per_group': 30, 'group_rss_max_kib': 12582912, 'memory_reserve_kib': 2097152, 'projected_group_count': 1, 'cell_row_seconds': 1200, 'group_child_seconds': 3300, 'group_cleanup_seconds': 10, 'group_envelope_seconds': 3310}:
        raise ValueError('cell retry derived budgets drift')
    if request['batch_policy'] != {'group_by': ['explicit execution_groups'], 'harness_timeout': '1200s; selected cell pair only; reference other rows600s', 'jobs': 1, 'compile_boundary': 'Stock initial export marker after std_project, before verification;900s cap in same process', 'per_root_rss': 'UNKNOWN; group process peak is not per-root RSS', 'group_rss_cap': 'min(12GiB,available-2GiB); cgroup headroom considered', 'phase_seconds': 8100, 'group_wall_seconds': 'compile900 + 2*root1200 =3300 child; cleanup10; envelope3310; phase8100 unchanged'} or request['artifact_policy'] != {'file': 'group-evidence.json.gz', 'files_per_group': 1, 'groups': 1, 'compressed_cap_per_group': 8388608, 'uncompressed_cap_per_group': 33554432, 'aggregate_compressed_cap': 8388608, 'raw_stdout_uploaded': False}:
        raise ValueError('cell retry envelope policy drift')

def validate_group(group):
    if (group.get('id') != GROUP or group.get('variant') != 'production' or group.get('unwind') != 34
            or [r.get('id') for r in group.get('rows', [])] != ROW_IDS
            or [r.get('selector') for r in group['rows']] != SELECTORS
            or any(r.get('mode') != 'PFC' or r.get('type') != 'Cell<u8>'
                   or r.get('N') != 'symbolic0..3' or type(r.get('timeout_seconds')) is not int
                   or r['timeout_seconds'] != SECONDS for r in group['rows'])):
        raise ValueError('only exact cell-u34 pair allowed')

def validate_selection(selectors, unwind):
    if selectors != SELECTORS or type(unwind) is not int or unwind != 34:
        raise ValueError('only exact cell-u34 selectors/unwind allowed')
