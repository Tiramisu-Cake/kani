# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Lossless, selector-scoped projections of regular output and stock JSON export.

This deliberately records observations only. It does not decide acceptance or
whether an individual property fulfills a verification role.
"""
import json
import re
from collections import Counter


MAX_REGULAR_BYTES = 16 * 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024
STOCK_SOURCE_COMMIT = 'bcdc1a0f8dc566654da1f18b4e502f0f4e7ad40a'
CHECK_BUCKETS = ('failure', 'unreachable', 'undetermined', 'error', 'unknown', 'other')
COVER_BUCKETS = ('satisfied', 'unsatisfiable', 'unreachable', 'undetermined',
                 'error', 'unknown', 'other')


def _incomplete(reason, observations=None, **extra):
    result = {'state': 'INCOMPLETE', 'reason': reason,
              'observations': observations or []}
    result.update(extra)
    return result


def regular(data: bytes, selector: str) -> dict:
    """Project one exact harness from Kani's regular stdout bytes."""
    if not isinstance(data, bytes) or not isinstance(selector, str) or not selector:
        return _incomplete('invalid input type or empty selector')
    if len(data) > MAX_REGULAR_BYTES:
        return _incomplete('regular output exceeds 16 MiB', observed_bytes=len(data))
    try:
        text = data.decode('utf-8', errors='strict')
    except UnicodeDecodeError as exc:
        return _incomplete('regular output is not valid UTF-8', byte_offset=exc.start)

    plain = text.split('\n')
    lines = [line + '\n' for line in plain[:-1]] + [plain[-1]]
    offsets = []
    cursor = 0
    for line in lines:
        offsets.append(cursor)
        cursor += len(line.encode('utf-8'))
    markers = [i for i, line in enumerate(plain) if re.fullmatch(r'Checking harness (.+)\.\.\.', line)]
    if len(markers) != 1 or plain[markers[0]] != 'Checking harness ' + selector + '...':
        return _incomplete('expected one exact selector marker', observed_bytes=len(data), selector=selector)
    start = markers[0]
    results = [i for i in range(start + 1, len(plain)) if plain[i] == 'RESULTS:']
    if len(results) != 1:
        return _incomplete('expected one selected RESULTS marker', observed_bytes=len(data), selector=selector)
    results = results[0]
    summaries = [i for i in range(results + 1, len(plain)) if plain[i] == 'SUMMARY:']
    summary = summaries[0] if summaries else len(plain)
    verifications = [i for i in range(summary + 1, len(plain))
                     if re.fullmatch(r'VERIFICATION:- (SUCCESSFUL|FAILED)(?: .*)?', plain[i])]
    verify = verifications[0] if verifications else None
    issues = []
    if len(summaries) != 1:
        issues.append('expected one selected SUMMARY marker')
    if len(verifications) != 1:
        issues.append('expected one terminal VERIFICATION line after SUMMARY')

    observations = []
    index = results + 1
    while index < summary:
        if not plain[index].strip():
            index += 1
            continue
        if not plain[index].startswith('Check '):
            issues.append(f'unexpected RESULTS text at line {index + 1}')
            break
        first = index
        end = index + 1
        while end < summary and not (
                plain[end].startswith('Check ') and end + 1 < summary
                and plain[end + 1].startswith('\t - Status: ')):
            end += 1
        raw = ''.join(lines[first:end]).rstrip('\r\n')
        match = re.fullmatch(
            r'Check ([1-9][0-9]*): ([^\n]+)\n\t - Status: ([A-Z_]+)\n'
            r'\t - Description: "([\s\S]*?)"(?:\n\t - Location: ([\s\S]*))?', raw)
        if not match:
            return _incomplete('malformed or partial property record', observations,
                                observed_bytes=len(data), selector=selector)
        ordinal, prop_id, status, description, location = match.groups()
        if int(ordinal) != len(observations) + 1:
            issues.append(f'noncontiguous property ordinal at line {first + 1}')
            break
        cls = re.search(r'(?:^|\.)(NaN|[a-z_-]+)\.([0-9]+)$', prop_id)
        if not cls:
            return _incomplete('property class/ID suffix missing', observations,
                                observed_bytes=len(data), selector=selector)
        byte_start = offsets[first]
        byte_end = offsets[end] if end < len(offsets) else len(data)
        if byte_end - byte_start > MAX_RECORD_BYTES:
            return _incomplete('property record exceeds 64 KiB', observations,
                                observed_bytes=len(data), selector=selector)
        property_class, counter = cls.groups()
        name = prop_id[:cls.start()]
        export_id = prop_id
        if property_class == 'missing_definition' and name:
            export_id = f'{name}.{counter}'
        elif property_class == 'recursion' and counter == '1':
            export_id = f'{name}.recursion'
        observations.append({
            'ordinal': int(ordinal), 'display_id': prop_id, 'id': prop_id,
            'stock_export_id': export_id,
            'class': cls.group(1), 'status': status,
            'description': description, 'location': location,
            'source_coordinate': {'byte_start': byte_start, 'byte_end': byte_end,
                                  'first_line': first + 1, 'last_line': end},
        })
        index = end
    summary_lines = [
        {'text': plain[i], 'coordinate': {'line': i + 1, 'byte_start': offsets[i],
                                          'byte_end': offsets[i] + len(plain[i].encode())}}
        for i in range(summary + 1, verify if verify is not None else len(plain))
        if re.match(r"^ \*\* \d+ of \d+ (?:failed|cover properties satisfied)", plain[i])
    ]
    if verify is not None and not any(re.fullmatch(r' \*\* [0-9]+ of [0-9]+ failed(?: \(.*\))?',
                                                   item['text']) for item in summary_lines):
        issues.append('terminal check count line missing')
    return {'state': 'INCOMPLETE' if issues else 'COMPLETE',
            'reason': '; '.join(issues) if issues else None, 'selector': selector,
            'observed_bytes': len(data), 'observations': observations,
            'terminal': {'summary_lines': summary_lines,
                         'verification': plain[verify] if verify is not None else None,
                          'verification_line': verify + 1 if verify is not None else None,
                         'verification_coordinate': ({'line': verify + 1, 'byte_start': offsets[verify],
                                                      'byte_end': offsets[verify] + len(plain[verify].encode())}
                                                     if verify is not None else None)},
            'source': {'kind': 'regular_stdout',
                       'coordinates': 'one-based lines/ordinals and zero-based byte ranges'}}


def _pointer(parts):
    return '/' + '/'.join(str(part).replace('~', '~0').replace('/', '~1') for part in parts)


def stock_export(data: bytes, selector: str) -> dict:
    """Validate and project selector-relevant RFC 0015 stock-export fields."""
    if not isinstance(data, bytes) or not isinstance(selector, str) or not selector:
        return _incomplete('invalid input type or empty selector', json_pointers=[])
    try:
        document = json.loads(data.decode('utf-8', errors='strict'))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _incomplete('malformed or partial JSON export: ' + str(exc), json_pointers=[])
    if not isinstance(document, dict):
        return _incomplete('JSON export root is not an object', json_pointers=[])
    pointers = []
    errors = []

    def need(obj, key, typ, path):
        ptr = _pointer(path + [key]); pointers.append(ptr)
        present = isinstance(obj, dict) and key in obj
        value = obj.get(key) if present else None
        if not present or not isinstance(value, typ) or (typ is int and isinstance(value, bool)):
            errors.append(ptr + ': missing or wrong type')
        return value

    def nullable(obj, key, typ, path):
        ptr = _pointer(path + [key]); pointers.append(ptr)
        present = isinstance(obj, dict) and key in obj
        value = obj.get(key) if present else None
        if not present or (value is not None and
                           (not isinstance(value, typ) or (typ is int and isinstance(value, bool)))):
            errors.append(ptr + ': missing or wrong nullable type')
        return value

    # Run-level identity, effective configuration and terminal summary.
    run_fields = {}
    for key, typ in (('schema_version', str), ('target', str), ('started_at', str),
                     ('run_state', str)):
        run_fields[key] = need(document, key, typ, [])
    if isinstance(run_fields['started_at'], str) and not re.fullmatch(
            r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z',
            run_fields['started_at']):
        errors.append('/started_at: invalid stock timestamp format')
    if run_fields['run_state'] not in ('COMPLETE', 'PARTIAL', 'NO_HARNESSES_SELECTED'):
        errors.append('/run_state: unsupported terminal state')
    run_fields['kani_commit'] = nullable(document, 'kani_commit', str, [])
    run_fields['kani_commit_dirty'] = nullable(document, 'kani_commit_dirty', bool, [])
    run_fields['harness_timeout_s'] = nullable(document, 'harness_timeout_s', (int, float), [])
    run_fields['wall_time_s'] = need(document, 'wall_time_s', (int, float), [])
    run_fields['enabled_unstable_features'] = need(document, 'enabled_unstable_features', list, [])
    if isinstance(run_fields['enabled_unstable_features'], list) and not all(
            isinstance(v, str) for v in run_fields['enabled_unstable_features']):
        errors.append('/enabled_unstable_features: expected strings')
    tools = need(document, 'tools', dict, [])
    run_fields['tools'] = {}
    if isinstance(tools, dict):
        for key in ('kani', 'rustc', 'cbmc'):
            run_fields['tools'][key] = nullable(tools, key, str, ['tools'])
            if key == 'kani' and not run_fields['tools'][key]:
                errors.append('/tools/kani: expected nonempty stock version')
    configuration = need(document, 'configuration', dict, [])
    run_fields['configuration'] = configuration
    if isinstance(configuration, dict):
        checks_config = need(configuration, 'checks', dict, ['configuration'])
        if isinstance(checks_config, dict):
            run_fields['configuration_checks'] = {}
            for key in ('memory_safety', 'overflow', 'unwinding', 'undefined_function',
                        'assertion_reach_checks', 'ignore_global_asm', 'extra_pointer_checks',
                        'assert_contracts', 'prove_safety_only'):
                run_fields['configuration_checks'][key] = need(
                    checks_config, key, bool, ['configuration', 'checks'])
        run_fields['cbmc_args'] = need(configuration, 'cbmc_args', list, ['configuration'])
        if isinstance(run_fields['cbmc_args'], list) and not all(
                isinstance(v, str) for v in run_fields['cbmc_args']):
            errors.append('/configuration/cbmc_args: expected strings')
        run_fields['coverage_enabled'] = need(configuration, 'coverage_enabled', bool,
                                              ['configuration'])
    run_outcome = need(document, 'outcome', dict, [])
    run_fields['outcome'] = run_outcome
    if isinstance(run_outcome, dict):
        kind = need(run_outcome, 'kind', str, ['outcome'])
        if kind != 'COMPLETED':
            errors.append('/outcome/kind: unexpected terminal run outcome')
    summary_obj = need(document, 'summary', dict, [])
    run_fields['summary'] = {}
    if isinstance(summary_obj, dict):
        for key in ('total', 'successful', 'failed', 'checks_total', 'checks_success',
                    'covers_total', 'covers_satisfied'):
            run_fields['summary'][key] = need(summary_obj, key, int, ['summary'])

    hs = need(document, 'harnesses', list, [])
    if not isinstance(hs, list):
        hs = []
    if isinstance(run_fields.get('summary'), dict) and run_fields['summary'].get('total') != len(hs):
        errors.append('/summary/total: does not equal exported harness count')
    if len(hs) != 1:
        errors.append('/harnesses: expected a singleton export')
    matches = [(i, h) for i, h in enumerate(hs)
               if isinstance(h, dict) and h.get('name') == selector]
    if len(matches) != 1:
        errors.append('/harnesses: expected exactly one exact selector match')
    selection = need(document, 'harness_selection', dict, [])
    run_fields['harness_selection'] = selection
    if isinstance(selection, dict):
        filters = need(selection, 'requested_filters', list, ['harness_selection'])
        exact = need(selection, 'exact', bool, ['harness_selection'])
        matched = need(selection, 'matched_count', int, ['harness_selection'])
        unmatched = need(selection, 'unmatched_filters', list, ['harness_selection'])
        if filters != [selector] or exact is not True or matched != 1 or unmatched != []:
            errors.append('/harness_selection: does not attest one exact requested selector')

    if len(matches) != 1:
        return _incomplete('; '.join(errors), json_pointers=pointers,
                            observed_bytes=len(data), selector=selector,
                            metadata=run_fields)
    index, h = matches[0]
    base = ['harnesses', index]
    projection = {'name': selector, 'json_pointer': _pointer(base), 'fields': {},
                  'totals': {}, 'property_buckets': {}}

    # Scoped metadata used to identify the selected contract harness and stubs.
    for key, typ in (('crate_name', str), ('file', str), ('line', int),
                     ('is_automatically_generated', bool), ('has_loop_contracts', bool),
                     ('is_bounded', bool), ('has_refcount_caveat', bool), ('generated_concrete_test', bool)):
        projection['fields'][key] = need(h, key, typ, base)
    for key, typ in (('resolved_solver', str), ('resolved_unwind', int)):
        projection['fields'][key] = nullable(h, key, typ, base)
    projection['fields']['resources'] = need(h, 'resources', dict, base)
    if isinstance(projection['fields']['resources'], dict):
        projection['fields']['resources']['verification_time_s'] = need(
            projection['fields']['resources'], 'verification_time_s', (int, float),
            base + ['resources'])
    attributes = need(h, 'attributes', dict, base)
    if isinstance(attributes, dict):
        kind = need(attributes, 'kind', (str, dict), base + ['attributes'])
        projection['fields']['attributes.kind'] = kind
        if isinstance(kind, dict):
            target = need(kind.get('ProofForContract'), 'target_fn', str,
                          base + ['attributes', 'kind', 'ProofForContract'])
            projection['fields']['attributes.kind.ProofForContract.target_fn'] = target
        for key in ('stubs', 'verified_stubs'):
            projection['fields']['attributes.' + key] = need(attributes, key, list,
                                                              base + ['attributes'])
        projection['fields']['attributes.should_panic'] = need(
            attributes, 'should_panic', bool, base + ['attributes'])
        for key, typ in (('solver', (str, dict)), ('unwind_value', int)):
            projection['fields']['attributes.' + key] = nullable(
                attributes, key, typ, base + ['attributes'])
        for key in ('original', 'replacement'):
            for j, stub in enumerate(projection['fields']['attributes.stubs'] or []):
                if not isinstance(stub, dict) or not isinstance(stub.get(key), str):
                    errors.append(_pointer(base + ['attributes', 'stubs', j, key]) + ': missing/wrong type')
                pointers.append(_pointer(base + ['attributes', 'stubs', j, key]))
    contract = nullable(h, 'contract', dict, base)
    if isinstance(contract, dict):
        projection['fields']['contract.contracted_function_name'] = need(
            contract, 'contracted_function_name', str, base + ['contract'])
        projection['fields']['contract.recursion_tracker'] = nullable(
            contract, 'recursion_tracker', str, base + ['contract'])
        projection['fields']['contract.json_pointer'] = _pointer(base + ['contract'])

    outcome = need(h, 'outcome', dict, base)
    if isinstance(outcome, dict):
        for key in ('kind', 'verdict', 'code', 'message'):
            if key == 'kind' or key in outcome:
                projection['fields']['outcome.' + key] = (nullable if key in ('code', 'message') else need)(
                    outcome, key, int if key == 'code' else str, base + ['outcome'])
        if outcome.get('kind') == 'COMPLETED' and 'verdict' not in outcome:
            errors.append(_pointer(base + ['outcome', 'verdict']) + ': absent on COMPLETED')
        if outcome.get('kind') != 'COMPLETED' and 'verdict' in outcome:
            errors.append(_pointer(base + ['outcome', 'verdict']) + ': unexpected on non-COMPLETED')
    for bucket_name, bucket_keys in (('checks', CHECK_BUCKETS), ('covers', COVER_BUCKETS)):
        bucket = need(h, bucket_name, dict, base)
        if not isinstance(bucket, dict):
            continue
        total = nullable(bucket, 'total', int, base + [bucket_name])
        projection['totals'][bucket_name + '.total'] = total
        count = 0
        for key in bucket_keys:
            values = need(bucket, key, list, base + [bucket_name])
            if not isinstance(values, list):
                continue
            projection['property_buckets'][bucket_name + '.' + key] = values
            count += len(values)
            for j, item in enumerate(values):
                if key == 'other':
                    if not isinstance(item, dict) or not isinstance(item.get('id'), str) or not isinstance(item.get('status'), str):
                        errors.append(_pointer(base + [bucket_name, key, j]) + ': malformed other bucket record')
                elif not isinstance(item, str) or not item:
                    errors.append(_pointer(base + [bucket_name, key, j]) + ': expected nonempty property ID')
                pointers.append(_pointer(base + [bucket_name, key, j]))
        if bucket_name == 'checks':
            success = nullable(bucket, 'success', int, base + [bucket_name])
            projection['totals']['checks.success'] = success
            count += success if isinstance(success, int) else 0
        if isinstance(total, int) and count != total:
            errors.append(_pointer(base + [bucket_name, 'total']) + ': partition total mismatch')
    for key in ('n_properties', 'n_failed'):
        projection['totals'][key] = nullable(h, key, int, base)
    if isinstance(projection['totals'].get('n_properties'), int):
        checks_total = projection['totals'].get('checks.total')
        covers_total = projection['totals'].get('covers.total')
        if isinstance(checks_total, int) and isinstance(covers_total, int) and projection['totals']['n_properties'] != checks_total + covers_total:
            errors.append(_pointer(base + ['n_properties']) + ': property total mismatch')
    failed_count = projection['totals'].get('n_failed')
    failure_ids = projection['property_buckets'].get('checks.failure', [])
    if isinstance(failed_count, int) and failed_count != len(failure_ids):
        errors.append(_pointer(base + ['n_failed']) + ': failure count mismatch')
    projection['fields']['failure_kind'] = h.get('failure_kind')
    if 'failure_kind' in h and h['failure_kind'] not in ('ERROR', 'NONE', 'OTHER', 'PANICS_ONLY'):
        errors.append(_pointer(base + ['failure_kind']) + ': unsupported value')
    for key in ('failed_properties', 'unsupported_constructs'):
        entries = need(h, key, list, base)
        projection['fields'][key] = []
        if isinstance(entries, list):
            for j, prop in enumerate(entries):
                ptr = base + [key, j]
                if not isinstance(prop, dict):
                    errors.append(_pointer(ptr) + ': expected property object')
                    continue
                fields = {name: need(prop, name, typ, ptr) for name, typ in
                          (('id', str), ('description', str), ('class', str),
                           ('trace_available', bool), ('status', str))}
                fields.update({name: nullable(prop, name, str, ptr) for name in ('file', 'line')})
                projection['fields'][key].append(fields)
    if isinstance(failed_count, int) and isinstance(projection['fields'].get('failed_properties'), list):
        failed = projection['fields']['failed_properties']
        if failed_count != len(failed):
            errors.append(_pointer(base + ['n_failed']) + ': failed_properties count mismatch')
        if Counter(p.get('id') for p in failed if isinstance(p, dict)) != Counter(failure_ids):
            errors.append(_pointer(base + ['failed_properties']) + ': IDs differ from checks.failure')
    warnings = need(h, 'warnings', list, base)
    projection['fields']['warnings'] = []
    if isinstance(warnings, list):
        for j, item in enumerate(warnings):
            ptr = base + ['warnings', j]
            projection['fields']['warnings'].append({
                'message': need(item, 'message', str, ptr),
                'truncated': need(item, 'truncated', bool, ptr),
                'original_chars': nullable(item, 'original_chars', int, ptr),
            })
    projection['fields']['warnings_truncated'] = need(h, 'warnings_truncated', int, base)
    return {'state': 'INCOMPLETE' if errors else 'COMPLETE',
            'reason': '; '.join(errors) if errors else None, 'selector': selector,
            'observed_bytes': len(data), 'observations': [projection],
            'metadata': run_fields,
            'json_pointers': pointers,
            'source': {'kind': 'stock_export_json', 'coordinates': 'RFC 0015 JSON Pointer',
                       'validator_source_commit': STOCK_SOURCE_COMMIT}}
