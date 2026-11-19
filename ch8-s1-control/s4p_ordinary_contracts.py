# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Bounded source preflight for ordinary stubs; no expansion/MIR/proof claim.

Walk the existing active smallsort module graph, including unselected providers.
Opaque macro bodies are conservatively scanned: every literal stub target in
any arm must be safe. Computed/metavariable targets and unresolved identities
fail closed. This can reject an unused macro arm, never accept an unsafe one.
"""
import hashlib
from pathlib import Path
import shlex
import cfg_pfc as c
import contract_stacks as cs

CONTRACTS = {'requires', 'modifies', 'ensures', 'recursion', 'checked_with',
             'replaced_with', 'asserted_with', 'recursion_check', 'modifies_wrapper',
             'is_contract_generated', 'recursion_tracker', 'fn_marker'}
META_FORWARDING_PINS = {'library/core/src/slice/sort/shared/smallsort/verify/network.rs': 'd59ceb99741990afcfe3f312119053a520f16c071f200953fc517a33729527bf', 'library/core/src/slice/sort/shared/smallsort/verify/merge/profiles.rs': '3a220d9fcd8269b253efaa8d7c18c13aa7a6e6f8cf59504ac2ec4c004b9abffe'}
RELEVANT = CONTRACTS | {'stub', 'stub_verified', 'proof_for_contract', 'use_stub_set', 'stub_set'}


def check(std, request):
    std = Path(std)
    flags = shlex.split(request['flags']['RUSTFLAGS'])
    c.need(all(f.startswith('--cfg=') for f in flags), 'ordinary gate: unsupported RUSTFLAGS')
    active = {'kani'} | {f[6:] for f in flags}
    c.need(len(request['rows']) == 8, 'ordinary gate: expected eight contexts')
    known = active | {'kani_smallsort_controls', 'kani_smallsort_sorting', 'kani_smallsort_s2_assumed', 'kani_smallsort_s3_leaf','kani_smallsort_s4_partition'}
    hashes, modules, declarations, stubs = {}, {}, {}, []

    def evaluate(attrs):
        # Only irrelevant cfg_attr (e.g. target-dependent lint) may use unknown cfg.
        def validate(ts):
            if not ts or ts[0][0] not in ('cfg', 'cfg_attr'):
                return
            args, end = c.group(ts, 1)
            c.need(end == len(ts), 'ordinary gate: trailing cfg syntax')
            parts = c.split(args)
            is_attr = ts[0][0] == 'cfg_attr'
            if is_attr and all(p and p[0][0] in {'allow', 'warn', 'deny', 'inline', 'cold'} for p in parts[1:]):
                return
            guard = parts[0] if is_attr else args
            identifiers = {t for t, _ in guard if t.isidentifier()}
            c.need(identifiers <= known | {'all', 'any', 'not'},
                   'ordinary gate: unknown cfg ' + c.spelling(guard))
            if is_attr:
                for p in parts[1:]: validate(p)
        for a in attrs: validate(a)
        return c.attributes(attrs, active)

    def walk(rel, module):
        path = std / rel
        c.need(path.is_file(), 'ordinary gate: missing module ' + rel)
        text = path.read_text()
        hashes[rel] = hashlib.sha256(path.read_bytes()).hexdigest()
        inner, items = c.items(text)
        c.need(evaluate(inner)[0], 'ordinary gate: inactive file ' + rel)
        aliases, globs = c.AliasMap(module, c.local_names(items, evaluate)), []
        enabled_items = []
        for item in items:
            enabled, attrs = evaluate(item['attrs'])
            if not enabled: continue
            enabled_items.append((item, attrs))
            pos = c.kind(item, 'use')
            if pos is not None:
                if any(t == '*' for t, _ in item['head'][pos:]):
                    globs.append(c.spelling(item['head'][pos:])); continue
                for alias, target in c.use_paths(item['head'][pos:]):
                    c.need(alias not in aliases, 'ordinary gate: ambiguous alias ' + alias + ' in ' + rel)
                    aliases[alias] = c.absolute(target, module)
        c.validate_aliases(aliases)
        modules[module] = {'file': rel, 'aliases': aliases, 'globs': globs}
        for name, item, attrs in cs.declarations(text, active):
            identity = module + name
            c.need(identity not in declarations, 'ordinary gate: duplicate declaration ' + '::'.join(identity))
            # Nested declarations have no active contract-relevant cfg unknown to this gate.
            evaluate(item['attrs'])
            declarations[identity] = {'file': rel, 'line': item['line'], 'attrs': attrs, 'module': module}
        for item, attrs in enabled_items:
            pos = c.kind(item, 'fn')
            if pos is not None:
                record_attrs(attrs, module, '::'.join(module + (item['head'][pos][0],)), rel, 'FUNCTION')
                # No hidden body-local stubs/contract declarations accepted.
                c.need(not list(nested_attrs(item['body'])) and not any(t in {'stub_set', 'use_stub_set'} for t, _ in item['body']),
                       'ordinary gate: unsupported body-local annotation ' + rel + ':' + str(item['line']))
            elif c.kind(item, 'mod') is not None:
                name = item['head'][c.kind(item, 'mod')][0]
                c.need(item['delimiter'] == ';', 'ordinary gate: unsupported inline module ' + rel + ':' + name)
                parent = path.parent if path.name == 'mod.rs' else path.with_suffix('')
                matches = [p for p in (parent/(name+'.rs'), parent/name/'mod.rs') if p.is_file()]
                c.need(len(matches) == 1, 'ordinary gate: missing/ambiguous module ' + name)
                walk(str(matches[0].relative_to(std)), module + (name,))
            else:
                # Includes macro_rules, impls and traits. Scan every literal
                # attribute, including inactive arms, rather than guess expansion.
                for attr in nested_attrs(item['body']):
                    enabled, expanded = evaluate([attr])
                    if enabled:
                        record_attrs(expanded, module, '::'.join(module) + '::<opaque@' + str(item['line']) + '>', rel, 'CONSERVATIVE_OPAQUE_ALL_ARMS')

    def nested_attrs(ts):
        for i, (t, _) in enumerate(ts[:-1]):
            if t == '#' and ts[i+1][0] == '[':
                attr, _ = c.group(ts, i+1)
                yield attr

    def record_attrs(attrs, module, harness, rel, scope):
        aliases = modules[module]['aliases']
        for attr in attrs:
            words = [t for t, _ in attr]
            if '$' in words and words[0] == '$':
                c.need(scope == 'CONSERVATIVE_OPAQUE_ALL_ARMS' and rel in META_FORWARDING_PINS
                       and hashes[rel] == META_FORWARDING_PINS[rel],
                       'ordinary gate: unsupported forwarded attribute ' + rel + ':' + str(attr[0][1]))
                continue  # exact frozen macro AND invocation bytes; no injected stub attrs
            p = words.index('(') if '(' in words else words.index('=') if '=' in words else len(words)
            path = c.attribute_identity(attr[:p], module, aliases)
            op = path[-1]
            c.need(op not in ('use_stub_set', 'stub_set'), 'ordinary gate: unsupported stub set ' + rel + ':' + str(attr[0][1]))
            if op != 'stub': continue
            c.need(path == ('core', 'kani', 'stub'), 'ordinary gate: unresolved stub attribute ' + c.spelling(attr))
            args, end = c.group(attr, p)
            parts = c.split(args)
            c.need(end == len(attr) and len(parts) == 2, 'ordinary gate: malformed stub ' + c.spelling(attr))
            target = c.resolve(parts[0], module, aliases)
            stubs.append({'harness': harness, 'target': '::'.join(target),
                          'file': rel, 'line': attr[0][1], 'scope': scope, '_target': target})

    # Existing PFC gate independently checks actual ancestor activation. Here
    # source hashing binds every module used for ordinary target declarations.
    walk(cs.SMALLSORT, c.SM)
    results, violations = [], []
    for stub in stubs:
        target = stub.pop('_target')
        c.need(target in declarations, f"{stub['file']}:{stub['line']} ordinary gate: unresolved/foreign target {stub['target']}")
        decl = declarations[target]
        c.need(not modules[decl['module']]['globs'], 'ordinary gate: unsupported target-scope glob ' + stub['target'])
        contracts = []
        for attr in decl['attrs']:
            words = [t for t, _ in attr]
            p = words.index('(') if '(' in words else words.index('=') if '=' in words else len(words)
            path = c.attribute_identity(attr[:p], decl['module'], modules[decl['module']]['aliases'])
            c.need(not any(t in CONTRACTS for t in words) or any(t in CONTRACTS for t in path),
                   'ordinary gate: unsupported contract wrapper ' + c.spelling(attr))
            if path[-1] in CONTRACTS or any(t in CONTRACTS for t in path):
                contracts.append(c.spelling(attr))
            else:
                c.need(c.spelling(attr[:p]) in {'inline', 'cold', 'allow', 'warn', 'deny', 'expect', 'doc', 'track_caller'},
                       'ordinary gate: unsupported target attribute ' + c.spelling(attr) + ' on ' + stub['target'])
        rec = {**stub, 'target_location': {'file': decl['file'], 'line': decl['line']},
               'active_contract_attrs': contracts, 'status': 'REJECT' if contracts else 'NO_ACTIVE_CONTRACT_ATTRS'}
        results.append(rec)
        if contracts:
            violations.append(f"{stub['file']}:{stub['line']} {stub['harness']}: ordinary stub target {stub['target']} has active contract attrs at {decl['file']}:{decl['line']}: " + ';'.join(contracts))
    c.need(not violations, '\n'.join(violations))
    if 'ordinary_contract_source_sha256' in request:
        c.need(hashes == request['ordinary_contract_source_sha256'], 'ordinary gate: source-hash binding drift')
    return {'schema': 'ch8-s2-ordinary-stub-contract-map-r4-v1',
            'source_sha': request['std_sha'], 'source_tree': request['std_tree'],
            'source_files_sha256': hashes, 'checked_active_ordinary_uses': results,
            'contexts': [{'row': r['id'], 'effective_cfg': sorted(active),
                          'checked_bindings': len(results), 'status': 'NO_ACTIVE_CONTRACT_ATTRS'} for r in request['rows']],
            'opaque_policy': 'ALL_LITERAL_TARGETS_IN_ALL_MACRO_ARMS; COMPUTED_TARGET_FAILS_CLOSED',
            'status': 'STATIC_PASS', 'compilation': 'NOT_RUN', 'proof_credit': 'NONE'}
