# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Bounded Rust item/cfg/alias checker, NOT a Rust compiler or proof qualifier.

Evidence slice: actual core module ancestors, smallsort function declarations,
verify::{helper_contracts,sorting_s2_batch}. Only these registration providers
are counted. Other providers cannot produce acceptance. Unsupported syntax in
this slice fails closed; bodies are opaque (no body-local registrations counted).
"""
import hashlib
import json
from pathlib import Path
import re
import shlex


class GateError(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise GateError(why)


def tokens(text):
    """Remove comments/literals without treating their contents as attributes."""
    out = []
    i = 0
    line = 1
    while i < len(text):
        if text[i].isspace():
            line += int(text[i] == '\n')
            i += 1
            continue
        if text.startswith('//', i):
            end = text.find('\n', i)
            i = len(text) if end < 0 else end
            continue
        if text.startswith('/*', i):
            start = i
            depth = 1
            i += 2
            while depth and i < len(text):
                if text.startswith('/*', i):
                    depth += 1
                    i += 2
                elif text.startswith('*/', i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            need(depth == 0, 'unterminated block comment')
            line += text[start:i].count('\n')
            continue
        start = i
        raw = re.match(r'(?:br|r)(#{0,32})"', text[i:])
        if raw:
            end = text.find('"' + raw[1], i + raw.end())
            need(end >= 0, 'unterminated raw literal')
            i = end + 1 + len(raw[1])
        elif text[i] == '"' or (text[i] == "'" and
                re.match(r"'(?:\\.|[^'\\\n])'", text[i:])):
            quote = text[i]
            i += 1
            while i < len(text):
                if text[i] == '\\':
                    i += 2
                elif text[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
            else:
                raise GateError('unterminated literal')
        else:
            m = re.match(r'[A-Za-z_][A-Za-z_0-9]*|[0-9]+|::|.', text[i:])
            i += m.end()
        out.append((text[start:i], line))
        line += text[start:i].count('\n')
    return out


def group(ts, start):
    pairs = {'(': ')', '[': ']', '{': '}'}
    need(ts[start][0] in pairs, 'expected delimiter')
    stack = [pairs[ts[start][0]]]
    i = start + 1
    while i < len(ts) and stack:
        t = ts[i][0]
        if t in pairs:
            stack.append(pairs[t])
        elif t in pairs.values():
            need(t == stack.pop(), 'unbalanced delimiter at line ' + str(ts[i][1]))
        i += 1
    need(not stack, 'unterminated delimiter')
    return ts[start+1:i-1], i


def split(ts):
    result, start, i = [], 0, 0
    while i < len(ts):
        if ts[i][0] in ('(', '[', '{'):
            _, i = group(ts, i)
        elif ts[i][0] == ',':
            result.append(ts[start:i])
            start = i + 1
            i += 1
        else:
            i += 1
    if start < len(ts):
        result.append(ts[start:])
    return result


def spelling(ts):
    return ''.join(t for t, _ in ts)


def cfg(ts, active):
    s = spelling(ts)
    if len(ts) == 1 and re.fullmatch(r'[A-Za-z_]\w*', s):
        return s in active
    if len(ts) == 3 and ts[1][0] == '=' and ts[2][0].startswith('"'):
        return s in active
    need(len(ts) >= 3 and ts[0][0] in ('all', 'any', 'not') and ts[1][0] == '(',
         'unsupported cfg expression: ' + s)
    inner, end = group(ts, 1)
    need(end == len(ts), 'trailing cfg syntax: ' + s)
    args = split(inner)
    values = [cfg(a, active) for a in args]
    if ts[0][0] == 'not':
        need(len(values) == 1, 'not needs exactly one cfg operand')
        return not values[0]
    return all(values) if ts[0][0] == 'all' else any(values)


def attributes(attrs, active):
    enabled, ordinary = True, []
    for ts in attrs:
        name = ts[0][0] if ts else ''
        if name in ('cfg', 'cfg_attr'):
            need(len(ts) >= 3 and ts[1][0] == '(', 'malformed ' + name)
            inner, end = group(ts, 1)
            need(end == len(ts), 'trailing attribute syntax')
            if name == 'cfg':
                enabled = cfg(inner, active) and enabled
            else:
                args = split(inner)
                need(len(args) >= 2, 'cfg_attr needs guard and attribute')
                # Parse both arms even if inactive; unsupported syntax is not hidden.
                nested_enabled, nested = attributes(args[1:], active)
                if cfg(args[0], active):
                    enabled = nested_enabled and enabled
                    ordinary.extend(nested)
        else:
            need(name not in ('path', 'macro_use'), 'unsupported module attribute: ' + name)
            ordinary.append(ts)
    return enabled, ordinary


def items(text):
    ts = tokens(text)
    i, attrs, result, inner = 0, [], [], []
    while i < len(ts):
        if ts[i][0] == '#':
            i += 1
            is_inner = ts[i][0] == '!'
            i += int(is_inner)
            need(ts[i][0] == '[', 'malformed attribute')
            value, i = group(ts, i)
            (inner if is_inner else attrs).append(value)
            continue
        start = i
        while i < len(ts) and ts[i][0] not in ('{', ';'):
            if ts[i][0] in ('(', '['):
                _, i = group(ts, i)
            else:
                i += 1
        need(i < len(ts), 'unsupported unterminated top-level item: ' + spelling(ts[start:]))
        head, body, delim = ts[start:i], [], ts[i][0]
        # use trees contain braces in their header rather than an item body.
        words = [t for t, _ in head]
        if 'use' in words and delim == '{':
            _, end = group(ts, i)
            need(end < len(ts) and ts[end][0] == ';', 'unsupported use tree suffix')
            head = ts[start:end]
            i = end + 1
            delim = ';'
        elif delim == '{':
            body, i = group(ts, i)
        else:
            i += 1
        result.append({'head': head, 'body': body, 'attrs': attrs, 'delimiter': delim,
                       'line': ts[start][1]})
        attrs = []
    need(not attrs, 'attribute without item')
    return inner, result


def kind(item, word):
    ts = item['head']
    # Strip only item modifiers and visibility; never find a word in a type/expression.
    i = 0
    while i < len(ts):
        t = ts[i][0]
        if t == 'pub':
            i += 1
            if i < len(ts) and ts[i][0] == '(':
                _, i = group(ts, i)
        elif t in ('unsafe', 'async', 'const', 'default') and word == 'fn':
            i += 1
        else:
            break
    return i + 1 if i < len(ts) and ts[i][0] == word else None


def use_paths(ts, prefix=()):
    """Explicit use trees, nested groups, self and as; globs fail closed."""
    values = [t for t, _ in ts]
    need('*' not in values, 'unsupported glob import')
    if '{' in values:
        pos = values.index('{')
        inner, end = group(ts, pos)
        need(end == len(ts), 'unsupported use suffix')
        pre = prefix + tuple(t for t in values[:pos] if t != '::')
        return [p for arg in split(inner) for p in use_paths(arg, pre)]
    if 'as' in values:
        pos = values.index('as')
        need(pos == len(values)-2, 'unsupported alias syntax')
        alias = values[-1]
        values = values[:pos]
    else:
        alias = values[-1]
    path = prefix + tuple(t for t in values if t != '::')
    if path[-1] == 'self':
        path = path[:-1]
        if alias == 'self':
            alias = path[-1]
    need(path and all(re.fullmatch(r'[A-Za-z_]\w*', t) for t in path), 'unsupported use path')
    return [(alias, path)]


def absolute(path, module):
    result = list(module)
    path = list(path)
    if path[0] == 'crate':
        result, path = ['core'], path[1:]
    elif path[0] == 'core':
        result, path = [], path
    elif path[0] == 'self':
        path = path[1:]
    while path and path[0] == 'super':
        need(len(result) > 1, 'super escapes crate')
        result.pop()
        path.pop(0)
    return tuple(result + path)


KANI_ATTRIBUTES = {'proof', 'unwind', 'solver', 'should_panic', 'stub', 'stub_verified', 'proof_for_contract', 'requires', 'modifies', 'ensures', 'recursion', 'checked_with', 'replaced_with', 'asserted_with', 'recursion_check', 'modifies_wrapper', 'is_contract_generated', 'recursion_tracker', 'fn_marker', 'use_stub_set', 'stub_set'}

def attribute_identity(ts, module, aliases):
    path = resolve(ts, module, aliases)
    if path[:2] == ('core', 'kani'):
        need(len(path) == 3 and path[-1] in KANI_ATTRIBUTES, 'unresolved Kani attribute: ' + spelling(ts))
    elif ts and ts[0][0] in aliases:
        # Unsupported cross-module/reexported attribute identities must not disappear.
        need(False, 'unsupported aliased attribute identity: ' + spelling(ts) + ' -> ' + '::'.join(path))
    else:
        inert = {'inline','cold','allow','warn','deny','expect','doc','track_caller','derive','repr','must_use','unstable','stable','unsafe'}
        safe_wrapper = len(ts) == 3 and ts[0][0] == 'safety' and ts[1][0] == '::' and ts[2][0] in KANI_ATTRIBUTES
        need((len(ts) == 1 and ts[0][0] in inert) or safe_wrapper, 'unsupported target attribute or annotation: ' + spelling(ts))
    return path


class AliasMap(dict):
    """Explicit imports plus active local names; aliases never resolve by basename."""
    def __init__(self, module, declared=()):
        super().__init__()
        self.module = module
        self.declared = set(declared)


def resolve(ts, module, aliases):
    s = spelling(ts)
    need(re.fullmatch(r'[A-Za-z_]\w*(?:::[A-Za-z_]\w*)*', s),
         'unsupported/ambiguous target or attribute path: ' + s)
    path = tuple(s.split('::'))
    seen = set()
    if path[0] in aliases:
        seen.add(path[0])
        path = aliases[path[0]] + path[1:]
    else:
        path = absolute(path, module)
    while path[:len(module)] == module and len(path) > len(module):
        key = path[len(module)]
        if key not in aliases:
            if seen and isinstance(aliases, AliasMap):
                need(key in aliases.declared, 'unresolved alias target: ' + '::'.join(path))
            break
        if isinstance(aliases, AliasMap) and key in aliases.declared and aliases[key] == module + (key,):
            break  # exact self reexport of a declared item (e.g. macro_rules)
        need(key not in seen, 'cyclic alias: ' + key)
        seen.add(key)
        path = aliases[key] + path[len(module)+1:]
    return path


def validate_aliases(aliases):
    for name in aliases:
        resolve([(name, 0)], aliases.module, aliases)


def local_names(declarations, evaluate):
    names = set()
    for item in declarations:
        if not evaluate(item['attrs'])[0]:
            continue
        if len(item['head']) > 2 and item['head'][0][0] == 'macro_rules' and item['head'][1][0] == '!':
            names.add(item['head'][2][0])
        for word in ('fn', 'mod', 'struct', 'enum', 'union', 'type', 'trait', 'const', 'static'):
            pos = kind(item, word)
            if pos is not None:
                names.add(item['head'][pos][0])
    return names


BASE = 'library/core/src/'
CHAIN = [('lib.rs', 'slice'), ('slice/mod.rs', 'sort'),
         ('slice/sort/mod.rs', 'shared'), ('slice/sort/shared/mod.rs', 'smallsort'),
         ('slice/sort/shared/smallsort.rs', 'verify')]
VERIFY = 'slice/sort/shared/smallsort/verify.rs'
SM = ('core', 'slice', 'sort', 'shared', 'smallsort')
PROVIDERS = ('helper_contracts', 'sorting_s2_batch', 'sorting_s3_leaf', 'sorting_s3_2_leaf', 'sorting_bridge1')


def check(std, request):
    """Return seven source-hash-bound rows or raise GateError with coordinates."""
    std = Path(std)
    import s34_ordinary_contracts
    s34_ordinary_contracts.check(std, request)
    hashes = {}

    def read(rel):
        rel = BASE + rel
        data = (std / rel).read_bytes()
        hashes[rel] = hashlib.sha256(data).hexdigest()
        return items(data.decode())

    flags = shlex.split(request['flags']['RUSTFLAGS'])
    need(all(x.startswith('--cfg=') for x in flags), 'unsupported effective RUSTFLAGS')
    active = {'kani'} | {x[len('--cfg='):] for x in flags}
    need(len(request['rows']) == 7, 'expected all seven manifest rows')
    # Kani sets cfg(kani) for verify-std; no other target cfg is assumed here.
    # Unknown target cfgs in this bounded slice must be rejected, not guessed.
    known = active | {'kani_smallsort_controls', 'kani_smallsort_sorting',
                      'kani_smallsort_s2_assumed', 'kani_smallsort_s3_leaf'}
    def evaluate(attrs):
        for attr in attrs:
            def validate_cfg(ts):
                if ts and ts[0][0] in ('cfg', 'cfg_attr'):
                    expr, _ = group(ts, 1)
                    parts = split(expr)
                    if ts[0][0] == 'cfg_attr' and not any(
                            t in ('cfg', 'cfg_attr', 'stub_verified', 'proof_for_contract', 'stub')
                            for part in parts[1:] for t, _ in part):
                        return  # e.g. target-dependent allow(dead_code) cannot change gate
                    guard = parts[0] if ts[0][0] == 'cfg_attr' else expr
                    identifiers = [t for t, _ in guard if re.fullmatch(r'[A-Za-z_]\w*', t)]
                    need(all(t in known | {'all', 'any', 'not'} for t in identifiers),
                         'unknown cfg in bounded slice: ' + spelling(guard))
                    if ts[0][0] == 'cfg_attr':
                        for child in parts[1:]:
                            validate_cfg(child)
            validate_cfg(attr)
        return attributes(attrs, active)

    def module_active(rel, name):
        inner, declarations = read(rel)
        need(evaluate(inner)[0], 'inactive ancestor file: ' + rel)
        matches = [x for x in declarations if kind(x, 'mod') is not None and
                   x['head'][kind(x, 'mod')][0] == name]
        need(len(matches) == 1, 'missing/ambiguous module ' + rel + ':' + name)
        item = matches[0]
        need(item['delimiter'] == ';', 'unsupported inline module ' + name)
        need(evaluate(item['attrs'])[0], 'inactive module ' + rel + ':' + name)

    for rel, name in CHAIN:
        module_active(rel, name)
    for name in PROVIDERS:
        module_active(VERIFY, name)

    functions, registrations = {}, {}
    uses, ordinary_stubs = {}, {}
    for name in PROVIDERS:
        rel = 'slice/sort/shared/smallsort/verify/' + name + '.rs'
        module = SM + ('verify', name)
        inner, declarations = read(rel)
        need(evaluate(inner)[0], 'inactive provider file ' + rel)
        aliases = AliasMap(module, local_names(declarations, evaluate))
        for item in declarations:
            enabled, _ = evaluate(item['attrs'])
            pos = kind(item, 'use')
            if pos is not None and enabled:
                for alias, path in use_paths(item['head'][pos:]):
                    need(alias not in aliases, 'ambiguous use alias: ' + alias)
                    aliases[alias] = absolute(path, module)
        validate_aliases(aliases)
        for item in declarations:
            enabled, attrs = evaluate(item['attrs'])
            if not enabled:
                continue
            pos = kind(item, 'fn')
            if pos is None:
                need(not any(t in ('stub_verified', 'proof_for_contract') for t, _ in
                             item['head'] + item['body']),
                     'unsupported opaque registration/stub item at ' + rel + ':' + str(item['line']))
                continue
            need(not any(t in ('stub_verified', 'proof_for_contract') for t, _ in item['body']),
                 'unsupported body-local registration/stub at ' + rel + ':' + str(item['line']))
            need(item['head'][pos][0] not in aliases,
                 'ambiguous imported/local function: ' + item['head'][pos][0])
            fullname = '::'.join(module + (item['head'][pos][0],))
            need(fullname not in functions, 'ambiguous active function ' + fullname)
            functions[fullname] = {'file': BASE + rel, 'line': item['line']}
            uses[fullname], ordinary_stubs[fullname] = [], []
            for attr in attrs:
                words = [t for t, _ in attr]
                if '(' not in words:
                    continue
                p = words.index('(')
                path = attribute_identity(attr[:p], module, aliases)
                if path[:2] != ('core', 'kani'):
                    need(not any(t in ('stub_verified', 'proof_for_contract') for t in words),
                         'unresolved Kani attribute: ' + spelling(attr))
                    continue
                op = path[-1]
                if op not in ('stub_verified', 'proof_for_contract', 'stub'):
                    continue
                args, end = group(attr, p)
                need(end == len(attr), 'trailing Kani attribute syntax')
                parts = split(args)
                need(len(parts) == (2 if op == 'stub' else 1), 'wrong Kani attribute arity')
                target = '::'.join(resolve(parts[0], module, aliases))
                receipt = {'target': target, 'file': BASE + rel, 'line': attr[0][1]}
                if op == 'proof_for_contract':
                    registrations.setdefault(target, []).append({'harness': fullname, **receipt})
                elif op == 'stub_verified':
                    uses[fullname].append(receipt)
                else:
                    receipt['replacement'] = '::'.join(resolve(parts[1], module, aliases))
                    ordinary_stubs[fullname].append(receipt)

    # Resolve against declarations as well as aliases; never match by basename.
    _, smallsort_items = read('slice/sort/shared/smallsort.rs')
    targets = {'::'.join(SM + (x['head'][kind(x, 'fn')][0],)) for x in smallsort_items
               if kind(x, 'fn') is not None and evaluate(x['attrs'])[0]}
    all_uses = []
    for harness, refs in uses.items():
        for ref in refs:
            target = ref['target']
            need(target in targets, 'unresolved/foreign stub target ' + target)
            matching = registrations.get(target, [])
            need(matching, f"{ref['file']}:{ref['line']} {harness}: active stub_verified({target}) has no active matching proof_for_contract in same core crate/cfg")
            all_uses.append({'harness': harness, **ref, 'matching_pfc': matching})
    # Ordinary replacements need active exact declarations too, including uses
    # on compiled but unselected functions. They confer no PFC qualification.
    all_ordinary = []
    for harness, refs in ordinary_stubs.items():
        for ref in refs:
            need(ref['target'] in targets | functions.keys(),
                 'unresolved/foreign ordinary stub target ' + ref['target'])
            need(ref['replacement'] in functions,
                 'inactive/missing/foreign ordinary replacement ' + ref['replacement'])
            all_ordinary.append({'harness': harness, **ref,
                                 'replacement_location': functions[ref['replacement']]})
    rows = []
    for row in request['rows']:
        selector = row['source_qualified_selector']
        need(selector in functions, 'manifest root inactive/missing: ' + selector)
        rows.append({'id': row['id'], 'root': selector, 'effective_cfg': sorted(active),
                     'location': functions[selector],
                     'stub_verified': [x for x in all_uses if x['harness'] == selector],
                     'ordinary_stubs_no_pfc_required': [x for x in all_ordinary if x['harness'] == selector],
                     'status': 'STATIC_MATCH', 'proof_credit': 'NONE'})
    need(len({x['root'] for x in rows}) == 7, 'duplicate manifest roots')
    if 'cfg_pfc_source_sha256' in request:
        need(hashes == request['cfg_pfc_source_sha256'], 'cfg/PFC source-hash binding drift')
    return {'schema': 'ch8-s2-cfg-pfc-map-v1', 'source_sha': request['std_sha'],
            'source_tree': request['std_tree'], 'source_files_sha256': hashes,
            'registration_provider_slice': list(PROVIDERS), 'rows': rows,
            'checked_active_slice_uses': all_uses,
            'checked_active_ordinary_uses': all_ordinary, 'status': 'STATIC_PASS',
            'compilation': 'NOT_RUN', 'qualification_from_registration': False,
            'proof_credit': 'NONE'}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--std', type=Path, required=True)
    parser.add_argument('--request', type=Path, default=Path(__file__).with_name('CI-REQUEST.json'))
    args = parser.parse_args()
    print(json.dumps(check(args.std, json.loads(args.request.read_text())), indent=2))
