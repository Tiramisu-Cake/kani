# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Finite prebuild lexical-path audit; no Rust typing, method, expansion or MIR claim.

Inventory is derived from the SHA-pinned r3 fixture (all new/changed bodies).
Every static call in every branch is visited. Original-copy bindings are compared
by full identity after the declared seam renames. Provider files are hash-pinned;
associated paths establish visible type roots and explicit declaration anchors,
not impl selection. Macros and dot dispatch are reported separately.
"""
import hashlib
import re
import shlex
from pathlib import Path
import cfg_pfc as c
import s2_correspondence as correspondence

MOD = c.SM + ('verify', 'sorting_s2_batch')
BATCH = correspondence.BATCH
BASE = c.BASE
# Explicit external provider, not an unbound-name exception: emitted by the exact
# kani_lib!(core) in core lib.rs and the already pinned stock Kani macro provider.
KANI_TOOL = '0aac16ef62da9e9d5645782d458593e5d78143ba'
KANI_PROVIDER = 'library/kani_core/src/lib.rs'
KANI_PROVIDER_SHA256 = 'fd4936db12f998df2419b9e6240f9171643f8287654840596ea2db40cfd76bc0'
KEYWORDS = {'if', 'while', 'for', 'match', 'loop', 'return', 'unsafe', 'const', 'fn'}
COPIES = {
    'sort13_fault_network': ('sort13_optimal', {'swap_if_less': 's2_swap_seam'}),
    'general_fault_copy': ('small_sort_general', {'small_sort_general_with_scratch': 'general_fault_scratch'}),
    'general_fault_scratch': ('small_sort_general_with_scratch', {'bidirectional_merge': 's2_merge_seam'}),
}


def functions(text):
    return {i['head'][c.kind(i, 'fn')][0]: i for i in c.items(text)[1] if c.kind(i, 'fn') is not None}


def delta_inventory(text):
    old = (Path(__file__).parent/'fixtures/s2-r3-batch.rs.txt').read_text()
    c.need(hashlib.sha256(old.encode()).hexdigest() == correspondence.R3, 'name gate: r3 fixture drift')
    a, b = functions(old), functions(text)
    return {n: i for n, i in b.items() if n not in a or any(
        c.spelling(i[k]) != c.spelling(a[n][k]) for k in ('head', 'body'))}


def angle(ts, start):
    depth, j = 1, start+1
    while j < len(ts) and depth:
        depth += (ts[j][0] == '<') - (ts[j][0] == '>' and ts[j-1][0] != '-')
        j += 1
    c.need(depth == 0, 'name gate: unsupported generic arguments')
    return j


def call_paths(ts):
    """Extract supported paths; unwrap balanced callable parentheses iteratively.

    Group/index/block/call-result expressions used as callees must be handled
    explicitly or rejected. This is a token guard, not Rust expression typing.
    Dot method calls retain their existing dispatch-only inventory.
    """
    pairs, stack = {}, []
    closing = {')': '(', ']': '[', '}': '{'}
    for at, (token, line) in enumerate(ts):
        if token in ('(', '[', '{'):
            stack.append(at)
        elif token in closing:
            c.need(stack and ts[stack[-1]][0] == closing[token],
                   'name gate: unbalanced callable delimiter at line ' + str(line))
            pairs[at] = stack.pop()
    c.need(not stack, 'name gate: unterminated callable delimiter')
    covered = set()
    i = 0
    while i < len(ts):
        t, line = ts[i]
        if t == '<' and (i == 0 or ts[i-1][0] != '::'):
            # A required UFCS path is outside this finite resolver.
            end = next((j for j in range(i+1,len(ts)) if ts[j][0] in ('>',';','{')), None)
            c.need(end is None or ts[end][0] != '>' or end+1 >= len(ts) or ts[end+1][0] != '::', 'name gate: unsupported qualified type path')
        if not t.isidentifier() or t in KEYWORDS or (i > 1 and ts[i-1][0] == '::' and (ts[i-2][0].isidentifier() or ts[i-2][0] == '>')):
            i += 1; continue
        path, j = [t], i+1
        while j < len(ts) and ts[j][0] == '::':
            j += 1
            if j < len(ts) and ts[j][0] == '<':
                start = j
                j = angle(ts, j)
                c.need(not any(t in ('(', '{') for t,_ in ts[start+1:j-1]), 'name gate: unsupported generic expression call')
                if j >= len(ts) or ts[j][0] != '::': break
                j += 1
            c.need(j < len(ts) and ts[j][0].isidentifier(), 'name gate: unsupported static path')
            path.append(ts[j][0]); j += 1
        # Strip any number of complete parentheses around this exact path.
        # Include an already-supported leading :: in the grouping boundary.
        begin = i-1 if i and ts[i-1][0] == '::' else i
        end = j
        while end < len(ts) and ts[end][0] == ')' and begin > 0 and pairs.get(end) == begin-1:
            begin -= 1
            end += 1
        if end > j and end < len(ts) and ts[end][0] == '(':
            # f(arg)() is invocation of a call result, not invocation of arg.
            previous = ts[begin-1][0] if begin else None
            c.need(previous is None or not (previous.isidentifier() and previous not in KEYWORDS
                   or previous in (')', ']', '}', '>', '!')),
                   'name gate: unsupported call-result/parenthesized callable expression at line ' + str(line))
            covered.add(end-1)
            yield tuple(path), line, 'STATIC', i
        elif j < len(ts) and ts[j][0] == '(':
            yield tuple(path), line, 'METHOD' if i and ts[i-1][0] == '.' else 'STATIC', i
        elif j < len(ts) and ts[j][0] == '!':
            yield tuple(path), line, 'MACRO', i
        i = max(i+1, j)
    # No required call ending in a group/index/block may disappear from both
    # the static and dispatch inventories. Reject unsupported expression forms.
    for at in range(1, len(ts)):
        if ts[at][0] == '(' and ts[at-1][0] in (')', ']', '}'):
            c.need(at-1 in covered,
                   'name gate: unsupported callable expression ending ' + ts[at-1][0]
                   + ' at line ' + str(ts[at][1]))


def value_scopes(ts):
    """Simple let bindings, with exact enclosing block lifetime and ordering.

    This is lexical presence only, not a claim that the value has a callable type.
    Unsupported binding patterns fail closed when used as required call roots.
    """
    result = []
    def walk(start, end):
        i = start
        while i < end:
            t = ts[i][0]
            c.need(t not in ('use','fn','#'), 'name gate: unsupported body-local item/attribute')
            if t == 'let':
                j = i+1
                if ts[j][0] == 'mut': j += 1
                if ts[j][0].isidentifier():
                    name = ts[j][0]; k = j+1
                    while k < end and ts[k][0] != ';':
                        if ts[k][0] in ('(', '[', '{'): _, k = c.group(ts,k)
                        else: k += 1
                    c.need(k < end, 'name gate: unsupported let binding')
                    result.append((name,k+1,end))
            if t == '{':
                _, stop = c.group(ts,i); walk(i+1,stop-1); i = stop
            else: i += 1
    walk(0,len(ts))
    return result


def visible(item, owner, consumer):
    h = item['head']
    if not h or h[0][0] != 'pub':
        return consumer[:len(owner)] == owner
    if len(h) < 2 or h[1][0] != '(':
        return True
    restriction, _ = c.group(h, 1)
    words = c.spelling(restriction)
    if words == 'crate': boundary = ('core',)
    elif words == 'super': boundary = owner[:-1]
    elif words == 'self': boundary = owner
    elif words.startswith('in'):
        boundary = c.absolute(tuple(t for t, _ in restriction[1:] if t != '::'), owner)
    else: raise c.GateError('name gate: unsupported visibility ' + words)
    return consumer[:len(boundary)] == boundary


def check(std, request):
    std = Path(std)
    active = {'kani'} | {x[6:] for x in shlex.split(request['flags']['RUSTFLAGS'])}
    c.need(len(request['rows']) == 11, 'name gate: expected ALL11 contexts')
    hashes, modules = {}, {}
    def read(rel):
        data = (std/rel).read_bytes(); hashes[rel] = hashlib.sha256(data).hexdigest()
        return data.decode()
    def evaluate(attrs):
        # Relevant cfg in the bounded dependency slice is fail closed.
        def validate(ts):
            if not ts or ts[0][0] not in ('cfg', 'cfg_attr'): return
            args, _ = c.group(ts, 1); parts = c.split(args)
            if ts[0][0] == 'cfg_attr' and all(p and p[0][0] in {'allow','warn','deny','inline','cold'} for p in parts[1:]): return
            guard = parts[0] if ts[0][0] == 'cfg_attr' else args
            ids = {t for t,_ in guard if t.isidentifier()}
            c.need(ids <= active | {'all','any','not','kani_smallsort_controls','kani_smallsort_sorting','kani_smallsort_s2_assumed'}, 'name gate: unknown cfg '+c.spelling(guard))
            if ts[0][0] == 'cfg_attr':
                for p in parts[1:]: validate(p)
        for a in attrs: validate(a)
        return c.attributes(attrs, active)
    def load(module, rel):
        text = read(rel); inner, items = c.items(text)
        c.need(evaluate(inner)[0], 'name gate: inactive module '+rel)
        enabled = [i for i in items if evaluate(i['attrs'])[0]]
        aliases = c.AliasMap(module, c.local_names(enabled, evaluate)); decls = {}
        for i in enabled:
            pos = c.kind(i, 'use')
            if pos is not None:
                for alias, target in c.use_paths(i['head'][pos:]):
                    c.need(alias not in aliases, 'name gate: ambiguous alias '+alias)
                    aliases[alias] = c.absolute(target, module)
            for word in ('fn','struct','union','enum','type','mod','trait','const'):
                pos = c.kind(i, word)
                if pos is not None:
                    name = i['head'][pos][0]
                    c.need(name not in decls, 'name gate: ambiguous declaration '+name)
                    decls[name] = (word, i)
        c.validate_aliases(aliases)
        modules[module] = (aliases, decls, rel)
        return text
    # Follow actual active ancestor declarations, including the sibling model
    # provider. A same-named file does not establish a visible module binding.
    owner = ('core',)
    for rel, name in c.CHAIN + [(c.VERIFY, 'sorting_s2_batch'), (c.VERIFY, 'sorting_model')]:
        declarations = c.items(read(BASE+rel))[1]
        matches = [i for i in declarations if c.kind(i,'mod') is not None and i['head'][c.kind(i,'mod')][0] == name]
        c.need(len(matches) == 1 and matches[0]['delimiter'] == ';' and evaluate(matches[0]['attrs'])[0], 'name gate: inactive/missing module '+rel+':'+name)
        current_owner = c.SM+('verify',) if rel == c.VERIFY else owner
        c.need(visible(matches[0],current_owner,MOD), 'name gate: invisible module '+name)
        if rel != c.VERIFY: owner += (name,)
    text = load(MOD, BATCH)
    original = load(c.SM, correspondence.SMALLSORT)
    load(c.SM+('verify','sorting_model'), BASE+'slice/sort/shared/smallsort/verify/sorting_model.rs')
    # Hash-pinned provider/reexport paths. Avoid parsing unrelated Rust bodies.
    provider_specs = {
        ('core','mem','size_of'): ('mem/mod.rs', 'pub const fn size_of<T>()'),
        ('core','mem','forget'): ('mem/mod.rs', 'pub const fn forget<T>'),
        ('core','mem','MaybeUninit','uninit'): ('mem/maybe_uninit.rs', 'pub const fn uninit()'),
        ('core','ptr','copy_nonoverlapping'): ('ptr/mod.rs', 'pub const unsafe fn copy_nonoverlapping<T>'),
        ('core','slice','from_raw_parts'): ('slice/raw.rs', "pub const unsafe fn from_raw_parts<'a, T>"),
        ('core','slice','from_raw_parts_mut'): ('slice/raw.rs', "pub const unsafe fn from_raw_parts_mut<'a, T>"),
        ('core','intrinsics','abort_immediate'): ('intrinsics/mod.rs', 'pub const fn abort_immediate()'),
    }
    providers = {}
    for path, (rel, anchor) in provider_specs.items():
        src = read(BASE+rel)
        c.need(c.spelling(c.tokens(anchor)) in c.spelling(c.tokens(src)), 'name gate: missing provider '+ '::'.join(path))
        providers[path] = {'file':BASE+rel, 'declaration_anchor':anchor, 'kind':'PINNED_PUBLIC_PROVIDER'}
    mem, sl, lib = read(BASE+'mem/mod.rs'), read(BASE+'slice/mod.rs'), read(BASE+'lib.rs')
    for fragment, src in [('pub use maybe_uninit::MaybeUninit;',mem), ('pub use raw::{from_raw_parts, from_raw_parts_mut};',sl), ('kani_core::kani_lib!(core);',lib)]:
        c.need(c.spelling(c.tokens(fragment)) in c.spelling(c.tokens(src)), 'name gate: provider/reexport route drift '+fragment)
    for module in ('mem','slice','ptr','intrinsics'):
        c.need('pubmod'+module+';' in c.spelling(c.tokens(lib)), 'name gate: missing crate module '+module)
    kani_invocations = [i for i in c.items(lib)[1] if c.spelling(i['head']) == 'kani_core::kani_lib!(core)']
    c.need(len(kani_invocations) == 1 and evaluate(kani_invocations[0]['attrs'])[0], 'name gate: inactive/missing Kani provider invocation')
    c.need(request['tool_sha'] == KANI_TOOL, 'name gate: external Kani provider drift')
    providers[('core','kani','any')] = {'kind':'EXPLICIT_PINNED_MACRO_PROVIDER','tool':KANI_TOOL,
        'file':KANI_PROVIDER,'sha256':KANI_PROVIDER_SHA256,'anchor':'pub fn any<T: Arbitrary>() -> T',
        'limit':'macro output not expanded; provider explicit, no typing claim'}
    prelude = read(BASE+'prelude/v1.rs')
    c.need('pubusecrate::mem::{align_of,align_of_val,size_of,size_of_val};' in c.spelling(c.tokens(prelude)), 'name gate: pinned size_of prelude route drift')
    def binding(path, module):
        aliases, decls, rel = modules[module]
        full = c.resolve([(t,0) for n,p in enumerate(path) for t in ((('::',p) if n else (p,)))], module, aliases)
        if len(path) == 1 and path[0] == 'size_of' and path[0] not in aliases and path[0] not in decls:
            full = ('core','mem','size_of')
        if full in providers: return full, providers[full]
        # Associated paths: resolve the exact visible type root. Impl selection
        # is outside this lexical gate and is always recorded as such.
        assoc = None
        if full[-1] == 'new' and full[:-1] == c.SM+('verify','sorting_model','KeyLess'):
            assoc, full = full[-1], full[:-1]
        owner, name = full[:-1], full[-1]
        c.need(owner in modules and name in modules[owner][1], 'name gate: unresolved static path '+ '::'.join(full))
        word, item = modules[owner][1][name]
        c.need(visible(item,owner,module), 'name gate: invisible static path '+ '::'.join(full))
        c.need(word in ('fn','struct','union','type','enum'), 'name gate: unsupported callable declaration '+ '::'.join(full))
        rec = {'kind':'LOCAL_FN' if owner == module and word == 'fn' else 'IMPORTED_DECLARATION',
               'file':modules[owner][2], 'line':item['line'], 'declaration_kind':word,
               'visibility':c.spelling(item['head'][:c.kind(item,word)-1])}
        if assoc:
            rec.update(kind='VISIBLE_TYPE_ASSOCIATED_PATH', member=assoc, limit='type root visible; impl/method dispatch NOT_CHECKED')
            full += (assoc,)
        return full, rec
    def audit(name, item, module):
        h = item['head']; pos = c.kind(item,'fn')+1
        if pos < len(h) and h[pos][0] == '<': pos = angle(h,pos)
        c.need(pos < len(h) and h[pos][0] == '(', 'name gate: unsupported signature '+name)
        params, _ = c.group(h,pos)
        # A parameter can shadow a module item; report callable values explicitly.
        values = {a[0][0] for a in c.split(params) if len(a)>1 and a[1][0] == ':'}
        calls, limits = [], []
        local_values = value_scopes(item['body'])
        for path, line, kind, at in call_paths(item['body']):
            if kind != 'STATIC':
                limits.append({'path':'::'.join(path),'line':line,'kind':kind,'resolution':'NOT_CHECKED_METHOD_OR_MACRO_DISPATCH'}); continue
            if len(path) == 1 and (path[0] in values or any(n == path[0] and start <= at < end for n,start,end in local_values)):
                calls.append({'path':path[0],'line':line,'binding':{'kind':'PARAMETER_CALLABLE' if path[0] in values else 'LOCAL_VALUE_CALLABLE','scope':name}}); continue
            full, rec = binding(path,module)
            calls.append({'path':'::'.join(path),'line':line,'identity':'::'.join(full),'binding':rec})
        return {'function':name,'line':item['line'],'static_calls':calls,'dispatch_outside_scope':limits}
    inventory = delta_inventory(text)
    records = [audit(n,i,MOD) for n,i in inventory.items()]
    byname = {r['function']:r for r in records}
    for copy, (source, renames) in COPIES.items():
        ref = audit(source, functions(original)[source], c.SM)
        expected = []
        for call in ref['static_calls']:
            full = call.get('identity')
            if full and full.split('::')[-1] in renames:
                full = '::'.join(MOD+(renames[full.split('::')[-1]],))
            expected.append(full or call['path'])
        actual = [x.get('identity',x['path']) for x in byname[copy]['static_calls']]
        c.need(actual == expected, 'name gate: relocated binding differs from original '+copy)
        byname[copy]['original_binding_correspondence'] = 'EXACT_FULL_IDENTITIES_AFTER_DECLARED_SEAM_RENAMES'
    if 'lexical_source_sha256' in request:
        c.need(hashes == request['lexical_source_sha256'], 'name gate: source/provider hash drift')
    return {'status':'STATIC_PASS','schema':'ch8-s2-lexical-binding-v1',
        'source_sha':request['std_sha'],'source_tree':request['std_tree'],
        'inventory_derivation':'all added or head/body-changed functions relative to SHA-pinned r3 fixture',
        'functions':records,'source_files_sha256':hashes,
        'contexts':[{'row':r['id'],'effective_cfg':sorted(active),'functions_checked':len(records),'all_branches':True} for r in request['rows']],
        'limits':['lexical paths only; no type, generic bound, borrow, method, macro expansion, MIR or compilation validation',
                  'body-local items/imports and unsupported paths fail closed; callable parameters are lexical only'],
        'native_compile':'NOT_RUN','proof_credit':'NONE'}
