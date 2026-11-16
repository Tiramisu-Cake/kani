# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Bounded same-invocation metadata retention, without inferred proof bindings."""
import base64
import hashlib
import json
from pathlib import Path

NATIVE_BYTES_CAP = 8 * 1024 * 1024
NATIVE_FILES_CAP = 64
UNKNOWN = 'UNKNOWN_NOT_EXPORTED_BY_PINNED_PRODUCER'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def capture(dest, target, request, group, receipt):
    """Only read native metadata in this invocation's fresh target directory.

    The generated invocation key is not a rustc compilation/instance identity.
    Native bytes and export/property records are retained for offline w11; no
    terminal-name, ordinal, source-callsite or wrapper-name inference is made.
    """
    entries=[];errors=[];total=0;attempted=0;native_harnesses=[]
    if target is not None and target.is_dir():
        for path in target.rglob('*.kani-metadata.json'):
            if attempted >= NATIVE_FILES_CAP:
                errors.append('native metadata file count cap');break
            attempted+=1
            try:
                if path.is_symlink() or target.resolve() not in path.resolve().parents:
                    raise ValueError('native metadata path outside invocation directory')
                size=path.stat().st_size
                if total+size > NATIVE_BYTES_CAP:
                    raise ValueError('native metadata byte cap')
                with path.open('rb') as stream:
                    data=stream.read(NATIVE_BYTES_CAP-total+1)
                if total+len(data)>NATIVE_BYTES_CAP:
                    raise ValueError('native metadata byte cap')
                total+=len(data)
                try:
                    text=data.decode('utf-8');encoding='utf-8'
                    value=json.loads(text)
                    state='CAPTURED' if isinstance(value,dict) else 'WRONG_TYPE'
                except UnicodeError:
                    text=base64.b64encode(data).decode('ascii');encoding='base64'
                    state='INVALID_UTF8'
                except ValueError:
                    state='INVALID_OR_PARTIAL'
                if state!='CAPTURED':errors.append(str(path.relative_to(target))+': '+state)
                # Encapsulate even invalid/partial JSON as exact text. Never
                # silently discard suffixes, placeholders or producer fields.
                entries.append({'path':str(path.relative_to(target)),'bytes':len(data),
                                'sha256':digest(data),'state':state,'text':text,'encoding':encoding})
                if state=='CAPTURED':
                    for key in ('proof_harnesses','test_harnesses'):
                        harnesses=value.get(key,[])
                        if not isinstance(harnesses,list):
                            errors.append(str(path.relative_to(target))+': '+key+' wrong type')
                            continue
                        for index,harness in enumerate(harnesses):
                            if isinstance(harness,dict):
                                native_harnesses.append({'metadata_path':str(path.relative_to(target)),
                                    'pointer':'/'+key+'/'+str(index),'name':harness.get('pretty_name'),
                                    'crate':harness.get('crate_name')})
            except (OSError,ValueError,UnicodeError) as exc:
                errors.append(str(path)+': '+type(exc).__name__+': '+str(exc))
    artifacts=[]
    for name in ('export.json','properties.json','compile/receipt.json'):
        path=dest/name
        if path.is_file():
            hasher=hashlib.sha256();size=0
            with path.open('rb') as stream:
                for block in iter(lambda:stream.read(1024*1024),b''):
                    hasher.update(block);size+=len(block)
            artifacts.append({'path':name,'bytes':size,'sha256':hasher.hexdigest()})
        else:artifacts.append({'path':name,'state':'MISSING','bytes':None,'sha256':None})
    gaps={key:UNKNOWN for key in ('compilation_id','harness_instance','resolved_target',
          'contract_resolution','effective_contract_clauses','assertion_origin','property_origin',
          'cover_predicate_and_expansion','target_wrapper_property_edges')}
    rows=[]
    for row in group['rows']:
        crate=request.get('source_bindings',{}).get(row['id'],{}).get('crate')
        matches=[x for x in native_harnesses if x['name']==row['selector'] and x['crate']==crate]
        if len(matches)!=1:
            errors.append(row['id']+': missing/nonunique exact native selector/crate record')
        rows.append({'group_id':group['id'],'row_id':row['id'],'variant':row['variant'],
                     'crate':crate,'harness':row['selector'],'mode':row['mode'],
                     'native_harness_records':matches,
                     'native_record_scope':'EXACT_SELECTOR_CRATE_WITHIN_INVOCATION_ONLY',
                     'binding_gaps':gaps})
    document={'schema':'ch8-s1-07-binding-metadata-v1',
              'state':'INCOMPLETE' if errors else 'CAPTURED_AVAILABLE_FIELDS',
              'invocation_id':receipt['invocation_id'],
              'identity_scope':'RUNNER_INVOCATION_DIRECTORY_NOT_COMPILER_INSTANCE',
              'compilation_id':None,'compiler_identity_status':UNKNOWN,
              'group_id':group['id'],'variant':group['variant'],
              'std_sha':receipt['std_sha'],'tool_sha':receipt['tool_sha'],
              'request_sha256':receipt['request_sha256'],
              'requirements_sha256':request.get('binding_metadata_requirements_sha256'),
              'source_under_test':receipt.get('source_under_test'),
              'source_bindings':{row['id']:request.get('source_bindings',{}).get(row['id']) for row in group['rows']},
              'argv':receipt['argv'],'effective_cfg':receipt.get('effective_cfg'),
              'unwind':group['unwind'],'expected_flags_and_checks':request.get('flags'),
              'configuration_sha256':digest(json.dumps({'flags':request.get('flags'),
                  'cfg':receipt.get('effective_cfg'),'argv':receipt['argv']},sort_keys=True).encode()),
              'execution':receipt.get('execution'),'execution_exception':receipt.get('execution_exception'),
              'original_exception':receipt.get('original_exception'),
              'source_before':receipt.get('source_before'),'source_after':receipt.get('source_after'),
              'binaries_before':receipt.get('tool_fingerprints_before'),
              'binaries_after':receipt.get('tool_fingerprints_after'),
              'artifacts':artifacts,'native_metadata':entries,
              'native_metadata_state':'CAPTURED' if entries else 'MISSING_OR_NOT_PRODUCED',
              'rows':rows,
              'errors':errors,'qualified_acceptance':'PENDING_OFFLINE_W11','proof_credit':'NONE'}
    data=(json.dumps(document,indent=2,sort_keys=True)+'\n').encode()
    path=dest/'binding-metadata.json';path.write_bytes(data)
    return {'path':path.name,'bytes':len(data),'sha256':digest(data),'state':document['state'],
            'invocation_id':receipt['invocation_id'],'native_files':len(entries),
            'native_bytes':total,'errors':errors,'binding_status':UNKNOWN,'proof_credit':'NONE'}
