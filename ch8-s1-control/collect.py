#!/usr/bin/env python3
"""Combine structured matrix receipts; never grants proof credit or opens logs."""
import argparse
import base64
import gzip
import hashlib
from io import BytesIO
import pack_evidence
import rich_evidence
import json
from pathlib import Path
import runner as r


def read_bytes(path):
    if path.is_file():
        if path.stat().st_size > r.ARTIFACT_CAP_BYTES:
            raise r.RunnerError('oversize receipt')
        data = path.read_bytes()
    else:
        root = next((p for p in path.parents if (p / pack_evidence.NAME).is_file()), None)
        if root is None:
            raise r.RunnerError('missing structured receipt')
        archive = root / pack_evidence.NAME
        if archive.stat().st_size > pack_evidence.COMPRESSED_CAP:
            raise r.RunnerError('oversize compact artifact')
        with gzip.open(archive, 'rb') as stream:
            raw = stream.read(pack_evidence.UNCOMPRESSED_CAP + 1)
        if len(raw) > pack_evidence.UNCOMPRESSED_CAP:
            raise r.RunnerError('oversize decompressed artifact')
        doc = json.loads(raw)
        if doc.get('schema') != 'ch8-s1-05-artifact-v1' or doc.get('state') != 'PACKAGED':
            raise r.RunnerError('incomplete compact artifact')
        entry = doc['files'][str(path.relative_to(root))]
        if entry.get('encoding','utf-8')=='utf-8':
            data=entry['text'].encode('utf-8')
        elif entry.get('encoding')=='base64':
            data=base64.b64decode(entry['text'],validate=True)
        else:
            raise r.RunnerError('unknown compact entry encoding')
        if len(data) != entry['bytes'] or hashlib.sha256(data).hexdigest() != entry['sha256']:
            raise r.RunnerError('compact entry integrity mismatch')
    return data


def read(path):
    value = json.loads(read_bytes(path))
    if not isinstance(value, dict):
        raise r.RunnerError('receipt must be an object')
    return value


def collect(roots,request):
    import r5_profile
    if r5_profile.enabled(request):
        import r5_campaign
        return r5_campaign.collect(roots,request)
    return legacy_collect(roots,request)


def legacy_collect(roots,request):
    groups={g['id']:g for g in r.group_rows(request['rows'],request['execution_groups'])}
    expected_identity={key:request[key] for key in ('std_sha','std_tree','tool_sha','tool_tree')}
    request_hash=r.sha256(r.REQUEST_PATH)
    seen=set(); observations={}
    for root in roots:
        terminal=read(root/'receipt.json')
        if (any(terminal.get(k)!=v for k,v in expected_identity.items()) or
                terminal.get('request_sha256')!=request_hash):
            raise r.RunnerError('matrix terminal identity mismatch')
        selected=terminal.get('selected_groups')
        if (not isinstance(selected,list) or not selected or any(not isinstance(x,str) for x in selected)
                or len(set(selected))!=len(selected) or not set(selected).issubset(groups)
                or seen.intersection(selected)):
            raise r.RunnerError('duplicate or invalid matrix partition')
        rows=terminal.get('rows')
        if not isinstance(rows,list) or any(not isinstance(x,dict) for x in rows):
            raise r.RunnerError('invalid terminal rows')
        byid={x.get('id'):x for x in rows}
        if len(byid)!=len(rows):raise r.RunnerError('duplicate terminal row')
        for gid in selected:
            group=groups[gid];receipt=read(root/'groups'/gid/'receipt.json')
            before,after=receipt.get('source_before'),receipt.get('source_after')
            expected_source={**expected_identity,'changed_file_sha256':request['changed_file_sha256']}
            intact=(receipt.get('request_sha256')==request_hash and before==expected_source and after==expected_source
                    and receipt.get('state')=='COMPLETE'
                    and r.fingerprints_match(receipt.get('tool_fingerprints_before'),
                                             receipt.get('tool_fingerprints_after'))
                    and not receipt.get('snapshot_errors'))
            if intact:
                ref=receipt.get('binding_metadata')
                if (not isinstance(ref,dict) or ref.get('state')!='CAPTURED_AVAILABLE_FIELDS'
                        or ref.get('errors') or ref.get('invocation_id')!=receipt.get('invocation_id')):
                    intact=False
            if intact:
                data=read_bytes(root/'groups'/gid/'binding-metadata.json')
                metadata=json.loads(data)
                if (len(data)!=ref.get('bytes') or hashlib.sha256(data).hexdigest()!=ref.get('sha256')
                        or not isinstance(metadata,dict) or metadata.get('group_id')!=gid
                        or metadata.get('invocation_id')!=receipt.get('invocation_id')
                        or metadata.get('request_sha256')!=request_hash
                        or metadata.get('variant')!=group['variant']
                        or metadata.get('state')!='CAPTURED_AVAILABLE_FIELDS' or metadata.get('errors')
                        or metadata.get('std_sha')!=request['std_sha'] or metadata.get('tool_sha')!=request['tool_sha']
                        or metadata.get('argv')!=receipt.get('argv')
                        or metadata.get('effective_cfg')!=receipt.get('effective_cfg')
                        or metadata.get('source_under_test')!=receipt.get('source_under_test')
                        or metadata.get('binaries_before')!=receipt.get('tool_fingerprints_before')
                        or metadata.get('binaries_after')!=receipt.get('tool_fingerprints_after')):
                    raise r.RunnerError('binding metadata identity/digest mismatch')
                expected_rows=[(gid,row['id'],row['selector'],row['variant'],
                                request['source_bindings'][row['id']]['crate'],row['mode'])
                               for row in group['rows']]
                actual_rows=[(x.get('group_id'),x.get('row_id'),x.get('harness'),x.get('variant'),
                              x.get('crate'),x.get('mode'))
                             for x in metadata.get('rows',[])]
                if actual_rows!=expected_rows:
                    raise r.RunnerError('binding metadata row mismatch')
                native=metadata.get('native_metadata');native_refs=[]
                if (metadata.get('native_metadata_state')!='CAPTURED' or
                        not isinstance(native,list) or not native):
                    raise r.RunnerError('missing native metadata inventory')
                for entry in native:
                    if (not isinstance(entry,dict) or entry.get('state')!='CAPTURED'
                            or entry.get('encoding')!='utf-8' or not isinstance(entry.get('text'),str)):
                        raise r.RunnerError('invalid native metadata entry')
                    raw=entry['text'].encode('utf-8')
                    if len(raw)!=entry.get('bytes') or hashlib.sha256(raw).hexdigest()!=entry.get('sha256'):
                        raise r.RunnerError('native metadata digest mismatch')
                    value=json.loads(raw)
                    if not isinstance(value,dict):raise r.RunnerError('native metadata must be object')
                    for key in ('proof_harnesses','test_harnesses'):
                        harnesses=value.get(key,[])
                        if not isinstance(harnesses,list):raise r.RunnerError('native harnesses wrong type')
                        for index,harness in enumerate(harnesses):
                            if isinstance(harness,dict):
                                native_refs.append({'metadata_path':entry['path'],'pointer':'/'+key+'/'+str(index),
                                    'name':harness.get('pretty_name'),'crate':harness.get('crate_name')})
                for row in metadata['rows']:
                    matches=[x for x in native_refs if x['name']==row['harness'] and x['crate']==row['crate']]
                    if len(matches)!=1 or row.get('native_harness_records')!=matches:
                        raise r.RunnerError('missing/nonunique native harness binding')
                artifacts=metadata.get('artifacts')
                if (not isinstance(artifacts,list) or len(artifacts)!=3
                        or any(not isinstance(item,dict) for item in artifacts)
                        or {item.get('path') for item in artifacts}!=
                           {'export.json','properties.json','compile/receipt.json'}):
                    raise r.RunnerError('binding metadata artifact inventory mismatch')
                for item in artifacts:
                    if item.get('path') not in ('export.json','properties.json','compile/receipt.json'):
                        raise r.RunnerError('binding metadata artifact path mismatch')
                    raw=read_bytes(root/'groups'/gid/item['path'])
                    if len(raw)!=item.get('bytes') or hashlib.sha256(raw).hexdigest()!=item.get('sha256'):
                        raise r.RunnerError('binding metadata artifact digest mismatch')
                stock=read(root/'groups'/gid/'export.json')
                rich=read(root/'groups'/gid/'properties.json')
                decoder=rich_evidence.RegularEvidence(receipt['selectors'], Path('/'))
                decoder.records={h['name']:h['properties'] for h in rich['harnesses']}
                decoder.finished=True
                if rich.get('state') != 'COMPLETE':
                    raise r.RunnerError('incomplete rich inventory')
                decoder.validate(stock)
                exceptions=decoder.location_exceptions()
                if (rich.get('location_exceptions') != exceptions or
                        receipt.get('location_exceptions') != exceptions):
                    raise r.RunnerError('location exception receipt mismatch')
            for row in group['rows']:
                observed=byid.get(row['id'])
                if (not isinstance(observed,dict) or observed.get('selector')!=row['selector']
                        or observed.get('group')!=gid or observed.get('mode')!=row['mode']
                        or observed.get('variant')!=row['variant']):
                    raise r.RunnerError('matrix row identity mismatch')
                observations[row['id']]=observed if intact else {**observed,'outcome':'UNKNOWN','reason':'group source/completion/binary snapshot mismatch'}
        seen.update(selected)
    missing=[gid for gid in groups if gid not in seen]
    unions=[r.aggregate_replacement_union(u,request['rows'],observations) for u in request['replacement_unions']]
    return {'state':'INCOMPLETE_MATRIX' if missing else 'COLLECTED_OBSERVATIONS_PENDING_REVIEW',
            **expected_identity,'request_sha256':request_hash,'missing_groups':missing,
            'replacement_unions':unions,'rows':[observations.get(row['id'],{'id':row['id'],'status':'NOT_RUN','outcome':'UNKNOWN'}) for row in request['rows']],
            'proof_credit':'NONE','qualified_acceptance':'PENDING_INDEPENDENT_BINDING_AND_EXCEPTION_REVIEW'}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,action='append',required=True)
    parser.add_argument('--out',type=Path,required=True);args=parser.parse_args()
    result=collect(args.root,r.load_request());r._write_json(args.out,result)
    print(json.dumps({'state':result['state'],'missing_groups':result['missing_groups'],'proof_credit':'NONE'}))
