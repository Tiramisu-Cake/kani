#!/usr/bin/env python3
"""Frozen, bounded runner for the q-pilot research campaign. Never grants proof credit."""
from __future__ import annotations
import argparse, hashlib, json, os, re, shutil, signal, subprocess, sys, tempfile, time, uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO / "ch8-s1-control"))
import runner as stock_runner
import rich_evidence
import s3_runtime

REQ_PATH = HERE / "CI-REQUEST.json"
RESULT = "q-pilot-results.json"
TOOL_SHA = "0aac16ef62da9e9d5645782d458593e5d78143ba"
TOOL_TREE = "9d8bc9312bf955ef126d32b819b3cd0ed105ed2b"
PENDING = "PENDING_"

class PilotError(RuntimeError): pass

def digest(path: Path) -> str:
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda:f.read(1024*1024), b''): h.update(chunk)
    return h.hexdigest()

def atomic(path: Path, value):
    path=Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    data=(json.dumps(value,indent=2,sort_keys=True,ensure_ascii=False)+'\n').encode()
    cap=268435456 if path.name==RESULT else None
    if cap is not None and len(data)>cap:
        reduced=json.loads(json.dumps(value))
        reduced['result_truncation']={'state':'PARTIAL','original_bytes':len(data),'limit_bytes':cap,
                                      'reason':'structured inventory exceeded bounded campaign record'}
        for root in reversed(reduced.get('roots',[])):
            props=root.get('inventory',{}).get('properties') if isinstance(root.get('inventory'),dict) else None
            if props is not None:
                raw=json.dumps(props,sort_keys=True,ensure_ascii=False).encode()
                root['inventory']['truncated_properties']={'count':len(props) if isinstance(props,list) else None,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
                root['inventory']['properties']=None;root['inventory']['state']='PARTIAL';root['control']={'match':'UNKNOWN','reason':'bounded result truncation'}
                reduced['roots']=reduced.get('roots',[])
                data=(json.dumps(reduced,indent=2,sort_keys=True,ensure_ascii=False)+'\n').encode()
                if len(data)<=cap: break
        if len(data)>cap: raise PilotError('structured result exceeds 256 MiB cap after bounded truncation')
        value.clear();value.update(reduced)
    tmp=path.with_name(path.name+'.tmp')
    with tmp.open('xb') as f: f.write(data); f.flush(); os.fsync(f.fileno())
    os.replace(tmp,path)
    fd=os.open(path.parent,os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)

def load_request():
    try: r=json.loads(REQ_PATH.read_text())
    except Exception as e: raise PilotError(f'request invalid: {type(e).__name__}: {e}')
    if not isinstance(r,dict) or r.get('schema')!='ch8-q-pilot-request-v1': raise PilotError('request schema')
    ids=['P-1','P-2','P-3','P-4','P-5a','P-5b','P-5c']
    if len(r.get('roots',[]))!=7 or [x.get('id') for x in r['roots']] != ids:
        raise PilotError('frozen root order mismatch')
    selectors=['slice::sort::shared::smallsort::verify::sorting_q_pilot::p1_swap_u8_v34_q_any',
      'slice::sort::shared::smallsort::verify::sorting_q_pilot::p2_sort13_u8_b01_len17_q_any',
      'slice::sort::shared::smallsort::verify::sorting_q_pilot::p3_insert_u8_b01_rel1_16_q_any',
      'slice::sort::shared::smallsort::verify::sorting_q_pilot::p4_network_u8_b01_n17_q_any',
      'slice::sort::shared::smallsort::verify::sorting_q_controls::p5_swap_false_or_q_any',
      'slice::sort::shared::smallsort::verify::sorting_q_controls::p5_swap_false_or_q_fixed0',
      'slice::sort::shared::smallsort::verify::sorting_q_controls::p5_network_n17_qpost_corrupt']
    if [x.get('selector') for x in r['roots']]!=selectors: raise PilotError('selector list mismatch')
    expected_cfg={'positive':'--cfg=kani_smallsort_sorting --cfg=kani_smallsort_q_pilot',
                  'mutant':'--cfg=kani_smallsort_sorting --cfg=kani_smallsort_q_pilot --cfg=kani_smallsort_q_controls',
                  'closed':True,'kani_added_by_tool':True}
    if r.get('cfg')!=expected_cfg: raise PilotError('frozen cfg mismatch')
    expected_limits={'setup_and_build_seconds':1800,'tool_build_seconds':900,'compile_seconds_per_root':180,'child_seconds_per_root':600,
      'slot_seconds_per_root':720,'campaign_seconds':6900,'outer_seconds':7500,'step_seconds':7560,'phase_seconds':8100,'job_minutes':180,
      'local_rss_kib':6291456,'outer_rss_kib':12582912,'memory_reserve_kib':2097152,'stdout_bytes_per_root':16777216,
      'stderr_bytes_per_root':1048576,'export_bytes_per_root':8388608,'artifact_bytes':268435456}
    if r.get('limits')!=expected_limits: raise PilotError('bounded limits mismatch')
    if r['tool_sha']!=TOOL_SHA or r['tool_tree']!=TOOL_TREE: raise PilotError('tool pin mismatch')
    if r.get('status')!='READY' or r.get('go')!='NOT_GRANTED' or r.get('proof_credit')!='NONE': raise PilotError('request status/authority drift')
    domains=[x.get('q_domain') for x in r['roots']]
    if domains!=['all_u8','all_u8','all_u8','all_u8','all_u8','{0}','all_u8']: raise PilotError('q-domain distinction lost')
    expected_root_cfgs=['positive','positive','positive','positive','mutant','mutant','positive']
    if [root.get('cfg') for root in r['roots']] != expected_root_cfgs:
        raise PilotError('root cfg selection mismatch')
    expected_targets=['swap_if_less','sort13_optimal','insert_tail',None,'swap_if_less','swap_if_less',None]
    if [root.get('target') for root in r['roots']] != expected_targets:
        raise PilotError('root contract target mismatch')
    expected_stubs=[[],['swap_if_less'],[],['sort13_optimal','insert_tail'],[],[],['sort13_optimal','insert_tail']]
    if [x.get('stubs') for x in r['roots']]!=expected_stubs: raise PilotError('verified-stub graph mismatch')
    expected_modes=['PFC','PFC','PFC','PROOF','PFC','PFC','PROOF']
    if [x.get('mode') for x in r['roots']]!=expected_modes: raise PilotError('root mode list mismatch')
    if r.get('aggregate_budget')!={'roots':7,'child_seconds':4200,'slot_seconds':5040,'accounting':'TRACKING_ONLY; no reservation or authorization'}: raise PilotError('campaign accounting drift')
    return r

def request_hash(): return digest(REQ_PATH)
def git(path,*args): return subprocess.check_output(['git','-C',str(path),*args],text=True,stderr=subprocess.PIPE).strip()

def validate_source(std: Path, tool: Path, request):
    if request['std_sha'].startswith(PENDING) or request['std_tree'].startswith(PENDING): raise PilotError('std commit/tree pin is pending')
    if git(std,'rev-parse','HEAD')!=request['std_sha'] or git(std,'rev-parse','HEAD^{tree}')!=request['std_tree']:
        raise PilotError('std identity mismatch')
    if git(tool,'rev-parse','HEAD')!=request['tool_sha'] or git(tool,'rev-parse','HEAD^{tree}')!=request['tool_tree']:
        raise PilotError('tool identity mismatch')
    for path in (std,tool):
        if git(path,'status','--porcelain','--untracked-files=no'): raise PilotError(f'dirty checkout: {path.name}')
    for rel,expected in request['std_files'].items():
        if not isinstance(expected,str) or len(expected)!=64 or digest(std/rel)!=expected: raise PilotError(f'source file hash mismatch: {rel}')
    for root in request['roots']:
        for label,binding in root['role_bindings'].items():
            lines=(std/binding['file']).read_text().splitlines()
            lo,hi=binding.get('line'),binding.get('line_end',binding.get('line'));expected=binding.get('source_lines')
            if type(lo) is not int or type(hi) is not int or lo<1 or hi<lo or hi>len(lines) or not isinstance(expected,list) or [x.strip() for x in lines[lo-1:hi]]!=expected:
                raise PilotError(f'source role site changed: {root["id"]}:{label}')
    for rid,groups in request.get('contract_site_groups',{}).items():
        for group in groups.values():
            spans=group if isinstance(group,list) else [group]
            for binding in spans:
                if not isinstance(binding,dict) or 'file' not in binding: continue
                lines=(std/binding['file']).read_text().splitlines()
                lo,hi=binding.get('line'),binding.get('line_end');expected=binding.get('source_lines')
                if type(lo) is not int or type(hi) is not int or lo<1 or hi<lo or hi>len(lines) or not isinstance(expected,list) or [x.strip() for x in lines[lo-1:hi]]!=expected:
                    raise PilotError(f"contract source span changed: {rid}:{binding.get('role')}")
    for key,binding in request.get('provider_bindings',{}).items():
        lines=(std/binding['file']).read_text().splitlines();lo=binding['line'];hi=binding.get('line_end',lo)
        if binding.get('source_sha256')!=request['std_files'].get(binding['file']) or lo<1 or hi>len(lines) or not any(binding['attribute'] in lines[i-1] for i in range(lo,hi+1)):
            raise PilotError(f'provider binding changed: {key}')
    for rid,call in request.get('provider_calls',{}).items():
        if call.get('source_call_count') is None: continue
        rel='library/core/src/slice/sort/shared/smallsort.rs';source=(std/rel).read_text()
        match=re.search(r'\b(?:unsafe\s+)?fn\s+'+re.escape(call['caller'])+r'\s*(?:<[^>{}]*>)?\s*\(',source)
        if not match: raise PilotError(f'provider caller missing: {rid}')
        start=match.start();brace=source.find('{',match.end());depth=0;end=None
        for i in range(brace,len(source)):
            if source[i]=='{': depth+=1
            elif source[i]=='}':
                depth-=1
                if depth==0: end=i+1;break
        count=source[brace:end].count(call['callee']+'(') if end else -1
        expected=call.get('source_call_count')
        if expected is not None and count!=expected: raise PilotError(f'provider call count mismatch: {rid}:{count}')
    return {'std_sha':request['std_sha'],'std_tree':request['std_tree'],'tool_sha':request['tool_sha'],'tool_tree':request['tool_tree'],
            'std_files':request['std_files'],'state':'MATCH'}

def cfg_for(root,request):
    name=root['cfg']
    if name not in ('positive','mutant'): raise PilotError('cfg outside closed list')
    return request['cfg'][name]

def argv_for(root,std,tool,export):
    return [str((tool/'scripts/kani').resolve()),'verify-std','-Z','unstable-options',
      '-Z','function-contracts','-Z','mem-predicates','-Z','float-lib','-Z','c-ffi','-Z','stubbing',
      '--no-assert-contracts','--jobs=1','--harness',root['selector'],'--exact','--default-unwind','36',
      '--harness-timeout','600s','--output-format=regular','-Z','export-json','--export-json',str(export.resolve()),
      str((std/'library').resolve()),'--cbmc-args','--object-bits','12']

class QCompileMonitor(stock_runner.CompileMonitor):
    """Require the first valid, identity-matched export to be INCOMPLETE."""
    def __init__(self,path,export,selector,identities):
        super().__init__(path,export,[selector],seconds=180,identities=identities)
        self.receipt['request_sha256']=request_hash()
        self.receipt['schema']='ch8-q-pilot-compile-v1'
        self.receipt['boundary']='WAITING_FOR_INITIAL_INCOMPLETE_EXPORT'
        stock_runner._write_json(self.path,self.receipt)
    def poll(self,elapsed,state):
        try:
            if self.export.stat().st_size>stock_runner.EXPORT_CAP_BYTES: return False
            data=self.export.read_bytes();value=json.loads(data)
        except (OSError,UnicodeError,ValueError): return False
        if value.get('run_state')!='INCOMPLETE': return False
        if not stock_runner._selection_matches(value,self.selectors,marker=True): return False
        return super().poll(elapsed,state)
    def finish(self,execution,state):
        super().finish(execution,state)
        if self.receipt.get('state')!='COMPLETE':
            try:
                data=self.export.read_bytes();value=json.loads(data)
                if stock_runner._selection_matches(value,self.selectors) and value.get('run_state')=='COMPLETE':
                    self.receipt.update(state='MISSING_INITIAL_MARKER',reason='only terminal COMPLETE export was observed',
                                        terminal_export_sha256=hashlib.sha256(data).hexdigest())
            except (OSError,UnicodeError,ValueError): pass
        stock_runner._write_json(self.path,self.receipt)

def check_config(value, root):
    if not isinstance(value,dict) or value.get('schema_version')!='0.1.0' or value.get('run_state')!='COMPLETE': return 'INCOMPLETE_OR_SCHEMA_DRIFT'
    if value.get('kani_commit')!=TOOL_SHA or value.get('kani_commit_dirty') is not False: return 'WRONG_TOOL_BINDING'
    selection=value.get('harness_selection')
    if not isinstance(selection,dict) or selection.get('requested_filters')!=[root['selector']] or selection.get('exact') is not True or selection.get('unmatched_filters')!=[] or selection.get('matched_count')!=1: return 'WRONG_ROOT_SELECTION'
    if value.get('harness_timeout_s')!=600: return 'WRONG_TIMEOUT'
    if value.get('enabled_unstable_features') is None: return 'MISSING_FEATURE_SET'
    features=set(value['enabled_unstable_features'])
    must={'function-contracts','mem-predicates','float-lib','c-ffi','stubbing','export-json'}
    if features!=must or {'loop-contracts','quantifiers','uninit-checks','valid-value-checks'} & features: return 'WRONG_FEATURE_SET'
    conf=value.get('configuration')
    if not isinstance(conf,dict) or conf.get('cbmc_args')!=['--object-bits','12']: return 'WRONG_CONFIGURATION'
    checks=conf.get('checks')
    if not isinstance(checks,dict) or checks.get('assert_contracts') is not False or any(checks.get(k) is not True for k in ('memory_safety','overflow','unwinding','undefined_function')): return 'WRONG_CHECKS'
    hs=value.get('harnesses')
    if not isinstance(hs,list) or len(hs)!=1 or not isinstance(hs[0],dict) or hs[0].get('name')!=root['selector']: return 'WRONG_NATIVE_HARNESS'
    h=hs[0]
    if type(h.get('resolved_unwind')) is not int or h.get('resolved_unwind')!=36 or not isinstance(h.get('outcome'),dict) or h['outcome'].get('kind')!='COMPLETED' or h['outcome'].get('verdict') not in ('SUCCESS','FAILURE'): return 'NOT_COMPLETED'
    attrs=h.get('attributes');kind=attrs.get('kind') if isinstance(attrs,dict) else None
    if root['mode']=='PFC':
        if not isinstance(kind,dict) or set(kind)!={'ProofForContract'}: return 'WRONG_MODE'
        target=kind['ProofForContract'].get('target_fn')
        if not isinstance(target,str) or not (target==root['target'] or target.endswith('::'+root['target']) or target.endswith(root['target']+'>')): return 'WRONG_PFC_TARGET'
        contract=h.get('contract')
        if not isinstance(contract,dict) or not isinstance(contract.get('contracted_function_name'),str): return 'MISSING_CONTRACT_MODE'
    elif kind!='Proof': return 'WRONG_MODE'
    attrs=h.get('attributes')
    if not isinstance(attrs,dict) or not isinstance(attrs.get('verified_stubs'),list) or not isinstance(attrs.get('stubs'),list): return 'MISSING_STUB_METADATA'
    if attrs.get('stubs')!=[]: return 'UNEXPECTED_UNVERIFIED_STUBS'
    actual_stubs=attrs.get('verified_stubs')
    if len(actual_stubs)!=len(root['stubs']) or any(not isinstance(x,str) or not any(x==name or x.endswith('::'+name) for name in root['stubs']) for x in actual_stubs): return 'VERIFIED_STUB_GRAPH_MISMATCH'
    solver=h.get('resolved_solver')
    if solver!='cadical': return 'WRONG_SOLVER'
    resources=h.get('resources')
    if not isinstance(resources,dict) or type(resources.get('verification_time_s')) not in (int,float): return 'MISSING_NATIVE_VERIFICATION_TIME'
    tools=value.get('tools')
    if not isinstance(tools,dict) or any(not isinstance(tools.get(k),str) or not tools[k] for k in ('kani','rustc','cbmc')): return 'MISSING_TOOL_VERSION'
    if not isinstance(h.get('checks'),dict) or not isinstance(h.get('covers'),dict): return 'MISSING_INVENTORY'
    try: rich_evidence.validate_stock_inventory(h)
    except (ValueError,KeyError,TypeError) as e: return f'INVALID_INVENTORY:{e}'
    return 'MATCH'

def role_inventory(root, parser, export_harness, source_root, request):
    records=parser.records.get(root['selector']) if parser else None
    if not isinstance(records,list): return {'state':'UNKNOWN','reason':'regular stream incomplete','roles':{}}
    roles={}
    for label in root['roles']:
        matches=[p for p in records if label in p.get('description','')]
        binding=root.get('role_bindings',{}).get(label)
        try: observed_line=int(matches[0].get('line')) if len(matches)==1 else 0
        except (TypeError,ValueError): observed_line=0
        exact=(len(matches)==1 and isinstance(binding,dict) and type(binding.get('line')) is int
               and binding.get('line')<=observed_line<=binding.get('line_end',binding.get('line'))
               and isinstance(matches[0].get('file'),str) and matches[0]['file'].endswith('/'+binding.get('file','')))
        roles[label]={'state':'MATCH' if exact else 'UNKNOWN','property':matches[0] if len(matches)==1 else None,
                      'reason':None if exact else 'label missing/ambiguous or source site does not match frozen binding'}
    # Cross-check full IDs/classes/statuses against this invocation's native aggregate.
    try:
        ids=[p['id'] for p in records]
        if len(ids)!=len(set(ids)) or len(ids)!=export_harness['n_properties']: raise ValueError('property totals differ')
        checks=export_harness['checks'];covers=export_harness['covers']
        check_rows=[p for p in records if p.get('class')!='cover'];cover_rows=[p for p in records if p.get('class')=='cover']
        if len(check_rows)!=checks['total'] or len(cover_rows)!=covers['total']: raise ValueError('property classes/totals differ')
        def bucket_map(bucket, names, *, success_name=None):
            result={}
            for name in names:
                vals=bucket.get(name)
                if not isinstance(vals,list): raise ValueError('missing/wrong native bucket '+name)
                for item in vals:
                    if isinstance(item,dict): pid=item.get('id'); status=item.get('status')
                    else: pid=item;status=('SATISFIED' if name==success_name else name.upper())
                    if not isinstance(pid,str) or not pid or not isinstance(status,str) or pid in result: raise ValueError('bad/duplicate native property entry')
                    result[pid]=status
            return result
        cstatus=bucket_map(checks,('failure','unreachable','undetermined','error','unknown','other'))
        cids={p['id'] for p in check_rows}
        if not set(cstatus)<=cids: raise ValueError('check bucket contains non-check ID')
        success_ids=cids-set(cstatus)
        if len(success_ids)!=checks['success']: raise ValueError('check SUCCESS IDs do not reconcile')
        cstatus.update({pid:'SUCCESS' for pid in success_ids})
        vstatus=bucket_map(covers,('satisfied','unsatisfiable','unreachable','undetermined','error','unknown','other'),success_name='satisfied')
        vids={p['id'] for p in cover_rows}
        if set(vstatus)!=vids: raise ValueError('cover IDs do not fully reconcile')
        all_expected={**cstatus,**vstatus}
        if set(all_expected)!=set(ids): raise ValueError('native/rich property ID set differs')
        for p in records:
            expected_status=all_expected[p['id']]
            if expected_status=='UNKNOWN' and p['status']=='UNDETERMINED':
                p['display_status']='UNDETERMINED';p['status']='UNKNOWN'
            if expected_status!=p['status']: raise ValueError('property status mismatch: '+p['id'])
        by_id={p['id']:p for p in records}
        for key in ('failed_properties','unsupported_constructs'):
            frozen=export_harness.get(key,[])
            if not isinstance(frozen,list): raise ValueError('native '+key+' malformed')
            for native_prop in frozen:
                if not isinstance(native_prop,dict) or native_prop.get('id') not in by_id: raise ValueError('native '+key+' ID missing from regular stream')
                observed=by_id[native_prop['id']]
                for field in ('id','class','status','description','line'):
                    if native_prop.get(field)!=observed.get(field): raise ValueError('native/rich '+key+' '+field+' mismatch: '+str(native_prop.get('id')))
                native_file=native_prop.get('file')
                expected_file=(str(Path(source_root).resolve()/native_file) if isinstance(native_file,str) else None)
                if expected_file!=observed.get('file'): raise ValueError('native/rich '+key+' file mismatch: '+str(native_prop.get('id')))
    except Exception as e:
        return {'state':'INCOMPLETE','reason':f'stock/rich inventory disagreement: {e}','roles':roles,'properties':records}
    return {'state':'COMPLETE','roles':roles,'properties':records,'count':len(records),
            'native_stock':{'outcome':export_harness.get('outcome'),'checks':checks,'covers':covers,
                            'unsupported_constructs':export_harness.get('unsupported_constructs')}}

def contract_role_inventory(root, parser):
    groups=load_request().get('contract_site_groups',{}).get(root['id'],{})
    records=parser.records.get(root['selector'],[]) if parser else []
    spans={}
    for group in groups.values():
        for span in (group if isinstance(group,list) else [group]):
            if isinstance(span,dict) and 'file' in span and span.get('mode'):
                spans.setdefault(span['role'],[]).append(span)
    result={}
    for role,bindings in spans.items():
        matches=[]
        unique_bindings={(b['file'],b['line'],b['line_end'],b['expression'],b['mode']):b for b in bindings}
        for binding in unique_bindings.values():
            for prop in records:
                line=prop.get('line')
                try: located=binding['line']<=int(line)<=binding['line_end']
                except (TypeError,ValueError): located=False
                desc=prop.get('description','')
                expr=binding['description_contains']
                if (located and isinstance(prop.get('file'),str) and prop['file'].endswith('/'+binding['file'])
                        and isinstance(desc,str) and expr in desc and prop.get('class')!='cover'):
                    matches.append(prop)
        # Multiple records at one exact frozen contract source span are retained as repeated call instances.
        matches=list({p.get('id'):p for p in matches if isinstance(p.get('id'),str)}.values())
        ids=[p.get('id') for p in matches]
        unique=len(ids)==len(set(ids)) and all(isinstance(x,str) and x for x in ids)
        wanted='FAILURE' if role==root.get('assigned_property') and root['expected_control']=='FAIL' else 'SUCCESS'
        state='UNKNOWN' if not matches or not unique else 'MATCH' if all(p.get('status')==wanted for p in matches) else 'MISMATCH'
        result[role]={'state':state,'mode_bindings':[{'mode':b['mode'],'file':b['file'],'line':b['line'],'line_end':b['line_end'],
                           'function':b['function'],'expression':b['expression']} for b in bindings],
                      'expected_status':wanted,'count':len(matches),'property_ids':ids if matches else None,
                      'properties':matches if matches else None,
                      'reason':None if state=='MATCH' else 'required contract property missing, ambiguous, or has wrong status'}
    return result

def control_match(root, export_harness, inventory, exit_code, diagnostic_gate):
    label=root['assigned_property']; roles=inventory.get('roles',{})
    if root['id']=='P-5b':
        native=export_harness.get('outcome',{}).get('verdict')
        contracts_ok=all(inventory.get('contract_roles',{}).get(x,{}).get('state')=='MATCH' for x in root.get('required_contract_roles',[]))
        roles_ok=all(roles.get(x,{}).get('state')=='MATCH' and isinstance(roles[x].get('property'),dict) and
                 roles[x]['property'].get('status')==('SATISFIED' if roles[x]['property'].get('class')=='cover' else 'SUCCESS')
                 for x in root['roles'])
        good=diagnostic_gate.get('state')=='CLEAR' and contracts_ok and roles_ok and native=='SUCCESS' and exit_code==0
        return {'native_outcome':native,'qualification':'FAIL' if good else 'UNKNOWN',
                'native_control_match':'MATCH' if good else 'UNKNOWN','contract_roles_ok':contracts_ok,'required_roles_ok':roles_ok,'match':'MATCH' if good else 'UNKNOWN',
                'reason':'Q_DOMAIN_NOT_UNIVERSAL' if good else 'native success/required roles not established',
                'domain_gate':{'q_domain':root['q_domain'],'required':'all_u8'},
                'expected':'NATIVE_SUCCESS_SYNTHETIC_GATE_FAIL'}
    match=all(roles.get(x,{}).get('state')=='MATCH' for x in root['roles'])
    expected_roles_ok=all(roles.get(x,{}).get('state')=='MATCH' and isinstance(roles[x].get('property'),dict) and
       roles[x]['property'].get('status')==('SATISFIED' if roles[x]['property'].get('class')=='cover' else
         'FAILURE' if x==root.get('assigned_property') and root['expected_control']=='FAIL' else 'SUCCESS') for x in root['roles'])
    contract_roles=inventory.get('contract_roles',{})
    contracts_ok=all(contract_roles.get(x,{}).get('state')=='MATCH' for x in root.get('required_contract_roles',[]))
    assigned=roles.get(label,{}).get('property'); wanted='FAILURE' if root['expected_control']=='FAIL' else 'SUCCESS'
    assigned_ok=isinstance(assigned,dict) and assigned.get('status')==wanted
    designated={assigned.get('id')} if assigned_ok and wanted=='FAILURE' else set()
    other_failures=[p.get('id') for p in inventory.get('properties',[]) if p.get('class')!='cover' and p.get('status')=='FAILURE' and p.get('id') not in designated]
    covers_bad=[p.get('id') for p in inventory.get('properties',[]) if p.get('class')=='cover' and p.get('status')!='SATISFIED']
    native=export_harness.get('outcome',{}).get('verdict')
    expected_native='FAILURE' if root['expected_control']=='FAIL' else 'SUCCESS'
    expected_exit=1 if root['expected_control']=='FAIL' else 0
    good=diagnostic_gate.get('state')=='CLEAR' and match and expected_roles_ok and contracts_ok and assigned_ok and not other_failures and not covers_bad and native==expected_native and exit_code==expected_exit
    return {'expected':root['expected_control'],'assigned_property':label,'actual_status':assigned.get('status') if isinstance(assigned,dict) else None,
            'native_outcome':native,'child_exit_code':exit_code,'expected_exit_code':expected_exit,'diagnostic_gate':diagnostic_gate,'required_roles_ok':expected_roles_ok,'contract_roles_ok':contracts_ok,'unexpected_failures':other_failures,'unsatisfied_covers':covers_bad,
            'match':'MATCH' if good else 'MISMATCH' if match else 'UNKNOWN',
            'reason':None if good else 'designated property, native verdict, required roles/covers, or unexpected failure mismatch'}

def root_record(root, status='NOT_RUN', reason='not launched'):
    return {'id':root['id'],'selector':root['selector'],'cfg':root['cfg'],'domain_id':root['domain_id'],'q_domain':root['q_domain'],
      'mode':root['mode'],'contract_target':root['target'],'verified_stubs':root['stubs'],'expected_control':root['expected_control'],
      'assigned_property':root['assigned_property'],'required_roles':root['roles'],'required_contract_roles':root.get('required_contract_roles',[]),
      'status':status,'reason':reason,
      'invocation_id':None,'argv':None,'solver':None,'target':None,'target_sha256':None,'export':None,
      'lifecycle':{'state':status,'exit_code':None,'signal':None,'timeout':None,'cutoff':None,'cleanup':None,'child_wall_seconds':None,
                   'compile_marker_upper_seconds':None,'native_verification_time_seconds':None,'sampled_rss_kib':None,
                   'rss_scope':None},'inventory':{'state':'UNKNOWN','properties':None,'reason':'not run'},'control':{'match':'UNKNOWN','reason':'not run'},
      'proof_credit':'NONE'}

def setup_record(out, request, state='UNKNOWN', **fields):
    return {'state':state,'exit_code':fields.get('exit_code'),'wall_seconds':fields.get('wall_seconds'),
            'proof_status':'NOT_RUN','reason':fields.get('reason')}

def campaign_base(request,out):
    return {'schema':request['result_schema'],'profile':request['profile'],'qualification':'RESEARCH_ONLY','proof_credit':'NONE',
      'run_id':os.environ.get('GITHUB_RUN_ID'),'run_attempt':os.environ.get('GITHUB_RUN_ATTEMPT'),'ref':os.environ.get('GITHUB_REF'),
      'event':os.environ.get('GITHUB_EVENT_NAME'),'trigger_sha':os.environ.get('GITHUB_SHA'),'trigger_tree':(git(REPO,'rev-parse',os.environ['GITHUB_SHA']+'^{tree}') if os.environ.get('GITHUB_SHA') else None),'trigger_parent':request['control_parent'],
      'request_sha256':request_hash(),'workflow_sha256':digest(REPO/request['workflow']) if (REPO/request['workflow']).is_file() else None,
      'std_sha':request['std_sha'],'std_tree':request['std_tree'],'tool_sha':request['tool_sha'],'tool_tree':request['tool_tree'],
      'os':os.environ.get('RUNNER_OS'),'python':sys.version,'setup':setup_record(out,request),'limits':request['limits'],'stop_reason':None,
      'roots':[root_record(r) for r in request['roots']]}

def read_export(path, cap):
    if not path.is_file(): return None,{'state':'MISSING','sha256':None,'bytes':None}
    n=path.stat().st_size
    if n>cap: return None,{'state':'INVALID','reason':'export cap exceeded','sha256':None,'bytes':n}
    try: data=path.read_bytes()
    except OSError as e: return None,{'state':'MISSING','reason':f'{type(e).__name__}: {e}','sha256':None,'bytes':None}
    try: value=json.loads(data)
    except (UnicodeError,json.JSONDecodeError) as e: return None,{'state':'INVALID','reason':f'{type(e).__name__}: {e}','sha256':hashlib.sha256(data).hexdigest(),'bytes':n}
    if value is None: return None,{'state':'NULL','sha256':hashlib.sha256(data).hexdigest(),'bytes':n}
    if not isinstance(value,dict): return None,{'state':'WRONG_TOP_LEVEL_TYPE','type':type(value).__name__,'sha256':hashlib.sha256(data).hexdigest(),'bytes':n}
    if value.get('run_state')=='INCOMPLETE': return value,{'state':'PARTIAL','sha256':hashlib.sha256(data).hexdigest(),'bytes':n}
    return value,{'state':'PRESENT','sha256':hashlib.sha256(data).hexdigest(),'bytes':n}

def invoke_root(root, std, tool, out, request, target_dir, invocation):
    rid=root['id']; dest=out/'roots'/rid; dest.mkdir(parents=True,exist_ok=False)
    export=dest/'export.json'; args=argv_for(root, std, tool, export)
    env=os.environ.copy(); env['RUSTFLAGS']=cfg_for(root,request); env['NO_COLOR']='1';env['TERM']='dumb'
    env.pop('CARGO_ENCODED_RUSTFLAGS', None)
    env['CARGO_TARGET_DIR']=str(target_dir.resolve())
    ident={k:request[k] for k in ('std_sha','std_tree','tool_sha','tool_tree')}
    mon=QCompileMonitor(dest/'compile.json',export,root['selector'],ident)
    parser=rich_evidence.RegularEvidence([root['selector']],std.resolve())
    memory=stock_runner.group_memory_budget()
    effective_rss=min(request['limits']['local_rss_kib'],memory['group_cap_kib'])
    atomic(dest/'started.json',{'invocation_id':invocation,'started_at_monotonic':time.monotonic(),'argv_sha256':hashlib.sha256(json.dumps(args).encode()).hexdigest()})
    execution=stock_runner.execute(args,std,dest/'execution',600,rss_cap_kib=effective_rss,
      stdout_cap=request['limits']['stdout_bytes_per_root'],stderr_cap=request['limits']['stderr_bytes_per_root'],
      export_path=export,export_cap=request['limits']['export_bytes_per_root'],env=env,capture_tail=True,
      compile_monitor=mon,rich_parser=parser,record_identity=True)
    native,export_info=read_export(export,request['limits']['export_bytes_per_root'])
    status='INVALID' if execution.get('runner_error') else 'PARTIAL' if execution.get('termination_reason') or execution.get('timed_out') or execution.get('original_exit_code') is None or execution.get('child_shutdown_verified') is not True or execution.get('cleanup_errors') else 'COMPLETE'
    result=root_record(root,status,execution.get('termination_reason') or execution.get('runner_error'))
    result.update(invocation_id=invocation,argv=args,target={'cargo_target_dir':str(target_dir.resolve()),'export_path_in_invocation':str(export),'export_sha256':export_info.get('sha256')},target_sha256=export_info.get('sha256'),export=export_info,
      memory={'nominal_local_rss_cap_kib':request['limits']['local_rss_kib'],'effective_local_rss_cap_kib':effective_rss,**memory},
      lifecycle={'state':status,'exit_code':execution.get('original_exit_code'),'signal':execution.get('signal'),'timeout':execution.get('timed_out'),
        'cutoff':execution.get('termination_reason'),'cleanup':execution.get('cleanup'),'child_wall_seconds':execution.get('elapsed_seconds'),
        'compile_marker_upper_seconds':mon.receipt.get('elapsed_upper_bound_seconds'),'native_verification_time_seconds':None,'measurement_null_reasons':{'native_verification_time_seconds':'not exposed until a valid export is parsed'},
        'child_shutdown_verified':execution.get('child_shutdown_verified'),'cleanup_errors':execution.get('cleanup_errors'),
        'process_identity':execution.get('process_identity'),'interrupted_by_signal':execution.get('interrupted_by_signal'),
        'sampled_rss_kib':execution.get('rss_peak_kib'),
        'rss_scope':execution.get('rss_scope') or execution.get('component_rss_scope') or execution.get('rss_status')})
    result['compile_marker']={k:mon.receipt.get(k) for k in ('schema','state','boundary','request_sha256','std_sha','std_tree','tool_sha','tool_tree','selectors','observed_run_state','elapsed_upper_bound_seconds','marker_sha256','reason')}
    if native is None:
        result['inventory']={'state':export_info['state'],'reason':export_info.get('reason'),'properties':None}
        result['control']={'match':'UNKNOWN','reason':'native export unavailable'}
    else:
        mode=check_config(native,root)
        hs=native.get('harnesses') if isinstance(native,dict) else None
        h=hs[0] if isinstance(hs,list) and len(hs)==1 and isinstance(hs[0],dict) else None
        parser.finish()
        compile_valid=(mon.receipt.get('state')=='COMPLETE' and mon.receipt.get('boundary')=='STOCK_INITIAL_EXPORT_OBSERVED'
            and mon.receipt.get('observed_run_state')=='INCOMPLETE' and mon.receipt.get('request_sha256')==request_hash()
            and all(mon.receipt.get(k)==request[k] for k in ('std_sha','std_tree','tool_sha','tool_tree'))
            and mon.receipt.get('selectors')==[root['selector']] and isinstance(mon.receipt.get('marker_sha256'),str)
            and type(mon.receipt.get('elapsed_upper_bound_seconds')) in (int,float)
            and mon.receipt['elapsed_upper_bound_seconds']<=request['limits']['compile_seconds_per_root'])
        cleanup_valid=execution.get('child_shutdown_verified') is True and not execution.get('cleanup_errors') and result['lifecycle'].get('cleanup_errors') in (None,[])
        output_valid=not execution.get('output_truncated') and not execution.get('stdout_truncated') and not execution.get('stderr_truncated')
        diagnostic_gate={'state':'CLEAR' if status=='COMPLETE' and h and compile_valid and cleanup_valid and output_valid and not h.get('warnings') and not h.get('warnings_truncated') and not h.get('unsupported_constructs') and not native.get('warnings') else 'WARNINGS_OR_UNSUPPORTED_OR_INCOMPLETE_BOUNDARY',
                         'compile_marker_state':mon.receipt.get('state'),'cleanup_valid':cleanup_valid,'output_valid':output_valid,
                         'harness_warnings':h.get('warnings') if h else None,'campaign_warnings':native.get('warnings') if isinstance(native,dict) else None,
                         'unsupported_constructs':h.get('unsupported_constructs') if h else None}
        if h and parser.finished and parser.error is None:
            inventory=role_inventory(root,parser,h,std,request)
            inventory['contract_roles']=contract_role_inventory(root,parser)
        else:
            partial=[]
            if parser:
                partial=[prop for records in parser.records.values() for prop in records]
            inventory={'state':'PARTIAL' if partial else 'UNKNOWN','reason':'regular stream incomplete: '+str(parser.error or 'not finished'),
                       'properties':partial or None,'roles':{}}
        result['native_harness']={'name':h.get('name') if h else None,'kind':h.get('attributes',{}).get('kind') if h else None,
          'reported_tools':native.get('tools') if isinstance(native,dict) else None,
          'contract_target':h.get('contract',{}).get('contracted_function_name') if h and isinstance(h.get('contract'),dict) else None,
          'export_binding':{'state':mode,'expected_target':root['target'],'exported_target':(h.get('attributes',{}).get('kind',{}).get('ProofForContract',{}).get('target_fn') if h and isinstance(h.get('attributes',{}).get('kind'),dict) else None)},
          'expected_verified_stubs':root['stubs'],'actual_verified_stubs':(h.get('attributes',{}).get('verified_stubs') if h else None),
          'verified_stub_binding':'MATCH' if h and h.get('attributes',{}).get('verified_stubs') is not None and len(h['attributes']['verified_stubs'])==len(root['stubs']) and all(any(x==name or x.endswith('::'+name) for name in root['stubs']) for x in h['attributes']['verified_stubs']) else 'MISMATCH_OR_UNKNOWN',
          'contract_mode_evidence':{'export_mode':root['mode'],'source_roles':request.get('contract_site_groups',{}).get(root['id']),
             'native_contract_roles':inventory.get('contract_roles'),
             'semantics':'CHECK_REPLACE_PRECEDES_ASSERT_ORIGINAL_FROM_EXACT_TOOL_PIN','evidence':'source-derived semantics plus native kind/target/stub export; no mode inferred from SUCCESS alone'},
          'resolved_solver':h.get('resolved_solver') if h else None,'native_verification_time_seconds':h.get('resources',{}).get('verification_time_s') if h else None,
          'native_warnings':{'campaign':native.get('warnings'),'harness':h.get('warnings') if h else None,'unsupported_constructs':h.get('unsupported_constructs') if h else None},
          'flags':native.get('configuration') if isinstance(native,dict) else None,'identity_check':mode,'native_outcome':h.get('outcome') if h else None}
        result['rich_stream']={'state':'COMPLETE' if parser.finished and parser.error is None else 'INCOMPLETE','error':parser.error,
             'bytes':parser.bytes,'property_count':sum(len(v) for v in parser.records.values()),'missing_sites':parser.missing_sites}
        result['inventory']=inventory
        if h:
            result['lifecycle']['native_verification_time_seconds']=h.get('resources',{}).get('verification_time_s')
            result['lifecycle']['measurement_null_reasons']={}
            result['solver']=h.get('resolved_solver')
        result['control']=control_match(root,h or {},inventory,execution.get('original_exit_code'),diagnostic_gate) if inventory.get('state')=='COMPLETE' and mode=='MATCH' else {'match':'UNKNOWN','reason':inventory.get('reason',mode),'diagnostic_gate':diagnostic_gate}
    atomic(dest/'root.json',result)
    for raw in (export,dest/'execution'/'stdout.log',dest/'execution'/'stderr.log'):
        try: raw.unlink()
        except FileNotFoundError: pass
    return result

def campaign(std,tool,out,setup_receipt=None):
    request=load_request(); out.mkdir(parents=True,exist_ok=True)
    doc=campaign_base(request,out); atomic(out/RESULT,doc)
    try:
        if not setup_receipt or not setup_receipt.is_file(): raise PilotError('setup/build receipt missing')
        setup=json.loads(setup_receipt.read_text())
        if not isinstance(setup,dict): raise PilotError('setup/build receipt wrong type')
        setup_ok=(setup.get('original_exit_code')==0 and not setup.get('timed_out') and not setup.get('termination_reason')
                  and type(setup.get('setup_total_seconds')) in (int,float))
        doc['setup']={'state':'COMPLETE' if setup_ok else 'FAILED','exit_code':setup.get('original_exit_code'),
                      'wall_seconds':setup.get('setup_total_seconds'),'proof_status':'NOT_RUN','receipt_sha256':digest(setup_receipt),
                      'original_exit_code':setup.get('original_exit_code'),'timed_out':setup.get('timed_out'),
                      'termination_reason':setup.get('termination_reason'),'stdout_bytes':setup.get('stdout_bytes'),
                      'stderr_bytes':setup.get('stderr_bytes')}
        atomic(out/RESULT,doc)
        if not setup_ok: raise PilotError('tool setup/build unsuccessful')
    except Exception as e:
        doc['setup']={**doc.get('setup',{}),'state':'FAILED','reason':f'{type(e).__name__}: {e}','proof_status':'NOT_RUN'}
        doc['stop_reason']='SETUP_FAILURE'
        for i,root in enumerate(request['roots']): doc['roots'][i]=root_record(root,'NOT_RUN',doc['stop_reason'])
        atomic(out/RESULT,doc);return 1
    try:
        source=validate_source(std,tool,request)
        doc['source_identity']=source
        atomic(out/RESULT,doc)
    except Exception as e:
        doc['source_identity']={'state':'MISMATCH','reason':f'{type(e).__name__}: {e}'}
        doc['stop_reason']='SOURCE_IDENTITY_FAILURE'
        for i,root in enumerate(request['roots']): doc['roots'][i]=root_record(root,'NOT_RUN',doc['stop_reason'])
        atomic(out/RESULT,doc);return 1
    setup_elapsed=doc['setup'].get('wall_seconds')
    epoch=os.environ.get('SETUP_EPOCH')
    if epoch and Path(epoch).is_file():
        try: setup_elapsed=max(setup_elapsed,time.time()-float(Path(epoch).read_text()))
        except Exception: pass
    if type(setup_elapsed) not in (int, float) or not 0 <= setup_elapsed <= request['limits']['setup_and_build_seconds']:
        doc['stop_reason'] = 'SETUP_BUDGET_UNAVAILABLE_OR_EXCEEDED'
        for i, root in enumerate(request['roots']):
            doc['roots'][i] = root_record(root, 'NOT_RUN', doc['stop_reason'])
        atomic(out / RESULT, doc)
        return 1
    start=time.monotonic(); stop=None
    for idx,root in enumerate(request['roots']):
        elapsed=setup_elapsed+time.monotonic()-start
        remaining=min(request['limits']['campaign_seconds']-elapsed,request['limits']['outer_seconds']-elapsed)
        needed=(len(request['roots'])-idx)*request['limits']['slot_seconds_per_root']+60
        if remaining < needed:
            stop='campaign_budget_reserve'; break
        dest=out/'workers'/(root['id']+'.stderr')
        # supervisor wraps an isolated Python root worker, so all descendants are owned/reaped.
        invocation=str(uuid.uuid4());temp_root=Path(os.environ.get('RUNNER_TEMP',tempfile.gettempdir()))
        target_dir=Path(tempfile.mkdtemp(prefix='ch8-q-pilot-'+invocation+'-',dir=temp_root))
        worker=[sys.executable,str(Path(__file__).resolve()),'_root','--root',root['id'],'--std',str(std.resolve()),'--tool',str(tool.resolve()),'--out',str(out.resolve()),'--target',str(target_dir.resolve()),'--invocation',invocation]
        outer_memory=stock_runner.group_memory_budget();effective_outer=min(request['limits']['outer_rss_kib'],outer_memory['group_cap_kib'])
        # The supervisor's owned-process reap can take up to eight additional seconds.
        slot_cutoff = request['limits']['slot_seconds_per_root'] - 8
        sup=s3_runtime.supervise(worker,REPO,os.environ.copy(),slot_cutoff,effective_outer,dest,
              artifact_check=lambda:sum(p.stat().st_size for p in out.rglob('*') if p.is_file())>request['limits']['artifact_bytes'])
        path=out/'roots'/root['id']/'root.json'
        if path.is_file():
            try: rec=json.loads(path.read_text())
            except Exception: rec=root_record(root,'INVALID','root record invalid')
        else:
            launched=(out/'roots'/root['id']/'started.json').is_file()
            rec=root_record(root,'PARTIAL' if launched else 'NOT_RUN','worker did not write complete root record')
            rec.update(invocation_id=invocation,target={'cargo_target_dir':str(target_dir.resolve()),'export_path_in_invocation':str(out/'roots'/root['id']/'export.json'),'export_sha256':None},
                       lifecycle={'state':'PARTIAL' if launched else 'NOT_RUN','exit_code':None,'worker_exit_code':sup.get('worker_exit'),'signal':None,'timeout':None,
                                  'cutoff':sup.get('cutoff'),'cleanup':None,'child_wall_seconds':None,'compile_marker_upper_seconds':None,
                                  'native_verification_time_seconds':None,'measurement_null_reasons':{'native_verification_time_seconds':'no validated native export'},
                                  'sampled_rss_kib':None,'rss_scope':sup.get('outer_rss_scope')})
        shutil.rmtree(target_dir,ignore_errors=True)
        rec['target_cleanup']={'state':'COMPLETE','verified':not target_dir.exists(),'path':str(target_dir.resolve())}
        identity_state=(rec.get('native_harness') or {}).get('identity_check')
        fatal_identity=identity_state in {'WRONG_TOOL_BINDING','WRONG_ROOT_SELECTION','WRONG_TIMEOUT','WRONG_FEATURE_SET','WRONG_CONFIGURATION','WRONG_CHECKS','WRONG_NATIVE_HARNESS','WRONG_MODE','WRONG_PFC_TARGET','MISSING_CONTRACT_MODE','MISSING_STUB_METADATA','UNEXPECTED_UNVERIFIED_STUBS','VERIFIED_STUB_GRAPH_MISMATCH','WRONG_SOLVER','MISSING_NATIVE_VERIFICATION_TIME','MISSING_TOOL_VERSION','WRONG_UNWIND'}
        rec['outer_memory']={'nominal_outer_rss_cap_kib':request['limits']['outer_rss_kib'],'effective_outer_rss_cap_kib':effective_outer,**outer_memory}
        rec['supervision']=sup
        child_cleanup=rec.get('lifecycle',{}).get('child_shutdown_verified')
        if sup.get('cutoff') or not (sup.get('containment') or {}).get('verified') or child_cleanup is False or not rec['target_cleanup']['verified']:
            rec['status']='PARTIAL';rec['lifecycle']['state']='PARTIAL';rec['lifecycle']['cutoff']=sup.get('cutoff') or 'containment_unverified'
            rec['control']={'match':'UNKNOWN','reason':'outer cutoff or containment/cleanup was not verified'}
            stop='SUPERVISION_OR_CONTAINMENT_FAILURE'
        elif fatal_identity:
            rec['control']={'match':'UNKNOWN','reason':'native source/tool/root identity mismatch'}
            stop='NATIVE_IDENTITY_MISMATCH'
        elif not path.is_file() and sup.get('worker_exit') not in (0,None):
            stop='ROOT_WORKER_FAILED_BEFORE_RECORD'
        doc['roots'][idx]=rec
        atomic(out/RESULT,doc)
        if stop: break
    if stop:
        doc['stop_reason']=stop
        for i in range(len(doc['roots'])):
            if doc['roots'][i]['status']=='NOT_RUN': doc['roots'][i]=root_record(request['roots'][i], 'NOT_RUN',stop)
        atomic(out/RESULT,doc)
    doc['worker_campaign_seconds']=round(time.monotonic()-start,3)
    doc['campaign_elapsed_including_setup_seconds']=round(setup_elapsed+time.monotonic()-start,3)
    doc['step_elapsed_seconds']=doc['campaign_elapsed_including_setup_seconds']
    doc['phase_elapsed_seconds']=doc['campaign_elapsed_including_setup_seconds']
    doc['stop_reason']=stop
    atomic(out/RESULT,doc)
    return 1 if stop else 0

def run_one(root_id,std,tool,out,target_dir,invocation):
    req=load_request(); root=next((r for r in req['roots'] if r['id']==root_id),None)
    if root is None: raise PilotError('unknown root')
    temp_root=Path(os.environ.get('RUNNER_TEMP',tempfile.gettempdir())).resolve()
    target_dir=target_dir.resolve()
    if target_dir.parent!=temp_root or not target_dir.name.startswith('ch8-q-pilot-') or target_dir.is_symlink() or not target_dir.is_dir() or any(target_dir.iterdir()):
        raise PilotError('worker target must be a fresh runner-temp directory')
    validate_source(std,tool,req)
    rec=invoke_root(root,std,tool,out,req,target_dir,invocation)
    atomic(out/'roots'/root_id/'root.json',rec)
    return 0

def finish(out,setup_receipt=None):
    req=load_request();out.mkdir(parents=True,exist_ok=True);path=out/RESULT
    if path.is_file():
        try: doc=json.loads(path.read_text())
        except Exception: doc=campaign_base(req,out);doc['stop_reason']='INVALID_PRIOR_RESULT'
    else: doc=campaign_base(req,out);doc['stop_reason']='PRODUCER_DID_NOT_START'
    for i,root in enumerate(req['roots']):
        rp=out/'roots'/root['id']/'root.json'
        if doc['roots'][i]['status']=='NOT_RUN' and rp.is_file():
            try: doc['roots'][i]=json.loads(rp.read_text())
            except Exception: pass
    for i,root in enumerate(req['roots']):
        if doc['roots'][i]['status']=='NOT_RUN' and doc.get('stop_reason'):
            doc['roots'][i]=root_record(root,'NOT_RUN',doc['stop_reason'])
    doc['artifact_state']='COMPLETE' if all(r.get('status')=='COMPLETE' for r in doc['roots']) else 'PARTIAL'
    atomic(path,doc)
    total=sum(p.stat().st_size for p in out.rglob('*') if p.is_file())
    if total>req['limits']['artifact_bytes']: raise PilotError('artifact cap exceeded after fallback')
    return 0

def check_source(std,tool):
    request=load_request()
    print(json.dumps(validate_source(std,tool,request),sort_keys=True))
    return 0

def validate_workflow(path):
    try:
        import yaml
        doc=yaml.safe_load(path.read_text())
    except Exception as exc:
        raise PilotError(f'workflow parse failed: {type(exc).__name__}: {exc}')
    if not isinstance(doc,dict) or doc.get('name')!='CH8 q-threshold research pilot': raise PilotError('workflow identity')
    event=doc.get('on') or doc.get(True)
    if event!={'push':{'branches':['uninit-ci/ch8-q-pilot-v1']}}: raise PilotError('workflow trigger is not the sole frozen push ref')
    if doc.get('permissions')!={'contents':'read'}: raise PilotError('workflow permissions drift')
    if doc.get('concurrency')!={'group':'ch8-s2-fork','cancel-in-progress':False}: raise PilotError('workflow serialization drift')
    jobs=doc.get('jobs')
    if not isinstance(jobs,dict) or list(jobs)!=['q_pilot']: raise PilotError('workflow must have one job')
    job=jobs['q_pilot']
    if job.get('runs-on')!='ubuntu-24.04' or job.get('timeout-minutes')!=180: raise PilotError('runner/job cap drift')
    steps=job.get('steps')
    if not isinstance(steps,list): raise PilotError('workflow steps')
    by={s.get('name'):s for s in steps if isinstance(s,dict)}
    for name in ('Validate frozen control and synthetic runner','Read immutable pins','Checkout exact std source','Checkout exact Kani tool','Check source and tool identities','Setup exact stock tool','Build exact stock tool once','Run seven q-pilot roots','Materialize bounded result fallback','Upload bounded structured evidence'):
        if name not in by: raise PilotError(f'missing workflow step: {name}')
    if by['Validate frozen control and synthetic runner'].get('timeout-minutes',99)>5: raise PilotError('synthetic preflight timeout exceeds five minutes')
    if by['Run seven q-pilot roots'].get('timeout-minutes')!=126: raise PilotError('campaign step cap drift')
    if by['Materialize bounded result fallback'].get('if')!='always()' or by['Upload bounded structured evidence'].get('if')!='always()': raise PilotError('fallback/artifact must always run')
    artifact=by['Upload bounded structured evidence'].get('with',{})
    if artifact.get('path')!='${{ env.RECEIPT_ROOT }}/q-pilot-results.json' or artifact.get('if-no-files-found')!='warn': raise PilotError('artifact must contain only bounded result JSON and tolerate absence')
    if by['Setup exact stock tool'].get('uses')!='./tool/.github/actions/setup': raise PilotError('stock tool setup action drift')
    build=by['Build exact stock tool once'].get('run','')
    if 'check_package.py build' not in build or 'cargo' in build: raise PilotError('build must use the bounded stock setup helper')
    run=by['Run seven q-pilot roots'].get('run','')
    if run!='python3 control/ch8-q-pilot-control/run.py run --std export --tool tool --out "$RECEIPT_ROOT" --setup-receipt "$SETUP_RECEIPT"': raise PilotError('campaign argv drift')
    return {'state':'MATCH','job':'q_pilot','artifact_path':artifact['path']}

def check_control(repo):
    req=load_request()
    if os.environ.get('GITHUB_REPOSITORY')!='Tiramisu-Cake/kani' or os.environ.get('GITHUB_EVENT_NAME')!='push' or os.environ.get('GITHUB_REF')!=req['event_ref']:
        raise PilotError('workflow event not the frozen fork push')
    if os.environ.get('GITHUB_RUN_ATTEMPT')!='1': raise PilotError('rerun requires separate coordinator GO')
    if git(repo,'rev-parse','HEAD')!=os.environ.get('GITHUB_SHA'): raise PilotError('trigger SHA mismatch')
    if git(repo,'rev-list','--parents','-n','1','HEAD').split()!=[os.environ['GITHUB_SHA'],req['control_parent']]: raise PilotError('control parent mismatch')
    if git(repo,'status','--porcelain','--untracked-files=no'): raise PilotError('dirty control checkout')
    changed=git(repo,'diff','--name-only',req['control_parent'],os.environ['GITHUB_SHA']).splitlines()
    if sorted(changed)!=sorted(req.get('control_changed_paths',[])): raise PilotError('control changed-path inventory mismatch')
    payload = req.get('control_payload_sha256')
    request_rel = 'ch8-q-pilot-control/CI-REQUEST.json'
    if not isinstance(payload, dict) or set(payload) != set(changed) - {request_rel}:
        raise PilotError('control payload hash inventory mismatch')
    for rel,expected in payload.items():
        if not isinstance(expected,str) or digest(repo/rel)!=expected: raise PilotError('control payload hash mismatch: '+rel)
    if git(repo,'diff','--diff-filter=D','--name-only',req['control_parent'],os.environ['GITHUB_SHA']): raise PilotError('control deletion forbidden')
    workflow=validate_workflow(repo/req['workflow'])
    return {'state':'STATIC_PASS','proof_credit':'NONE','request_sha256':request_hash(),'workflow':workflow}

def main():
    p=argparse.ArgumentParser(); sp=p.add_subparsers(dest='cmd',required=True)
    x=sp.add_parser('validate');x.add_argument('--repo',type=Path,default=REPO)
    x=sp.add_parser('check-source');x.add_argument('--std',type=Path,required=True);x.add_argument('--tool',type=Path,required=True)
    x=sp.add_parser('run');x.add_argument('--std',type=Path,required=True);x.add_argument('--tool',type=Path,required=True);x.add_argument('--out',type=Path,required=True);x.add_argument('--setup-receipt',type=Path,required=True)
    x=sp.add_parser('finish');x.add_argument('--out',type=Path,required=True)
    x=sp.add_parser('_root');x.add_argument('--root',required=True);x.add_argument('--std',type=Path,required=True);x.add_argument('--tool',type=Path,required=True);x.add_argument('--out',type=Path,required=True);x.add_argument('--target',type=Path,required=True);x.add_argument('--invocation',required=True)
    a=p.parse_args()
    try:
        if a.cmd=='validate': result=check_control(a.repo.resolve())
        elif a.cmd=='check-source': result={'exit_code':check_source(a.std,a.tool),'proof_credit':'NONE'}
        elif a.cmd=='run': result={'status':'COMPLETE' if campaign(a.std,a.tool,a.out,a.setup_receipt)==0 else 'FAILED','proof_credit':'NONE'}
        elif a.cmd=='finish': result={'status':'MATERIALIZED','exit_code':finish(a.out,Path(os.environ['SETUP_RECEIPT']) if os.environ.get('SETUP_RECEIPT') else None),'proof_credit':'NONE'}
        else: result={'exit_code':run_one(a.root,a.std,a.tool,a.out,a.target,a.invocation),'proof_credit':'NONE'}
        print(json.dumps(result,sort_keys=True));return 0 if result.get('exit_code',0)==0 and result.get('status','COMPLETE')!='FAILED' else 1
    except Exception as e:
        print(json.dumps({'error':f'{type(e).__name__}: {e}','proof_credit':'NONE'}),file=sys.stderr);return 1
if __name__=='__main__': raise SystemExit(main())
