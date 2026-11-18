"""Controller-owned protected E0/pre/post capture. A worker cannot redefine E0."""
import time
from pathlib import Path
import runner as r
from s3_runtime import diagnostic


def capture(std,tool,request,context,epoch,shutdown=None):
    doc={'schema':'ch8-s3-protected-snapshot-v1','context':dict(context),'epoch':epoch,
         'monotonic':time.monotonic(),'source':None,'control':None,'binaries':None,
         'request_sha256':None,'errors':[],'state':'INCOMPLETE','shutdown':shutdown}
    if epoch.endswith('.post') and (not isinstance(shutdown,dict) or shutdown.get('verified') is not True):
        doc['errors'].append({'operation':'snapshot.post','reason':'TREE_SHUTDOWN_NOT_VERIFIED'})
        return doc
    for name,operation in [('request_sha256',lambda:r.sha256(r.REQUEST_PATH)),
        ('source',lambda:r.verify_source(std,tool,request)),
        ('control',lambda:{'sha':r.git(r.HERE.parent,'rev-parse','HEAD'),'tree':r.git(r.HERE.parent,'rev-parse','HEAD^{tree}'),
                            'parent':r.git(r.HERE.parent,'rev-parse','HEAD^'),'dirty':r.git(r.HERE.parent,'status','--porcelain=v1')}),
        ('binaries',lambda:r.snapshot_binaries(tool,{},'after' if epoch.endswith('.post') else 'before'))]:
        try:doc[name]=operation()
        except BaseException as exc:doc['errors'].append(diagnostic(exc,'snapshot.'+name,epoch=epoch))
    if (not doc['errors'] and doc['source']=={k:request[k] for k in ('std_sha','std_tree','tool_sha','tool_tree','changed_file_sha256')}
        and isinstance(doc['control'],dict) and not doc['control']['dirty'] and doc['control']['parent']==request['control_parent']
        and r.fingerprints_match(doc['binaries'],doc['binaries'])):doc['state']='COMPLETE'
    return doc


def validate_pair(baseline,pre,post,context):
    base_context=context.get('baseline_context')
    if (not isinstance(base_context,dict) or type(context.get('rank')) is not int or not 1<=context['rank']<=9
        or context.get('epoch')!='E'+str(context['rank']) or not isinstance(context.get('invocation_id'),str)
        or not context['invocation_id'] or not isinstance(context.get('root'),str) or not context['root']
        or any(context.get(k)!=base_context.get(k) or context.get(k) is None for k in ('campaign_id','request_sha256','source_parent','control_parent'))):
        raise ValueError('snapshot baseline/parent/request/rank context mismatch')
    for x,epoch in ((baseline,'E0'),(pre,context['epoch']+'.pre'),(post,context['epoch']+'.post')):
        if not isinstance(x,dict) or x.get('state')!='COMPLETE' or x.get('errors')!=[] or x.get('epoch')!=epoch:
            raise ValueError('protected snapshot incomplete/wrong epoch')
        if x.get('context')!=(context if epoch!='E0' else context['baseline_context']):
            raise ValueError('protected snapshot invocation/root/parent context mismatch')
        for key in ('request_sha256','source','control'):
            if x.get(key)!=baseline.get(key) or x.get(key) is None:raise ValueError('protected '+key+' drift/unavailable')
        if not r.fingerprints_match(baseline.get('binaries'),x.get('binaries')):raise ValueError('protected binary drift/unavailable')
    if not (baseline['monotonic']<=pre['monotonic']<=post['monotonic']):raise ValueError('snapshot epoch time order')
    if not isinstance(post.get('shutdown'),dict) or post['shutdown'].get('verified') is not True:raise ValueError('snapshot missing verified tree shutdown')
    return True
