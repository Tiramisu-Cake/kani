"""Synthetic YAML/control/fallback checks; never calls build/toolchain commands."""
import copy
import hashlib
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import yaml
import check_package as c


def fast_dump(value, **kwargs):
    return yaml.dump(value, Dumper=getattr(yaml, 'CSafeDumper', yaml.SafeDumper), **kwargs)


class PackageTests(unittest.TestCase):
    def test_yaml_valid_and_sensitivity(self):
        source=Path(__file__).resolve().parents[1]/'.github/workflows/ch8-s1.yml'
        self.assertEqual(c.check_yaml(source)['yaml'],'PASS')
        doc=c.load_yaml(source.read_text())
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'workflow.yml'
            for mutate in [lambda x:x['on'].update({'workflow_dispatch':{}}),
                lambda x:next(s for s in x['jobs']['s1_light']['steps'] if s['name']=='Run grouped S1 batch with per-harness timeout').update({'run':'python3 runner.py list'}),
                lambda x:x['jobs']['s1_light'].update({'env':{'TEMP':'${{ runner.temp }}'}}),
                lambda x:x['jobs']['s1_light']['steps'][1]['with'].update({'fetch-depth':'1'}),
                lambda x:x['jobs']['s1_light'].update({'runs-on':'self-hosted'}),
                lambda x:x['on']['push'].update({'branches':['uninit-ci/ch8-s1-*']}),
                lambda x:x['jobs']['s1_light'].update({'if':"${{ github.repository == 'Tiramisu-Cake/verify-rust-std' && github.event_name == 'push' }}"}),
                lambda x:x['jobs']['s1_light']['steps'][1]['with'].update({'ref':'main'}),
                lambda x:next(s for s in x['jobs']['s1_light']['steps'] if s.get('with',{}).get('path')=='export')['with'].update({'repository':'Tiramisu-Cake/kani'}),
                lambda x:next(s for s in x['jobs']['s1_light']['steps'] if s.get('with',{}).get('path')=='export')['with'].update({'submodules':False}),
                lambda x:next(s for s in x['jobs']['s1_light']['steps'] if s.get('with',{}).get('path')=='tool')['with'].update({'ref':'main'})]:
                bad=copy.deepcopy(doc);mutate(bad);p.write_text(fast_dump(bad))
                with self.assertRaises(AssertionError):c.check_yaml(p)

    def test_native_scalar_types_reject_each_quoted_or_wrong_type_field(self):
        source=Path(__file__).resolve().parents[1]/'.github/workflows/ch8-s1.yml'
        doc=c.load_yaml(source.read_text())
        self.assertIn('on', c.load_yaml('on: push\n'))
        self.assertEqual(c.load_yaml('value: yes\n'), {'value':'yes'})

        def typed_leaves(value, path=()):
            if type(value) in (bool, int):
                yield path, value
            elif isinstance(value, dict):
                for key, child in value.items():
                    yield from typed_leaves(child, path+(key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    yield from typed_leaves(child, path+(index,))

        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'workflow.yml'
            for path, value in typed_leaves(doc):
                quoted=str(value).lower()
                wrong=[quoted, None, [], {}]
                wrong += [0, 1, 'yes'] if type(value) is bool else [True, False, 1.5, -1]
                for replacement in wrong:
                    bad=copy.deepcopy(doc); parent=bad
                    for key in path[:-1]: parent=parent[key]
                    parent[path[-1]]=replacement
                    p.write_text(fast_dump(bad, sort_keys=False))
                    with self.subTest(path=path, replacement=replacement):
                        with self.assertRaisesRegex(AssertionError, 'expected native'):
                            c.check_yaml(p)
            # Check optional schema flags at job, step and job-concurrency scope.
            for target, key in [(doc['jobs']['s1_light'], 'continue-on-error'),
                                (doc['jobs']['s1_light']['steps'][0], 'continue-on-error')]:
                target[key]=False
                c.check_scalar_types(doc)
                target[key]='false'
                with self.assertRaisesRegex(AssertionError, 'expected native boolean'):
                    c.check_scalar_types(doc)
                del target[key]
            doc['jobs']['s1_light']['concurrency']={'group':'test','cancel-in-progress':'false'}
            with self.assertRaisesRegex(AssertionError, 'expected native boolean'):
                c.check_scalar_types(doc)

    def test_control_guards_and_payload_drift(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);repo=root/'control';here=repo/'ch8-s1-control';here.mkdir(parents=True)
            payload=here/'payload.py';payload.write_text('synthetic')
            rel='ch8-s1-control/payload.py'
            req={'status':'READY','tool_sha':'a'*40,'ci_payload_sha256':{rel:hashlib.sha256(payload.read_bytes()).hexdigest()},'ci_changed_paths':[rel]}
            (here/'CI-REQUEST.json').write_text(json.dumps(req))
            responses={('rev-parse','HEAD'):'b'*40,('rev-parse','HEAD^'):'a'*40,
                ('rev-list','--parents','-n','1','HEAD'):'b'*40+' '+'a'*40,
                ('status','--porcelain','--untracked-files=no'):'',
                ('diff','--name-only','a'*40,'HEAD'):rel,
                ('ls-tree','-r','--name-only','HEAD','.github/workflows'):'.github/workflows/ch8-s1.yml'}
            env={'GITHUB_REPOSITORY':'Tiramisu-Cake/kani','GITHUB_EVENT_NAME':'push',
                 'GITHUB_REF':'refs/heads/uninit-ci/ch8-s1k-synthetic','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'b'*40}
            with patch.object(c,'HERE',here),patch.object(c,'git',side_effect=lambda repo,*args:responses[args]),patch.dict(os.environ,env,clear=True),patch.object(c,'check_yaml') as yaml_check:
                self.assertEqual(c.control(repo)['status'],'PASS')
                yaml_check.assert_called_once_with(repo/'.github/workflows/ch8-s1.yml')
                with patch.object(c,'check_yaml',side_effect=AssertionError('schema type failure')):
                    with self.assertRaisesRegex(AssertionError, 'schema type failure'):c.control(repo)
                for key,value in [('GITHUB_REPOSITORY','other/repo'),('GITHUB_EVENT_NAME','workflow_dispatch'),
                                  ('GITHUB_REF','refs/heads/main'),('GITHUB_REF','refs/heads/uninit-ci/ch8-s1-old'),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_SHA','c'*40)]:
                    with patch.dict(os.environ,{key:value}):
                        with self.assertRaises(AssertionError):c.control(repo)
                for args,bad in [
                    (('rev-parse','HEAD^'),'c'*40),
                    (('status','--porcelain','--untracked-files=no'),' M ch8-s1-control/payload.py'),
                    (('diff','--name-only','a'*40,'HEAD'),'kani-driver/src/main.rs'),
                    (('diff','--name-only','a'*40,'HEAD'),rel+'\nch8-s1-control/unlisted.py'),
                    (('ls-tree','-r','--name-only','HEAD','.github/workflows'),'.github/workflows/ch8-s1.yml\n.github/workflows/extra.yml')]:
                    original=responses[args];responses[args]=bad
                    with self.subTest(args=args,bad=bad):
                        with self.assertRaises(AssertionError):c.control(repo)
                    responses[args]=original
                responses[('rev-list','--parents','-n','1','HEAD')]+=' '+'c'*40
                with self.assertRaises(AssertionError):c.control(repo)
                responses[('rev-list','--parents','-n','1','HEAD')]='b'*40+' '+'a'*40
                payload.write_text('drift')
                with self.assertRaises(AssertionError):c.control(repo)
                payload.write_text('synthetic')
                (root/'Cargo.toml').write_text('[workspace]')
                with self.assertRaises(AssertionError):c.control(repo)

    def test_checkout_depth_policy_in_every_job(self):
        source=Path(__file__).resolve().parents[1]/'.github/workflows/ch8-s1.yml'
        doc=c.load_yaml(source.read_text())
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'workflow.yml'
            for job_name, job in doc['jobs'].items():
                for index, step in enumerate(job['steps']):
                    if not step.get('uses','').startswith('actions/checkout@'):
                        continue
                    checkout=step['with']['path']
                    for depth in ([0,1,2,3,4,6] if checkout=='control' else [0,1,3]):
                        bad=copy.deepcopy(doc)
                        bad['jobs'][job_name]['steps'][index]['with']['fetch-depth']=depth
                        path.write_text(fast_dump(bad,sort_keys=False))
                        with self.subTest(job=job_name,checkout=checkout,depth=depth):
                            with self.assertRaisesRegex(AssertionError,'checkout depth must be'):
                                c.check_yaml(path)

    def test_every_checkout_shallow_clone_runs_real_identity_operations(self):
        # Use an actual file:// transport (never local-clone hardlinks/alternates).
        # An extra older commit makes all selected checkouts genuinely shallow.
        import runner
        source=Path(__file__).resolve().parents[1]/'.github/workflows/ch8-s1.yml'
        doc=c.load_yaml(source.read_text())
        def git(repo,*args):
            return subprocess.check_output(['git','-C',str(repo),*args],
                                           text=True,stderr=subprocess.PIPE).strip()
        def commit(repo,message):
            git(repo,'add','.')
            git(repo,'-c','user.name=Synthetic','-c','user.email=synthetic@invalid',
                'commit','--allow-empty','-qm',message)
            return git(repo,'rev-parse','HEAD')
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); origin=root/'origin';origin.mkdir()
            git(origin,'init','-q')
            (origin/'seed.txt').write_text('synthetic source\n')
            older=commit(origin,'older')
            tool_sha=commit(origin,'tool');git(origin,'branch','tool',tool_sha)
            tool_tree=git(origin,'rev-parse','HEAD^{tree}')
            commit(origin,'prior control')
            commit(origin,'reviewed S1-07 control')
            parent=commit(origin,'parent');git(origin,'branch','export',parent)
            std_tree=git(origin,'rev-parse','HEAD^{tree}')
            here=origin/'ch8-s1-control';here.mkdir()
            workflow=origin/'.github/workflows/ch8-s1.yml'
            workflow.parent.mkdir(parents=True);workflow.write_bytes(source.read_bytes())
            request={'status':'READY','tool_sha':tool_sha,'control_parent':parent,
                     'workflow_stages':json.loads((c.HERE/'CI-REQUEST.json').read_text())['workflow_stages'],
                     'ci_payload_sha256':{'.github/workflows/ch8-s1.yml':hashlib.sha256(workflow.read_bytes()).hexdigest()},
                     'ci_changed_paths':['.github/workflows/ch8-s1.yml','ch8-s1-control/CI-REQUEST.json'],
                     'changed_file_sha256':{'seed.txt':hashlib.sha256((origin/'seed.txt').read_bytes()).hexdigest()},
                     'source_bindings':{},'rows':[]}
            (here/'CI-REQUEST.json').write_text(json.dumps(request))
            control_sha=commit(origin,'control');git(origin,'branch','control',control_sha)
            env={'GITHUB_REPOSITORY':'Tiramisu-Cake/kani','GITHUB_EVENT_NAME':'push',
                 'GITHUB_REF':'refs/heads/uninit-ci/ch8-s1k-synthetic',
                 'GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':control_sha}
            def clone(destination,branch,depth):
                subprocess.run(['git','clone','-q','--no-local','--single-branch',
                                '--branch',branch,'--depth',str(depth),origin.as_uri(),str(destination)],
                               check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                self.assertEqual(git(destination,'rev-parse','--is-shallow-repository'),'true')
                self.assertFalse((destination/'.git/objects/info/alternates').exists())
                self.assertEqual(int(git(destination,'rev-list','--count','HEAD')),depth)
            for name,job in doc['jobs'].items():
                jobroot=root/name;jobroot.mkdir()
                depths={s['with']['path']:s['with']['fetch-depth'] for s in job['steps']
                        if s.get('uses','').startswith('actions/checkout@')}
                for checkout,depth in depths.items():
                    clone(jobroot/checkout,checkout,depth)
                control=jobroot/'control';std=jobroot/'export';tool=jobroot/'tool'
                with self.subTest(job=name),patch.object(c,'HERE',control/'ch8-s1-control'),patch.dict(os.environ,env):
                    self.assertEqual(c.control(control)['status'],'PASS')
                    # The tool commit is the shallow boundary, but endpoint diff works.
                    self.assertEqual(git(control,'diff','--name-only',tool_sha,'HEAD').splitlines(),
                                     request['ci_changed_paths'])
                    with self.assertRaises(subprocess.CalledProcessError):
                        git(control,'cat-file','-t',older)
                with patch.object(runner,'STD_SHA',parent),patch.object(runner,'STD_TREE',std_tree),\
                     patch.object(runner,'TOOL_SHA',tool_sha),patch.object(runner,'TOOL_TREE',tool_tree):
                    self.assertEqual(runner.verify_source(std,tool,request)['std_sha'],parent)
                # Additional validate metadata commands use only current commit/tree.
                for args in [('log','-1','--format=%B'),('log','-1','--format=%an <%ae>'),
                             ('rev-parse','HEAD^{tree}')]:
                    self.assertTrue(git(control,*args))
            # Reproduce the reported error: HEAD^ exists at 2, tool base does not.
            bad=root/'too-shallow';clone(bad,'control',2)
            self.assertEqual(git(bad,'rev-parse','HEAD^'),parent)
            with patch.object(c,'HERE',bad/'ch8-s1-control'),patch.dict(os.environ,env):
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    c.control(bad)
                self.assertEqual(caught.exception.returncode,128)
                self.assertEqual(caught.exception.cmd[-4:],['diff','--name-only',tool_sha,'HEAD'])
            one=root/'depth-one';clone(one,'control',1)
            with self.assertRaises(subprocess.CalledProcessError):git(one,'rev-parse','HEAD^')

    def test_matrix_partition_and_fallback_subset(self):
        here=Path(__file__).resolve().parent
        request=json.loads((here/'CI-REQUEST.json').read_text())
        staged=[g for groups in request['workflow_stages'].values() for g in groups]
        self.assertEqual(staged,[g['id'] for g in request['execution_groups']])
        self.assertEqual(len(staged),len(set(staged)))
        self.assertEqual(len(request['rows']),35)
        for group in request['execution_groups']:
            envelope=900+600*len(group['row_ids'])+10
            self.assertLessEqual(envelope,8100)
            self.assertLessEqual(1800+envelope+900,180*60)
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'receipts'
            chosen=request['execution_groups'][-1]
            c.fallback(out,[chosen['id']])
            actual={p.parent.name for p in out.glob('*/receipt.json')}
            self.assertEqual(actual,set(chosen['row_ids']))
            self.assertEqual({p.name for p in (out/'groups').iterdir()},{chosen['id']})
            with self.assertRaises(AssertionError):c.fallback(out,['unknown'])

    def test_collection_rejects_duplicate_wrong_pin_and_retains_missing(self):
        import collect
        import runner
        request=json.loads((Path(__file__).resolve().parent/'CI-REQUEST.json').read_text())
        identity={key:request[key] for key in ('std_sha','std_tree','tool_sha','tool_tree')}
        digest=runner.sha256(runner.REQUEST_PATH)
        byid={row['id']:row for row in request['rows']}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);roots=[]
            for group in request['execution_groups']:
                dest=root/group['id'];dest.mkdir();roots.append(dest)
                rows=[{**byid[rid],'group':group['id'],'status':'NOT_RUN','outcome':'UNKNOWN'} for rid in group['row_ids']]
                terminal={**identity,'request_sha256':digest,'selected_groups':[group['id']],'rows':rows}
                (dest/'receipt.json').write_text(json.dumps(terminal))
                groupdest=dest/'groups'/group['id'];groupdest.mkdir(parents=True)
                source={**identity,'changed_file_sha256':request['changed_file_sha256']}
                (groupdest/'receipt.json').write_text(json.dumps({'state':'NOT_RUN','request_sha256':digest,'source_before':source,'source_after':source}))
            result=collect.collect(roots,request)
            self.assertEqual(result['missing_groups'],[])
            self.assertEqual(result['proof_credit'],'NONE')
            self.assertFalse(any(u['eligible_for_review'] for u in result['replacement_unions']))
            self.assertEqual(collect.collect(roots[:-1],request)['missing_groups'],[request['execution_groups'][-1]['id']])
            with self.assertRaises(runner.RunnerError):collect.collect(roots+[roots[0]],request)
            path=roots[0]/'receipt.json';original=path.read_text()
            for mutation in [None,[],{**json.loads(original),'std_sha':'0'*40},
                             {**json.loads(original),'request_sha256':'0'*64}]:
                path.write_text(json.dumps(mutation))
                with self.assertRaises(runner.RunnerError):collect.collect(roots,request)
            path.write_text(original)
            group=request['execution_groups'][0];gpath=roots[0]/'groups'/group['id']/'receipt.json'
            bad=json.loads(gpath.read_text());bad['source_after']=None;gpath.write_text(json.dumps(bad))
            result=collect.collect(roots,request)
            self.assertTrue(all(row['outcome']=='UNKNOWN' for row in result['rows'] if row['id'] in group['row_ids']))

    def test_fallback_terminal_after_setup_failure_and_mid_run_interruption(self):
        import collect
        request=json.loads((Path(__file__).resolve().parent/'CI-REQUEST.json').read_text())
        chosen=request['execution_groups'][-1]
        with tempfile.TemporaryDirectory() as d:
            out=Path(d)/'receipts'
            c.fallback(out,[chosen['id']])
            terminal=json.loads((out/'receipt.json').read_text())
            self.assertEqual(terminal['state'],'FALLBACK_INCOMPLETE')
            self.assertEqual(terminal['selected_groups'],[chosen['id']])
            result=collect.collect([out],request)
            self.assertTrue(all(row['outcome']=='UNKNOWN' for row in result['rows']))
            self.assertEqual(result['proof_credit'],'NONE')
            original={'state':'IN_PROGRESS','rows':[],'stop_reason':'captured exception'}
            (out/'receipt.json').write_text(json.dumps(original))
            rid=chosen['row_ids'][0];rowpath=out/rid/'receipt.json'
            row=json.loads(rowpath.read_text());row.update(status='IN_PROGRESS',original_exit_code=42)
            rowpath.write_text(json.dumps(row))
            c.fallback(out,[chosen['id']])
            self.assertEqual(json.loads((out/'interrupted-terminal.json').read_text()),original)
            terminal=json.loads((out/'receipt.json').read_text())
            observed=next(row for row in terminal['rows'] if row['id']==rid)
            self.assertEqual(observed['original_exit_code'],42)
            self.assertEqual(observed['status'],'INTERRUPTED')
            self.assertEqual(collect.collect([out],request)['proof_credit'],'NONE')
            for raw in ['null','[]','{']:
                (out/'receipt.json').write_text(raw)
                c.fallback(out,[chosen['id']])
                self.assertTrue((out/'interrupted-terminal.json').exists())
                self.assertEqual(collect.collect([out],request)['proof_credit'],'NONE')

    def test_build_wrapper_receipts_and_errors_without_build(self):
        import runner
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);epoch=root/'epoch';epoch.write_text('1000')
            result={'original_exit_code':0,'timed_out':False,'termination_reason':None,
                    'stdout_truncated':False,'stderr_truncated':False}
            with patch.object(c.time,'time',return_value=1010),patch.object(runner,'execute',return_value=result.copy()) as execute:
                self.assertEqual(c.build(root,epoch,root/'ok')['setup'],'COMPLETE')
                self.assertEqual(execute.call_args.args[0],['cargo','build-dev','--','--release'])
                self.assertEqual(execute.call_args.args[1],root.resolve())
                for key,value in [('original_exit_code',42),('timed_out',True),
                                  ('termination_reason','signal'),('stdout_truncated',True),('stderr_truncated',True)]:
                    execute.return_value={**result,key:value}
                    out=root/key
                    with self.assertRaises(AssertionError):c.build(root,epoch,out)
                    self.assertEqual(json.loads((out/'receipt.json').read_text())[key],value)
                execute.side_effect=OSError('synthetic launch error')
                with self.assertRaises(OSError):c.build(root,epoch,root/'exception')
            with patch.object(c.time,'time',return_value=2801),patch.object(runner,'execute') as execute:
                with self.assertRaises(AssertionError):c.build(root,epoch,root/'expired')
                execute.assert_not_called()

    def test_fallback_preserves_receipt_materializes_tail_and_bounds(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);here=root/'control';here.mkdir();out=root/'receipts';out.mkdir()
            request={'rows':[{'id':s,'selector':'x::'+s,'mode':'Original','variant':'production','unwind':34} for s in ['done','tail']],
                     'budgets':{'artifact_bytes':10000}}
            (here/'CI-REQUEST.json').write_text(json.dumps(request))
            done=out/'done';done.mkdir();(done/'receipt.json').write_text('{"original_exit_code":42}')
            with patch.object(c,'HERE',here):
                c.fallback(out)
                self.assertEqual(json.loads((done/'receipt.json').read_text())['original_exit_code'],42)
                self.assertEqual(json.loads((out/'tail/receipt.json').read_text())['status'],'NOT_RUN')
                list_receipt=out/'groups/production-u34/compile/receipt.json'
                self.assertEqual(json.loads(list_receipt.read_text())['state'],'NOT_RUN_OR_INTERRUPTED')
                list_receipt.write_text(json.dumps({'state':'IN_PROGRESS','execution':{'signal':None}}))
                c.fallback(out)
                self.assertEqual(json.loads(list_receipt.read_text())['state'],'INTERRUPTED')
                complete='{"state":"COMPLETE","execution":{"original_exit_code":0}}'
                list_receipt.write_text(complete)
                c.fallback(out)
                self.assertEqual(list_receipt.read_text(),complete)
                pending=out/'tail/receipt.json'
                pending.write_text(json.dumps({'status':'IN_PROGRESS','original_exit':None,'signal':None,'group':'production-u34'}))
                (out/'groups/production-u34/stdout.log').write_text('row interrupted tail')
                c.fallback(out)
                value=json.loads(pending.read_text())
                self.assertEqual(value['status'],'INTERRUPTED')
                self.assertEqual(value['outcome'],'UNKNOWN')
                self.assertIn('row interrupted tail',value['stdout']['head'])
                self.assertFalse((out/'list').exists())
                (out/'oversize.log').write_bytes(b'x'*20000)
                c.fallback(out)
                self.assertTrue((out/'TRUNCATED.json').is_file())
                self.assertFalse((out/'oversize.log').exists())


if __name__=='__main__':unittest.main()
