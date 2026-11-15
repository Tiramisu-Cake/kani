"""Synthetic YAML/control/fallback checks; never calls build/toolchain commands."""
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import yaml
import check_package as c


class PackageTests(unittest.TestCase):
    def test_yaml_valid_and_sensitivity(self):
        source=Path(__file__).resolve().parents[1]/'.github/workflows/ch8-s1.yml'
        self.assertEqual(c.check_yaml(source)['yaml'],'PASS')
        doc=yaml.load(source.read_text(),Loader=yaml.BaseLoader)
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'workflow.yml'
            for mutate in [lambda x:x['on'].update({'workflow_dispatch':{}}),
                lambda x:x['jobs']['s1'].update({'env':{'TEMP':'${{ runner.temp }}'}}),
                lambda x:x['jobs']['s1']['steps'][1]['with'].update({'fetch-depth':'1'}),
                lambda x:x['jobs']['s1'].update({'runs-on':'self-hosted'}),
                lambda x:x['on']['push'].update({'branches':['uninit-ci/ch8-s1-*']}),
                lambda x:x['jobs']['s1'].update({'if':"${{ github.repository == 'Tiramisu-Cake/verify-rust-std' && github.event_name == 'push' }}"}),
                lambda x:x['jobs']['s1']['steps'][1]['with'].update({'ref':'main'}),
                lambda x:next(s for s in x['jobs']['s1']['steps'] if s.get('with',{}).get('path')=='export')['with'].update({'repository':'Tiramisu-Cake/kani'}),
                lambda x:next(s for s in x['jobs']['s1']['steps'] if s.get('with',{}).get('path')=='export')['with'].update({'submodules':'false'}),
                lambda x:next(s for s in x['jobs']['s1']['steps'] if s.get('with',{}).get('path')=='tool')['with'].update({'ref':'main'})]:
                bad=copy.deepcopy(doc);mutate(bad);p.write_text(yaml.safe_dump(bad))
                with self.assertRaises(AssertionError):c.check_yaml(p)

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
                ('diff','--name-only','HEAD^','HEAD'):rel,
                ('ls-tree','-r','--name-only','HEAD','.github/workflows'):'.github/workflows/ch8-s1.yml'}
            env={'GITHUB_REPOSITORY':'Tiramisu-Cake/kani','GITHUB_EVENT_NAME':'push',
                 'GITHUB_REF':'refs/heads/uninit-ci/ch8-s1k-synthetic','GITHUB_RUN_ATTEMPT':'1','GITHUB_SHA':'b'*40}
            with patch.object(c,'HERE',here),patch.object(c,'git',side_effect=lambda repo,*args:responses[args]),patch.dict(os.environ,env,clear=True):
                self.assertEqual(c.control(repo)['status'],'PASS')
                for key,value in [('GITHUB_REPOSITORY','other/repo'),('GITHUB_EVENT_NAME','workflow_dispatch'),
                                  ('GITHUB_REF','refs/heads/main'),('GITHUB_REF','refs/heads/uninit-ci/ch8-s1-old'),('GITHUB_RUN_ATTEMPT','2'),('GITHUB_SHA','c'*40)]:
                    with patch.dict(os.environ,{key:value}):
                        with self.assertRaises(AssertionError):c.control(repo)
                for args,bad in [
                    (('rev-parse','HEAD^'),'c'*40),
                    (('status','--porcelain','--untracked-files=no'),' M ch8-s1-control/payload.py'),
                    (('diff','--name-only','HEAD^','HEAD'),'kani-driver/src/main.rs'),
                    (('diff','--name-only','HEAD^','HEAD'),rel+'\nch8-s1-control/unlisted.py'),
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
            request={'rows':[{'id':s,'selector':'x::'+s,'mode':'Original','variant':'production'} for s in ['done','tail']],
                     'budgets':{'artifact_bytes':10000}}
            (here/'CI-REQUEST.json').write_text(json.dumps(request))
            done=out/'done';done.mkdir();(done/'receipt.json').write_text('{"original_exit_code":42}')
            with patch.object(c,'HERE',here):
                c.fallback(out)
                self.assertEqual(json.loads((done/'receipt.json').read_text())['original_exit_code'],42)
                self.assertEqual(json.loads((out/'tail/receipt.json').read_text())['status'],'NOT_RUN')
                (out/'oversize.log').write_bytes(b'x'*20000)
                c.fallback(out)
                self.assertTrue((out/'TRUNCATED.json').is_file())
                self.assertFalse((out/'oversize.log').exists())


if __name__=='__main__':unittest.main()
