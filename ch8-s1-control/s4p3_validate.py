#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Prepared final Validate: all366 old tests plus concrete-call regressions.

No invocation is authorized by preparing this file. CI step remains18min and
successful validation additionally requires margin>=1.5 (elapsed<=720s).
"""
import importlib,json,subprocess,tempfile,time,unittest
from contextlib import ExitStack
from pathlib import Path
from unittest import mock
import runner,check_package,s3_validate,s32_validate,s34_validate,s4p_validate,s4p2_validate,s4p2r2_validate
HERE=Path(__file__).resolve().parent
NEW=('test_s4p3_domain','test_s4p3.RoleTests','test_s4p3.CampaignTests',
     'test_s4p3.WorkflowTests','test_s4p3.SingletonRunnerTests')

def old_s4p2r2_suite(names=None):
    names=s4p2r2_validate.NEW if names is None else names
    with tempfile.TemporaryDirectory() as d,ExitStack() as stack:
        root=Path(d)/'control';here=root/'ch8-s1-control';here.mkdir(parents=True)
        for path in HERE.iterdir():
            if path.name!='CI-REQUEST.json':(here/path.name).symlink_to(path,target_is_directory=path.is_dir())
        (here/'CI-REQUEST.json').write_bytes((HERE/'fixtures/s4p2r2-request.json').read_bytes())
        workflow=root/'.github/workflows/ch8-s2.yml';workflow.parent.mkdir(parents=True)
        workflow.write_bytes((HERE/'fixtures/s4p2r2-workflow.yml').read_bytes())
        original=runner.load_request
        def load(path=None):return original(path if path is not None else here/'CI-REQUEST.json')
        modules={name.split('.')[0]:importlib.import_module(name.split('.')[0]) for name in names}
        stack.enter_context(mock.patch.object(runner,'load_request',side_effect=load))
        stack.enter_context(mock.patch.object(runner,'REQUEST_PATH',here/'CI-REQUEST.json'))
        for module in [runner,check_package,*modules.values()]:
            if hasattr(module,'HERE'):stack.enter_context(mock.patch.object(module,'HERE',here))
        return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(names))

def run_suites():
    start=time.monotonic()
    runs=[s3_validate.legacy_suite(),s32_validate.old_s3_suite(),s34_validate.old_s32_suite(),
          s4p_validate.old_bridge_suite(),s4p2_validate.old_s4p_suite(),s4p2r2_validate.old_s4p2_suite(),old_s4p2r2_suite()]
    runs.append(unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(NEW)))
    git=lambda arg:subprocess.check_output(['git','-C',str(HERE.parent),'rev-parse',arg],text=True).strip()
    result={'schema':'ch8-s4p-3-validate-v1','control_sha':git('HEAD'),'control_tree':git('HEAD^{tree}'),
        'request_sha256':runner.sha256(HERE/'CI-REQUEST.json'),'elapsed_seconds':time.monotonic()-start,
        'test_counts':dict(zip(('legacy','s3','s32','bridge1','s4p','s4p2','s4p2r2','s4p3'),[x.testsRun for x in runs])),
        'failures':sum(len(x.failures) for x in runs),'errors':sum(len(x.errors) for x in runs),
        'success':all(x.wasSuccessful() for x in runs),'native_compile_proof_cost_fit':'NOT_RUN','proof_credit':'NONE'}
    result['margin_at_18_minutes']=1080/result['elapsed_seconds'];print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['success'] and result['margin_at_18_minutes']>=1.5 else 1

def main():
    from validate_tokens import cached_tokens
    with cached_tokens(('cfg_pfc','s3_cfg_pfc','s32_cfg_pfc','s34_cfg_pfc','s4p_cfg_pfc','s4p2_cfg_pfc','s4p2r2_cfg_pfc','s4p3_cfg_pfc')):return run_suites()
if __name__=='__main__':raise SystemExit(main())
