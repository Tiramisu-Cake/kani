#!/usr/bin/env python3
"""Exact workflow Validate unit/service step. Never executes a native tool."""
import importlib,json,os,sys,tempfile,time,unittest
from pathlib import Path
from unittest import mock
import runner
import check_package
HERE=Path(__file__).resolve().parent
LEGACY=('test_runner','test_s107.FinalizationTests','test_s2','test_cfg_pfc','test_rustc_diagnostics','test_contract_stacks','test_r1403_lexical','test_r5')


def legacy_suite():
    """Explicit frozen R5 test inputs, against current runner/service code.

    Only fixture locations/default request change in this test context. Legacy
    source/policy gates and their failure controls remain active and unchanged.
    """
    with tempfile.TemporaryDirectory() as d:
        root=Path(d)/'control';here=root/'ch8-s1-control';here.mkdir(parents=True)
        for f in HERE.iterdir():
            if f.name!='CI-REQUEST.json':(here/f.name).symlink_to(f,target_is_directory=f.is_dir())
        (here/'CI-REQUEST.json').write_bytes((HERE/'fixtures/r5-request.json').read_bytes())
        workflow=root/'.github/workflows/ch8-s2.yml';workflow.parent.mkdir(parents=True)
        workflow.write_bytes((HERE/'fixtures/r5-workflow.yml').read_bytes())
        modules={name.split('.')[0]:importlib.import_module(name.split('.')[0]) for name in LEGACY}
        original=runner.load_request
        def load(path=None):return original(path if path is not None else here/'CI-REQUEST.json')
        from contextlib import ExitStack
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(runner,'load_request',side_effect=load))
            stack.enter_context(mock.patch.object(runner,'REQUEST_PATH',here/'CI-REQUEST.json'))
            stack.enter_context(mock.patch.object(runner,'HERE',here))
            stack.enter_context(mock.patch.object(check_package,'HERE',here))
            for module in modules.values():
                if hasattr(module,'HERE'):stack.enter_context(mock.patch.object(module,'HERE',here))
            suite=unittest.defaultTestLoader.loadTestsFromNames(LEGACY)
            return unittest.TextTestRunner(verbosity=2).run(suite)


def main():
    start=time.monotonic()
    legacy=legacy_suite()
    current=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(('test_s3','test_s3_repair','test_s3_paths')))
    result={'schema':'ch8-s3-validate-v1','elapsed_seconds':time.monotonic()-start,
        'legacy_tests':legacy.testsRun,'s3_tests':current.testsRun,
        'failures':len(legacy.failures)+len(current.failures),'errors':len(legacy.errors)+len(current.errors),
        'success':legacy.wasSuccessful() and current.wasSuccessful(),'native_compile':'NOT_RUN','proof_credit':'NONE'}
    print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['success'] else 1
if __name__=='__main__':raise SystemExit(main())
