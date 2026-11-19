#!/usr/bin/env python3
"""Final exact offline Validate: protected legacy suites plus bounded S3-2 services."""
import importlib,json,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest import mock
from contextlib import ExitStack
import runner,check_package,s3_validate
HERE=Path(__file__).resolve().parent
NEW=('test_s32.SourceTests','test_s32.RoleTests','test_s32.CampaignTests',
     'test_s32.WorkflowTests','test_s32.SingletonRunnerTests','test_s32_boundary',
     'test_s32_paths.RealPathWriterTests.test_workflow_relative_entry_real_writer_and_portable_replay',
     'test_s32_paths.RealPathWriterTests.test_real_hash_mutation_global_stop_and_portable_prefix',
     'test_s32_paths.RealPathWriterTests.test_genuine_absent_after_interruption_and_original_exit_preserved',
     'test_s32_paths.RealPathWriterTests.test_actual_killed_python_worker_has_genuinely_absent_after')

def old_s3_suite():
    names=('test_s3','test_s3_repair','test_s3_paths')
    with tempfile.TemporaryDirectory() as d,ExitStack() as stack:
        root=Path(d)/'control';here=root/'ch8-s1-control';here.mkdir(parents=True)
        for file in HERE.iterdir():
            if file.name!='CI-REQUEST.json':(here/file.name).symlink_to(file,target_is_directory=file.is_dir())
        (here/'CI-REQUEST.json').write_bytes((HERE/'fixtures/s3-1-request.json').read_bytes())
        workflow=root/'.github/workflows/ch8-s2.yml';workflow.parent.mkdir(parents=True)
        workflow.write_bytes((HERE/'fixtures/s3-1-workflow.yml').read_bytes())
        original=runner.load_request
        def load(path=None):return original(path if path is not None else here/'CI-REQUEST.json')
        modules=[importlib.import_module(n) for n in names]
        stack.enter_context(mock.patch.object(runner,'load_request',side_effect=load))
        for module in [runner,check_package,*modules]:
            if hasattr(module,'HERE'):stack.enter_context(mock.patch.object(module,'HERE',here))
        stack.enter_context(mock.patch.object(runner,'REQUEST_PATH',here/'CI-REQUEST.json'))
        return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(names))

def main():
    started=time.monotonic()
    legacy=s3_validate.legacy_suite();old=old_s3_suite()
    new=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(NEW))
    runs=[legacy,old,new]
    git=lambda arg:subprocess.check_output(['git','-C',str(HERE.parent),'rev-parse',arg],text=True).strip()
    result={'schema':'ch8-s3-2-validate-v1','control_sha':git('HEAD'),'control_tree':git('HEAD^{tree}'),
        'request_sha256':runner.sha256(HERE/'CI-REQUEST.json'),'elapsed_seconds':time.monotonic()-started,
        'legacy_tests':legacy.testsRun,'protected_s3_1_tests':old.testsRun,'s3_2_tests':new.testsRun,
        'failures':sum(len(x.failures) for x in runs),'errors':sum(len(x.errors) for x in runs),
        'success':all(x.wasSuccessful() for x in runs),'native_compile_proof_fit':'NOT_RUN','proof_credit':'NONE'}
    print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['success'] else 1
if __name__=='__main__':raise SystemExit(main())
