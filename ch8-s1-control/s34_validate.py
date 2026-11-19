#!/usr/bin/env python3
"""Final exact offline Validate; protected legacy/S3/S32 plus bridge regressions."""
import importlib,json,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest import mock
from contextlib import ExitStack
import runner,check_package,s3_validate,s32_validate
HERE=Path(__file__).resolve().parent
NEW=('test_s34.SourceTests','test_s34.RoleTests','test_s34.CampaignTests',
     'test_s34.WorkflowTests','test_s34.SingletonRunnerTests','test_s34_boundary.BoundaryTests',
     'test_s34_boundary.CellGateTests.test_cell_missing_constructor_or_method_anchor_fails_closed',
     'test_s34_paths.RealPathWriterTests.test_workflow_relative_entry_real_writer_and_portable_replay',
     'test_s34_paths.RealPathWriterTests.test_selected_count_real_writer_and_both_readers',
     'test_s34_paths.RealPathWriterTests.test_selected_count_stopped_and_partial_prefix',
     'test_s34_paths.RealPathWriterTests.test_selected_count_without_completions',
     'test_s34_paths.RealPathWriterTests.test_selected_count_requires_validated_request_inventory',
     'test_s34_paths.RealPathWriterTests.test_missing_binary_and_real_read_error_fail_closed',
     'test_s34_paths.RealPathWriterTests.test_all_states_recorded_drift_cannot_use_controller_recovery',
     'test_s34_paths.RealPathWriterTests.test_genuine_absent_after_interruption_and_original_exit_preserved')

def old_s32_suite():
    names=s32_validate.NEW
    with tempfile.TemporaryDirectory() as d,ExitStack() as stack:
        root=Path(d)/'control';here=root/'ch8-s1-control';here.mkdir(parents=True)
        for file in HERE.iterdir():
            if file.name!='CI-REQUEST.json':(here/file.name).symlink_to(file,target_is_directory=file.is_dir())
        (here/'CI-REQUEST.json').write_bytes((HERE/'fixtures/s3-2-request.json').read_bytes())
        workflow=root/'.github/workflows/ch8-s2.yml';workflow.parent.mkdir(parents=True)
        workflow.write_bytes((HERE/'fixtures/s3-2-workflow.yml').read_bytes())
        original=runner.load_request
        def load(path=None):return original(path if path is not None else here/'CI-REQUEST.json')
        modules={n.split('.')[0]:importlib.import_module(n.split('.')[0]) for n in names}
        stack.enter_context(mock.patch.object(runner,'load_request',side_effect=load))
        stack.enter_context(mock.patch.object(runner,'REQUEST_PATH',here/'CI-REQUEST.json'))
        for module in [runner,check_package,*modules.values()]:
            if hasattr(module,'HERE'):stack.enter_context(mock.patch.object(module,'HERE',here))
        return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(names))

def main():
    started=time.monotonic()
    legacy=s3_validate.legacy_suite();s3=s32_validate.old_s3_suite();s32=old_s32_suite()
    new=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(NEW))
    runs=[legacy,s3,s32,new]
    git=lambda arg:subprocess.check_output(['git','-C',str(HERE.parent),'rev-parse',arg],text=True).strip()
    result={'schema':'ch8-s3s4-bridge1-validate-v1','control_sha':git('HEAD'),'control_tree':git('HEAD^{tree}'),
        'request_sha256':runner.sha256(HERE/'CI-REQUEST.json'),'elapsed_seconds':time.monotonic()-started,
        'legacy_tests':legacy.testsRun,'protected_s3_1_tests':s3.testsRun,'protected_s3_2_tests':s32.testsRun,'bridge1_tests':new.testsRun,
        'failures':sum(len(x.failures) for x in runs),'errors':sum(len(x.errors) for x in runs),
        'success':all(x.wasSuccessful() for x in runs),'native_compile_proof_fit':'NOT_RUN','proof_credit':'NONE'}
    result['margin_at_18_minutes']=1080/result['elapsed_seconds']
    print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['success'] else 1
if __name__=='__main__':raise SystemExit(main())
