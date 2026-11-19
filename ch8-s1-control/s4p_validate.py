#!/usr/bin/env python3
"""Exact CI Validate: unchanged legacy/S3/S32/bridge controls plus S4 partitions.

Python static/service tests only. No native compiler, expansion or verifier.
"""
import importlib,json,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest import mock
from contextlib import ExitStack
import runner,check_package,s3_validate,s32_validate,s34_validate
HERE=Path(__file__).resolve().parent
NEW=('test_s4p_boundary', 'test_s4p_gate_repair', 'test_s4p.RoleTests', 'test_s4p.CampaignTests',
     'test_s4p.WorkflowTests', 'test_s4p.SingletonRunnerTests',
     'test_s4p_paths.RealPathWriterTests.test_workflow_relative_entry_real_writer_and_portable_replay',
     'test_s4p_paths.RealPathWriterTests.test_selected_count_real_writer_and_both_readers',
     'test_s4p_paths.RealPathWriterTests.test_all_valid_prefix_lengths_replay_local_and_upload',
     'test_s4p_paths.RealPathWriterTests.test_selected_count_stopped_and_partial_prefix',
     'test_s4p_paths.RealPathWriterTests.test_selected_count_without_completions',
     'test_s4p_paths.RealPathWriterTests.test_selected_count_requires_validated_request_inventory',
     'test_s4p_paths.RealPathWriterTests.test_missing_binary_and_real_read_error_fail_closed',
     'test_s4p_paths.RealPathWriterTests.test_all_states_recorded_drift_cannot_use_controller_recovery',
     'test_s4p_paths.RealPathWriterTests.test_genuine_absent_after_interruption_and_original_exit_preserved')
def old_bridge_suite():
    names=s34_validate.NEW
    with tempfile.TemporaryDirectory() as d,ExitStack() as stack:
        root=Path(d)/'control';here=root/'ch8-s1-control';here.mkdir(parents=True)
        for file in HERE.iterdir():
            if file.name!='CI-REQUEST.json':(here/file.name).symlink_to(file,target_is_directory=file.is_dir())
        (here/'CI-REQUEST.json').write_bytes((HERE/'fixtures/s34-request.json').read_bytes())
        workflow=root/'.github/workflows/ch8-s2.yml';workflow.parent.mkdir(parents=True)
        workflow.write_bytes((HERE/'fixtures/s34-workflow.yml').read_bytes())
        original=runner.load_request
        def load(path=None):return original(path if path is not None else here/'CI-REQUEST.json')
        modules={n.split('.')[0]:importlib.import_module(n.split('.')[0]) for n in names}
        stack.enter_context(mock.patch.object(runner,'load_request',side_effect=load))
        stack.enter_context(mock.patch.object(runner,'REQUEST_PATH',here/'CI-REQUEST.json'))
        for module in [runner,check_package,*modules.values()]:
            if hasattr(module,'HERE'):stack.enter_context(mock.patch.object(module,'HERE',here))
        return unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(names))

def run_suites():
    started=time.monotonic()
    runs=[s3_validate.legacy_suite(),s32_validate.old_s3_suite(),s34_validate.old_s32_suite(),old_bridge_suite()]
    runs.append(unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(NEW)))
    git=lambda arg:subprocess.check_output(['git','-C',str(HERE.parent),'rev-parse',arg],text=True).strip()
    result={'schema':'ch8-s4p-1-validate-v1','control_sha':git('HEAD'),'control_tree':git('HEAD^{tree}'),
        'request_sha256':runner.sha256(HERE/'CI-REQUEST.json'),'elapsed_seconds':time.monotonic()-started,
        'test_counts':dict(zip(('legacy','s3','s32','bridge1','s4p'),[x.testsRun for x in runs])),
        'failures':sum(len(x.failures) for x in runs),'errors':sum(len(x.errors) for x in runs),
        'success':all(x.wasSuccessful() for x in runs),'native_compile_proof_cost_fit':'NOT_RUN','proof_credit':'NONE'}
    result['margin_at_18_minutes']=1080/result['elapsed_seconds']
    print(json.dumps(result,sort_keys=True),flush=True)
    return 0 if result['success'] and result['margin_at_18_minutes']>=1.5 else 1

def main():
    from validate_tokens import cached_tokens
    with cached_tokens():return run_suites()
if __name__=='__main__':raise SystemExit(main())
