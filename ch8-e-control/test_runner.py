"""Synthetic-only tests for the bounded E runner; no Kani or compiler is invoked."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from contextlib import ExitStack

RUNNER_PATH = Path(__file__).with_name("runner.py")
spec = importlib.util.spec_from_file_location("e_runner", RUNNER_PATH)
runner = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(runner)


def example(specification, defs):
    if isinstance(specification, list):
        return []
    if isinstance(specification, dict):
        return {k: example(v, defs) for k, v in specification.items() if not k.startswith("_")}
    if specification.startswith("ref:"):
        return example(defs[specification[4:]], defs)
    if specification.endswith("?"):
        return None
    if specification == "string": return "value"
    if specification == "integer": return 0
    if specification == "number": return 0
    if specification == "boolean": return False
    if specification.startswith("enum:"): return specification[5:].split("|")[0]
    if specification.startswith("pattern:"): return "2026-01-02T03:04:05Z"
    if specification == "named:attribute_kind": return "Proof"
    if specification == "named:solver": return "solver"
    raise AssertionError(specification)


def valid_export(pin, source, harness="root", check="ON"):
    schema = json.loads((runner.REPO / "tests/json-handler/schema-validation/kani_json_schema.json").read_text())
    defs = schema["_defs"]
    value = {k: example(v, defs) for k, v in schema.items() if not k.startswith("_")}
    hs = example(schema["harnesses"][0], defs)
    value["harnesses"] = [hs]
    value.update(schema_version="0.1.0", kani_commit=runner.PIN_DATA[pin]["sha"], kani_commit_dirty=False,
                 enabled_unstable_features=["unstable-options", "loop-contracts", "quantifiers", "export-json"] + (["uninit-checks"] if check == "ON" else []),
                 harness_selection={"requested_filters": [harness], "exact": True, "unmatched_filters": [], "matched_count": 1},
                 harness_timeout_s=600, run_state="COMPLETE")
    value["outcome"] = {"kind": "COMPLETED"}
    value["tools"] = {"kani": "kani", "rustc": "rustc", "cbmc": "cbmc"}
    for field in ("memory_safety", "overflow", "unwinding", "undefined_function", "assert_contracts"):
        value["configuration"]["checks"][field] = True
    value["configuration"]["checks"]["prove_safety_only"] = False
    value["configuration"]["cbmc_args"] = ["--object-bits", "12"]
    hs.update(name=harness, file=str(source.resolve()), line=1, has_loop_contracts=False,
              outcome={"kind": "COMPLETED", "verdict": "SUCCESS"}, failure_kind="NONE",
              n_properties=0, n_failed=0)
    hs["contract"] = None
    hs["attributes"]["kind"] = "Proof"
    hs["attributes"]["should_panic"] = False
    hs["checks"].update(total=1, success=1)
    hs["n_properties"] = 1
    hs["covers"].update(total=0, satisfied=[])
    value["summary"].update(total=1, successful=1, failed=0, checks_total=1, checks_success=1,
                            covers_total=0, covers_satisfied=0)
    return value


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "fixture.rs"
        self.source.write_text("fn root() {}\n")
        self.row = {"id": "row1", "file": "fixture.rs", "harness": "root", "checks": ["ON"],
                    "expected_by_check": {"ON": "SUCCESS"}, "oracle": "expected success", "required_covers": []}

    def tearDown(self): self.temp.cleanup()

    def parse(self, value, pin="upstream", run=None, source=None, row=None):
        path = self.root / "export.json"
        path.write_text(json.dumps(value))
        return runner.parse_export(path, row or self.row, "ON", pin, source or self.source,
                                   run or {"cwd": str(self.root), "original_exit_code": 0})

    def test_success_synthetic_export(self):
        parsed = self.parse(valid_export("upstream", self.source))
        self.assertEqual(parsed["outcome"], "SUCCESS")
        self.assertEqual(parsed["proof_credit"], "NONE")
        self.assertEqual(parsed["cover_description_binding"], "PENDING_SOURCE_REVIEW")

    def test_off_success_is_observation_without_initialization_credit(self):
        value = valid_export("upstream", self.source, check="OFF")
        parsed = runner.parse_export(self._write(value), self.row | {"expected_by_check": {"OFF": "OBSERVE"}},
                                     "OFF", "upstream", self.source,
                                     {"cwd": str(self.root), "original_exit_code": 0})
        self.assertEqual(parsed["outcome"], "OBSERVE")
        self.assertEqual(parsed["proof_credit"], "NONE")

    def _write(self, value):
        path = self.root / "export.json"
        path.write_text(json.dumps(value)); return path

    def test_missing_null_wrong_type_partial(self):
        base = {"cwd": str(self.root), "original_exit_code": 0}
        p = self.root / "none.json"
        self.assertEqual(runner.parse_export(p, self.row, "ON", "upstream", self.source, base)["state"], "MISSING")
        for raw, expected in (("null", "NULL"), ("[]", "WRONG_TOP_LEVEL_TYPE"), ("{", "INVALID_OR_PARTIAL")):
            p.write_text(raw)
            self.assertEqual(runner.parse_export(p, self.row, "ON", "upstream", self.source, base)["state"], expected)

    def test_schema_missing_and_wrong_type_stay_unknown(self):
        value = valid_export("upstream", self.source)
        del value["summary"]["total"]
        self.assertEqual(self.parse(value)["outcome"], "UNKNOWN")
        value = valid_export("upstream", self.source)
        value["configuration"]["checks"]["assert_contracts"] = "false"
        self.assertEqual(self.parse(value)["outcome"], "UNKNOWN")

    def test_pin_source_and_stage_mismatch(self):
        value = valid_export("sel1", self.source)
        self.assertEqual(self.parse(value, pin="upstream")["state"], "TOOL_PIN_MISMATCH")
        value = valid_export("upstream", self.source)
        value["harnesses"][0]["file"] = str(self.root / "elsewhere.rs")
        self.assertEqual(self.parse(value)["state"], "SOURCE_FILE_MISMATCH")

    def test_timeout_and_truncation_prevent_export_acceptance(self):
        path = self._write(valid_export("upstream", self.source))
        for run in ({"timed_out": True}, {"output_truncated": True}, {"termination_reason": "rss_cap"}):
            self.assertEqual(runner.parse_export(path, self.row, "ON", "upstream", self.source, run)["state"], "EXECUTION_INCOMPLETE")

    def test_expected_outcome_mismatch_is_not_pass(self):
        row = self.row | {"expected_by_check": {"ON": "ASSERTION_FAILURE"}}
        parsed = self.parse(valid_export("upstream", self.source), row=row)
        self.assertEqual(parsed["outcome"], "UNEXPECTED")

    def test_named_uninit_failure_requires_matching_class_description_file_and_line(self):
        value = valid_export("upstream", self.source)
        harness = value["harnesses"][0]
        harness["outcome"] = {"kind": "COMPLETED", "verdict": "FAILURE"}
        harness["has_loop_contracts"] = False
        harness["failure_kind"] = "OTHER"
        harness["n_properties"] = 1; harness["n_failed"] = 1
        harness["checks"].update(total=1, success=0, failure=["property-1"])
        harness["failed_properties"] = [{"id":"property-1", "class":"safety_check",
            "description":"Undefined Behavior: Reading from an uninitialized pointer of type `u8`",
            "file":str(self.source.resolve()), "line":"1", "trace_available":False, "status":"FAILURE"}]
        value["summary"].update(successful=0, failed=1, checks_total=1, checks_success=0)
        row = self.row | {"expected_by_check":{"ON":"UNINIT_FAILURE"},
            "failure_match":{"class":"safety_check", "description_regex":r"^Undefined Behavior: Reading from an uninitialized pointer of type `(?:u8|\*const u8)`$",
                             "file":str(self.source.resolve()), "line":1}, "oracle":"UNINIT_FAILURE"}
        path = self._write(value)
        run = {"cwd":str(self.root), "original_exit_code":1}
        parsed = runner.parse_export(path, row, "ON", "upstream", self.source, run)
        self.assertEqual(parsed["outcome"], "UNINIT_FAILURE")
        harness["failed_properties"][0]["line"] = "2"
        path.write_text(json.dumps(value))
        self.assertEqual(runner.parse_export(path, row, "ON", "upstream", self.source, run)["outcome"], "UNKNOWN")

    def test_frontend_diagnostic_requires_exact_error_line_and_positive_exit(self):
        row = self.row | {"frontend_diagnostic":"pinned diagnostic"}
        out = self.root/"diag"; out.mkdir()
        (out/"stdout.log").write_text("error: pinned diagnostic\n")
        (out/"stderr.log").write_text("")
        good = {"original_exit_code":1,"signal":None,"cwd":str(self.root)}
        self.assertTrue(runner._diag_matches(row, good, out))
        (out/"stdout.log").write_text("prefix pinned diagnostic suffix\n")
        self.assertFalse(runner._diag_matches(row, good, out))
        self.assertFalse(runner._diag_matches(row, good | {"signal":9}, out))

    def test_synthetic_process_captures_original_exit_and_bounded_logs(self):
        out = self.root / "proc"
        clean = runner.execute([sys.executable, "-c", "import sys; print('ok'); sys.exit(7)"], self.root, self.root/'clean', 20)
        self.assertEqual(clean["original_exit_code"], 7)
        code = "import sys;sys.stdout.write('x'*1200000);sys.stdout.flush();sys.exit(7)"
        run = runner.execute([sys.executable, "-c", code], self.root, out, 20)
        self.assertIsInstance(run["original_exit_code"], int)
        self.assertTrue(run["stdout_truncated"])
        self.assertLessEqual((out/"stdout.log").stat().st_size, runner.LOG_CAP)
        self.assertLessEqual((out/"stdout.tail.log").stat().st_size, runner.LOG_TAIL)
        self.assertGreater(run["output_bytes"], runner.LOG_CAP)
        self.assertLessEqual(run["output_bytes"], 1200000)

    def test_synthetic_timeout_and_partial_export(self):
        out = self.root / "timeout"
        run = runner.execute([sys.executable, "-c", "import time;time.sleep(10)"], self.root, out, 1)
        self.assertTrue(run["timed_out"])
        p = self.root/"partial.json"; p.write_text('{"schema_version":')
        parsed = runner.parse_export(p, self.row, "ON", "upstream", self.source,
                                     {"cwd": str(self.root), "original_exit_code": 0})
        self.assertEqual(parsed["state"], "INVALID_OR_PARTIAL")

    def test_request_pin_mismatch(self):
        old = runner.REQUEST
        try:
            request = {"status":"READY", "attempt":1,"bucket":"E","item":1,
                       "pins":{"upstream":{"sha":"wrong","tree":"wrong","repository":"Tiramisu-Cake/kani"}},
                       "payload_sha256":{},"rows_sha256":"a"*64}
            path = self.root/"request.json"; path.write_text(json.dumps(request)); runner.REQUEST = path
            with self.assertRaises(runner.RunnerError): runner.load_request("upstream")
        finally: runner.REQUEST = old

    def context(self, out):
        request = {"payload_sha256": {"fixture.rs": runner.sha256(self.source)}}
        binding = {"pin":"upstream", **{k:runner.PIN_DATA["upstream"][k] for k in ("sha","tree")}}
        out.mkdir(exist_ok=True)
        (out/'build.json').write_text(json.dumps({"status":"COMPLETE", "pin":"upstream",
            "request_sha256":"request-sha", "tool":binding, "run":{"original_exit_code":0}}))
        stack = ExitStack()
        stack.enter_context(patch.object(runner, 'HERE', self.root))
        stack.enter_context(patch.object(runner, 'load_request', return_value=(request,'request-sha')))
        stack.enter_context(patch.object(runner, 'load_rows', return_value=([self.row],'rows-sha')))
        stack.enter_context(patch.object(runner, 'verify_tool', return_value=binding))
        stack.enter_context(patch.object(runner, '_guard_env', return_value={}))
        return stack

    def fake_execute(self, argv, cwd, out, timeout, env=None, export_path=None):
        export_path.write_text(json.dumps(valid_export('upstream', self.source)))
        return {'cwd':str(cwd), 'original_exit_code':0, 'argv':argv, 'signal':None}

    def test_incremental_receipt_and_parser_exception_preserve_exit_snapshot(self):
        for broken in (False, True):
            out = self.root/('broken' if broken else 'success')
            with self.context(out), patch.object(runner, 'execute', side_effect=self.fake_execute):
                with patch.object(runner, 'parse_export', side_effect=RuntimeError('synthetic parse exception')) if broken else ExitStack():
                    self.assertEqual(runner.run_rows(self.root/'tool', out, 'upstream'), 0)
            record = json.loads((out/'rows/row1/on/receipt.json').read_text())
            self.assertEqual(record['run']['original_exit_code'],0)
            self.assertIn('unstable-options', record['argv'])
            self.assertIn('--harness-timeout', record['argv'])
            self.assertNotIn('verify-std', record['argv'])
            self.assertEqual(record['status'],'ERROR' if broken else 'OBSERVED')
            self.assertEqual(record['export']['outcome'],'UNKNOWN' if broken else 'SUCCESS')
            self.assertTrue((out/'rows/row1/on/export.json').is_file())
            if broken: self.assertIn('synthetic parse exception', record['error'])

    def test_no_envelope_creates_explicit_not_run_without_execution(self):
        out = self.root/'budget'
        with self.context(out), patch.object(runner, 'PHASE_SECONDS',0), patch.object(runner, 'execute') as execute:
            self.assertEqual(runner.run_rows(self.root/'tool',out,'upstream'),0)
            execute.assert_not_called()
        self.assertEqual(json.loads((out/'run.json').read_text())['receipts'][0]['status'],'NOT_RUN')

    def test_wrong_build_binding_never_executes(self):
        for bad in (None, [], {'status':'FAILED'}, {'status':'COMPLETE','pin':'upstream','request_sha256':'other'}):
            out=self.root/'build-mismatch'
            with self.context(out), patch.object(runner,'execute') as execute:
                (out/'build.json').write_text(json.dumps(bad))
                self.assertEqual(runner.run_rows(self.root/'tool',out,'upstream'),1)
                execute.assert_not_called()

    def test_build_identity_exception_preserves_original_exit(self):
        out=self.root/'build-fail'
        with self.context(out), patch.object(runner,'execute',return_value={'original_exit_code':8,'cwd':str(self.root)}), patch.object(runner,'verify_tool',side_effect=[{},runner.RunnerError('synthetic drift')]):
            self.assertEqual(runner.build(self.root/'tool',out,'upstream'),1)
        record=json.loads((out/'build.json').read_text())
        self.assertEqual(record['run']['original_exit_code'],8)
        self.assertIn('synthetic drift',record['error'])

    def test_fallback_preserves_originals_for_missing_null_partial_wrong_type(self):
        for index, raw in enumerate((None, 'null', '[]', '{', '{"receipts":null}', '{"status":"FAILED","receipts":[]}')):
            out=self.root/('fallback'+str(index))
            with self.context(out):
                path=out/'run.json'
                if raw is not None: path.write_text(raw)
                (out/'target').mkdir()
                (out/'target/build.bin').write_bytes(b'not evidence')
                build_before=(out/'build.json').read_bytes()
                self.assertEqual(runner.fallback(out,'upstream'),0)
                self.assertFalse((out/'target').exists())
                self.assertEqual((out/'build.json').read_bytes(),build_before)
                if raw is not None: self.assertEqual(path.read_text(),raw)
                else: self.assertFalse(path.exists())
                missing=json.loads((out/'missing-not-run.json').read_text())['receipts']
                self.assertEqual(missing[0]['status'],'NOT_RUN')

    def test_fallback_keeps_completed_slot_when_aggregate_partial_and_records_cleanup_error(self):
        out=self.root/'slot-fallback'
        with self.context(out):
            (out/'run.json').write_text('{')
            slot=out/'rows/row1/on'; slot.mkdir(parents=True)
            original=json.dumps({'id':'row1','check':'ON','status':'OBSERVED','run':{'original_exit_code':9}})
            (slot/'receipt.json').write_text(original)
            (out/'target').mkdir()
            with patch.object(runner.shutil,'rmtree',side_effect=OSError('synthetic cleanup failure')):
                self.assertEqual(runner.fallback(out,'upstream'),0)
            self.assertEqual((slot/'receipt.json').read_text(),original)
            self.assertEqual(json.loads((out/'missing-not-run.json').read_text())['receipts'],[])
            job=json.loads((out/'job-status.json').read_text())
            self.assertIn('synthetic cleanup failure',job['target_cleanup'][0]['error'])

    def test_missing_binary_exception_preserved(self):
        result=runner.execute([str(self.root/'missing-synthetic-executable')],self.root,self.root/'missing-exec',1)
        self.assertIsNone(result['original_exit_code'])
        self.assertIn('exec failed',result['runner_error'])

    def test_signaled_success_and_disabled_checks_do_not_pass(self):
        value=valid_export('upstream',self.source)
        self.assertEqual(self.parse(value,run={'cwd':str(self.root),'original_exit_code':7})['outcome'],'UNKNOWN')
        self.assertEqual(self.parse(value,run={'cwd':str(self.root),'original_exit_code':-9,'signal':9})['outcome'],'UNKNOWN')
        value['configuration']['checks']['memory_safety']=False
        self.assertEqual(self.parse(value)['outcome'],'UNKNOWN')
        value=valid_export('upstream',self.source)
        value['harnesses'][0]['checks']=None
        self.assertEqual(self.parse(value)['outcome'],'UNKNOWN')


if __name__ == "__main__":
    unittest.main()
