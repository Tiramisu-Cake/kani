"""Synthetic tests for runner validation; none invokes Kani or a verifier."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import threading
import sys
import tempfile
import unittest
from unittest import mock

import runner


def legacy_request():
    """Exercise the unchanged legacy grouped contract separately from r5 service tests."""
    request=runner.load_request()
    request.pop('profile',None);request.pop('r5',None)
    runner.s2_policy.validate_legacy_request(request)
    return request


def row(**updates):
    value = {"id": "synthetic", "selector": "slice::sort::root", "mode": "PFC",
             "variant": "production", "unwind": 4, "expected": "SUCCESS",
             "failure_description": "expected semantic failure", "required_cover_count": 2,
             "timeout_seconds": 600}
    value.update(updates)
    if value["expected"] == "DETECTED":
        value.setdefault("oracle", {"selector": value["selector"], "property_id": "synthetic.assertion.1",
                                      "file": "source.rs", "export_file": "/std/source.rs",
                                      "line": 7, "class": "assertion"})
    return value


def export(*, selector="slice::sort::root", mode="pfc", schema="0.1.0", state="COMPLETE",
           verdict="SUCCESS", failures=None, named=None):
    target = "slice::sort::body"
    wrapper = "_RNvNtCs1kani4sort6modify"
    kind = {"ProofForContract": {"target_fn": target}} if mode == "pfc" else "Proof"
    failures = failures or []
    named = named or []
    return {"schema_version": schema, "run_state": state, "kani_commit": runner.TOOL_SHA,
            "kani_commit_dirty": False, "harness_timeout_s": 600.0,
            "tools": {"kani": "kani synthetic", "rustc": "rustc synthetic", "cbmc": "CBMC synthetic"},
            "configuration": {"checks": {"assert_contracts": False, "memory_safety": True,
                                            "overflow": True, "unwinding": True, "undefined_function": True},
                              "cbmc_args": ["--object-bits", "12"]},
            "enabled_unstable_features": sorted(set(runner.UNSTABLE) | {"export-json"}),
            "harness_selection": {"requested_filters": [selector], "exact": True,
                                  "unmatched_filters": [], "matched_count": 1},
            "harnesses": [{"name": selector, "crate_name": "core", "file": "source.rs", "line": 7,
                           "is_automatically_generated": False, "attributes": {"kind": kind},
                           "contract": {"contracted_function_name": wrapper, "recursion_tracker": None} if mode == "pfc" else None,
                           "resolved_unwind": 4,
                           "outcome": {"kind": "COMPLETED", "verdict": verdict},
                           "n_properties": 6,
                           "n_failed": len(failures), "failed_properties": named,
                           "unsupported_constructs": [],
                           "checks": {"total": 4, "success": 4-len(failures), "failure": failures,
                                      "unreachable": [], "undetermined": [], "error": [], "unknown": [], "other": []},
                           "covers": {"total": 2, "satisfied": ["cover-A", "cover-B"],
                                      "unsatisfiable": [], "unreachable": [], "undetermined": [],
                                      "error": [], "unknown": [], "other": []}}]}


class RequestTests(unittest.TestCase):
    def request(self):
        selected = row()
        return {"status": "READY", "std_sha": runner.STD_SHA, "std_tree": runner.STD_TREE,
                "tool_sha": runner.TOOL_SHA, "tool_tree": runner.TOOL_TREE,
                "rows": [selected], "changed_file_sha256": {}, "variants": {},
                "execution_groups": [{"id": "fixture", "variant": "production", "unwind": 4,
                                      "row_ids": [selected["id"]]}], "replacement_unions": [],
                "budgets": {"phase_seconds": runner.PHASE_SECONDS, "rss_kib": runner.RSS_CAP_KIB,
                            "stdout_bytes": runner.STDOUT_CAP_BYTES, "stderr_bytes": runner.STDERR_CAP_BYTES,
                            "export_bytes": runner.EXPORT_CAP_BYTES, "artifact_bytes": runner.ARTIFACT_CAP_BYTES,
                            "row_seconds": runner.MAX_ROW_SECONDS, "compile_seconds": runner.COMPILE_SECONDS,
                            "group_rss_max_kib": runner.GROUP_RSS_MAX_KIB,
                            "memory_reserve_kib": runner.MEMORY_RESERVE_KIB}}

    def test_request_binding_and_guard(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "CI-REQUEST.json"
            request = self.request(); request["std_sha"] = "wrong"
            path.write_text(json.dumps(request))
            with self.assertRaisesRegex(runner.RunnerError, "std_sha"):
                runner.load_request(path)
            request = self.request(); request["rows"][0]["variant"] = "surprise"
            path.write_text(json.dumps(request))
            with self.assertRaisesRegex(runner.RunnerError, "variant"):
                runner.load_request(path)
        argv = runner.build_argv(Path("/std"), Path("/tool"), ["x::root"], 3, Path("/tmp/e.json"))
        self.assertIn("--no-assert-contracts", argv)
        self.assertLess(argv.index("-Z"), argv.index("--cbmc-args"))
        self.assertEqual(argv[-3:], ["--cbmc-args", "--object-bits", "12"])
        self.assertEqual(argv[argv.index("--export-json") + 1], "/tmp/e.json")
        self.assertEqual(argv[-4], "/std/library")

    def test_source_binding_and_dirty_or_file_drift(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); std = root / "std"; tool = root / "tool"
            std.mkdir(); tool.mkdir(); (std / "src").mkdir()
            source = std / "src/a.rs"; source.write_text("pinned")
            request = self.request(); request["changed_file_sha256"] = {"src/a.rs": runner.sha256(source)}
            expected = {str(std.resolve()): (runner.STD_SHA, runner.STD_TREE),
                        str(tool.resolve()): (runner.TOOL_SHA, runner.TOOL_TREE)}
            def fake_git(repo, *args):
                if args == ("rev-parse", "HEAD"): return expected[str(repo)][0]
                if args == ("rev-parse", "HEAD^{tree}"): return expected[str(repo)][1]
                if args == ("cat-file", "-t", runner.STD_SHA) or args == ("cat-file", "-t", runner.TOOL_SHA): return "commit"
                if args == ("status", "--porcelain=v1"): return ""
                raise AssertionError((repo, args))
            with mock.patch.object(runner, "git", side_effect=fake_git):
                runner.verify_source(std, tool, request)
                source.write_text("drift")
                with self.assertRaisesRegex(runner.RunnerError, "changed-file SHA drift"):
                    runner.verify_source(std, tool, request)

    def test_rejects_unpinned_rustflags(self):
        with mock.patch.dict(os.environ, {"RUSTFLAGS": "-C opt-level=3"}):
            with self.assertRaisesRegex(runner.RunnerError, "inherited RUSTFLAGS"):
                runner.ci_env()


def binding(selected_row=None, target="slice::sort::body"):
    r = selected_row or row()
    return {"selector": r["selector"], "mode": r["mode"], "crate": "core", "file": "source.rs",
            "locations": [{"line": 7, "source": "fn root() {}"}],
            "target": target if r["mode"] == "PFC" else None}


class ExportTests(unittest.TestCase):
    def parse(self, value, selected_row=None, contract_binding=None):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "export.json"
            p.write_text(json.dumps(value))
            r = selected_row or row()
            target = (contract_binding or {}).get(r["selector"], "slice::sort::body")
            return runner.parse_export(p, r, source_binding=binding(r, target), std=Path("/std"))

    def test_success_and_named_negative(self):
        binding = {row()["selector"]: "slice::sort::body"}
        accepted = self.parse(export(), contract_binding=binding)
        self.assertEqual(accepted["outcome"], "RECORDED")
        self.assertEqual(accepted["expected_target_fn"], "slice::sort::body")
        self.assertEqual(accepted["reported_contracted_function_name"], "_RNvNtCs1kani4sort6modify")
        self.assertNotEqual(accepted["reported_contracted_function_name"], accepted["expected_target_fn"])
        negative_row = row(expected="DETECTED", failure_description="S1 semantic check")
        negative = export(verdict="FAILURE", failures=["synthetic.assertion.1"], named=[
            {"id": "synthetic.assertion.1", "description": "S1 semantic check failed",
             "file": "/std/source.rs", "line": "7", "class": "assertion", "status": "FAILURE"}])
        self.assertEqual(self.parse(negative, negative_row,
                                   {negative_row["selector"]: "slice::sort::body"})["outcome"], "RECORDED")
        extra = export(verdict="FAILURE", failures=["synthetic.assertion.1", "other"], named=[
            {"id": "synthetic.assertion.1", "description": "S1 semantic check failed",
             "file": "/std/source.rs", "line": "7", "class": "assertion", "status": "FAILURE"}])
        self.assertEqual(self.parse(extra, negative_row,
                                   {negative_row["selector"]: "slice::sort::body"})["outcome"], "UNKNOWN")

    def test_wrong_root_mode_guard_and_export_drift(self):
        binding = {row()["selector"]: "slice::sort::body"}
        self.assertEqual(self.parse(export(selector="other::root"), contract_binding=binding)["state"], "WRONG_ROOT_OR_SELECTION")
        self.assertEqual(self.parse(export(mode="ordinary"), contract_binding=binding)["state"], "WRONG_MODE")
        self.assertEqual(self.parse(export(schema="0.2.0"), contract_binding=binding)["state"], "INCOMPLETE_OR_SCHEMA_DRIFT")
        self.assertEqual(self.parse(export(state="PARTIAL"), contract_binding=binding)["state"], "INCOMPLETE_OR_SCHEMA_DRIFT")
        bad = export(); bad["harnesses"][0]["checks"]["unreachable"] = ["x"]
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "INCONSISTENT_PROPERTY_COUNTS")
        bad = export(); bad["harnesses"][0]["resolved_unwind"] = 99
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "WRONG_UNWIND")
        bad = export(); bad["harnesses"][0]["attributes"]["kind"]["ProofForContract"]["target_fn"] = "other"
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "CONTRACT_TARGET_BINDING_MISMATCH")
        bad = export(); bad["harnesses"][0]["contract"]["contracted_function_name"] = ""
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "CONTRACT_TARGET_BINDING_MISMATCH")
        bad = export(); del bad["harnesses"][0]["contract"]["contracted_function_name"]
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "CONTRACT_TARGET_BINDING_MISMATCH")
        bad = export(); bad["configuration"]["checks"]["assert_contracts"] = True
        self.assertEqual(self.parse(bad, contract_binding=binding)["state"], "WRONG_CONFIGURATION")

    def test_invalid_export_shapes_and_size(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "e.json"
            self.assertEqual(runner.parse_export(p, row())["state"], "MISSING")
            p.write_bytes(b"")
            self.assertEqual(runner.parse_export(p, row())["state"], "EMPTY")
            p.write_bytes(b"{")
            self.assertEqual(runner.parse_export(p, row())["state"], "INVALID_OR_PARTIAL")
            p.write_text("null")
            self.assertEqual(runner.parse_export(p, row())["state"], "NULL")
            p.write_text("[]")
            self.assertEqual(runner.parse_export(p, row())["state"], "WRONG_TOP_LEVEL_TYPE")
            p.write_bytes(b" " * 100)
            self.assertEqual(runner.parse_export(p, row(), max_bytes=50)["state"], "OVERSIZE")


class ExecutionTests(unittest.TestCase):
    def test_synthetic_subprocess_success_and_signal(self):
        with tempfile.TemporaryDirectory() as d:
            ok = runner.execute([sys.executable, "-c", "print('synthetic ok')"], Path(d),
                                Path(d) / "ok", timeout=5)
            self.assertEqual(ok["original_exit_code"], 0)
            self.assertIn("synthetic ok", (Path(d) / "ok/stdout.log").read_text())
            killed = runner.execute([sys.executable, "-c", "import os,signal; os.kill(os.getpid(), signal.SIGTERM)"],
                                    Path(d), Path(d) / "signal", timeout=5)
            self.assertEqual(killed["signal"], 15)

    def test_synthetic_subprocess_timeout(self):
        with tempfile.TemporaryDirectory() as d:
            timed = runner.execute([sys.executable, "-c", "import time; time.sleep(5)"],
                                   Path(d), Path(d) / "timeout", timeout=1)
            self.assertTrue(timed["timed_out"])
            self.assertEqual(timed["termination_reason"], "timeout")

    def test_output_and_export_caps_kill_child(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "stdout"
            capped = runner.execute([sys.executable, "-c", "import sys; sys.stdout.write('x'*1000000); sys.stdout.flush(); import time; time.sleep(2)"],
                                    Path(d), out, timeout=5, stdout_cap=1024)
            self.assertEqual(capped["termination_reason"], "stdout_cap")
            self.assertLessEqual((out / "stdout.log").stat().st_size, 1024)
            export_path = Path(d) / "oversize-export.json"
            export_run = runner.execute([sys.executable, "-c",
                f"from pathlib import Path; import time; Path({str(export_path)!r}).write_bytes(b'x'*5000); time.sleep(2)"],
                Path(d), Path(d) / "export-cap", timeout=5, export_path=export_path, export_cap=1024)
            self.assertEqual(export_run["termination_reason"], "export_cap")

    def test_external_signal_kills_child_and_returns_receipt(self):
        with tempfile.TemporaryDirectory() as d:
            timer = threading.Timer(0.25, lambda: os.kill(os.getpid(), runner.signal.SIGTERM))
            timer.start()
            try:
                result = runner.execute([sys.executable, "-c", "import time; time.sleep(4)"],
                                        Path(d), Path(d) / "external", timeout=8)
            finally:
                timer.cancel()
            self.assertEqual(result["interrupted_by_signal"], runner.signal.SIGTERM)
            self.assertEqual(result["termination_reason"], "external_signal")


class NoListBindingTests(unittest.TestCase):
    def parse(self, value, r=None, b=None):
        r=r or row()
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'export.json';path.write_text(json.dumps(value))
            return runner.parse_export(path,r,source_binding=b or binding(r),std=Path('/std'))

    def test_selection_mode_source_and_manual_harness_fail_closed(self):
        import copy
        mutations=[
            lambda v:v['harness_selection'].update(exact=False),
            lambda v:v['harness_selection'].update(matched_count=0),
            lambda v:v['harness_selection'].update(matched_count=2),
            lambda v:v['harness_selection'].update(matched_count=True),
            lambda v:v['harness_selection'].update(unmatched_filters=['other']),
            lambda v:v['harness_selection'].update(requested_filters=['other']),
            lambda v:v.update(harnesses=[]),
            lambda v:v['harnesses'].append(copy.deepcopy(v['harnesses'][0])),
            lambda v:v['harnesses'][0].update(name='other::root'),
            lambda v:v['harnesses'][0].update(is_automatically_generated=True),
            lambda v:v['harnesses'][0].pop('is_automatically_generated'),
            lambda v:v['harnesses'][0].update(crate_name='std'),
            lambda v:v['harnesses'][0].update(file='../other/source.rs'),
            lambda v:v['harnesses'][0].update(line=8),
            lambda v:v['harnesses'][0].update(line=True),
            lambda v:v['harnesses'][0].pop('contract'),
            lambda v:v['harnesses'][0].update(contract=None),
            lambda v:v['harnesses'][0]['attributes']['kind']['ProofForContract'].update(target_fn='wrong'),
        ]
        for i,mutate in enumerate(mutations):
            value=export();mutate(value)
            with self.subTest(case=i):self.assertEqual(self.parse(value)['outcome'],'UNKNOWN')
        for missing in ('schema_version','run_state','kani_commit','harness_selection','harnesses'):
            value=export();value.pop(missing)
            self.assertEqual(self.parse(value)['outcome'],'UNKNOWN')
        value=export();value['harnesses'][0]['attributes']['kind']['ProofForContract']['target_fn']='slice :: sort :: body'
        self.assertEqual(self.parse(value)['outcome'],'RECORDED')
        ordinary=row(mode='Original');value=export(mode='ordinary')
        self.assertEqual(self.parse(value,ordinary)['outcome'],'RECORDED')
        value['harnesses'][0]['contract']={}
        self.assertEqual(self.parse(value,ordinary)['outcome'],'UNKNOWN')
        value['harnesses'][0].pop('contract')
        self.assertEqual(self.parse(value,ordinary)['outcome'],'UNKNOWN')
        value=export();value['harnesses'][0]['outcome']={'kind':'NOT_RUN'}
        self.assertEqual(self.parse(value)['outcome'],'UNKNOWN')
        self.assertNotEqual(self.parse(value)['outcome'],'RECORDED')

    def test_target_tokens_preserve_identifier_boundaries(self):
        r=row(); b=binding(r,"<u8 as Trait>::small_sort")
        v=export(); kind=v['harnesses'][0]['attributes']['kind']['ProofForContract']
        for target in ('< u8 as Trait > :: small_sort','<u8 as Trait>::small_sort'):
            kind['target_fn']=target
            self.assertEqual(self.parse(v,r,b)['outcome'],'RECORDED')
        for target in ('<u8asTrait>::small_sort','<u8 asTrait>::small_sort',
                       '<u8 as Trait>::other','<u8 as Trait>::small_sort()',
                       '<u8 as Trait>::small_sort/*comment*/','',None):
            kind['target_fn']=target
            self.assertEqual(self.parse(v,r,b)['outcome'],'UNKNOWN')

    def test_source_anchor_and_request_binding_mutations(self):
        import copy
        original=legacy_request()
        mutations=[
            lambda r:r['source_bindings'].pop(r['rows'][0]['id']),
            lambda r:r['source_bindings'][r['rows'][0]['id']].update(selector='other'),
            lambda r:r['source_bindings'][r['rows'][0]['id']].update(mode='Original'),
            lambda r:r['source_bindings'][r['rows'][0]['id']].update(locations=[]),
            lambda r:r['source_bindings']['swap_pfc'].update(target='other_target'),
            lambda r:r['source_bindings']['merge32_real'].update(target='spurious_target'),
            lambda r:r['budgets'].update(compile_seconds=1500),
        ]
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'request.json'
            for mutate in mutations:
                request=copy.deepcopy(original);mutate(request);p.write_text(json.dumps(request))
                with self.assertRaises(runner.RunnerError):runner.load_request(p)

def batch_export(rows, bindings=None):
    value=export()
    value['harness_selection'].update(requested_filters=[r['selector'] for r in rows],matched_count=len(rows))
    value['harnesses']=[]
    for r in rows:
        neg=r['expected']=='DETECTED'
        oracle=r.get('oracle') or {'property_id':'synthetic-unbound-property','export_file':'/synthetic/unbound.rs','line':1}
        h=export(selector=r['selector'],mode='pfc' if r['mode']=='PFC' else 'ordinary',
                 verdict='FAILURE' if neg else 'SUCCESS',failures=[oracle['property_id']] if neg else [],
                 named=[{'id':oracle['property_id'],'description':r['failure_description'],
                         'file':oracle['export_file'],'line':str(oracle['line']),
                         'class':'assertion','status':'FAILURE'}] if neg else [])['harnesses'][0]
        if neg:
            h['checks']['failure'] = [oracle['property_id']]
        b=(bindings or {}).get(r['id'],binding(r))
        h.update(file=b['file'],line=b['locations'][0]['line'],resolved_unwind=r['unwind'])
        if r['mode']=='PFC':h['attributes']['kind']['ProofForContract']['target_fn']=b['target']
        covers=[r['selector']+'.cover.'+str(i+1) for i in range(r['required_cover_count'])]
        while len(covers)<r['required_cover_count']:covers.append('cover-'+str(len(covers)))
        h['covers'].update(total=len(covers),satisfied=covers)
        h['n_properties']=h['checks']['total']+len(covers)
        value['harnesses'].append(h)
    value['harnesses'].reverse()  # Mapping must never depend on export order.
    return value


def render_regular(harnesses):
    output=[]
    for name, props in harnesses:
        output += ['Checking harness '+name+'...', '', 'RESULTS:']
        for i,p in enumerate(props, 1):
            output += [f"Check {i}: {p['id']}", '\t - Status: '+p['status'],
                       '\t - Description: "'+p['description']+'"',
                       '\t - Location: '+p['file']+':'+str(p['line']), '']
        output += ['', 'SUMMARY:', 'VERIFICATION:- SUCCESS']
    return ('\n'.join(output)+'\n').encode()


def feed_regular(parser, stock):
    entries=[]
    for h in stock['harnesses']:
        props=list(h['failed_properties'])
        for i in range(h['checks']['success']):
            props.append({'id':h['name']+'.assertion.'+str(100+i),'class':'assertion',
                          'description':'synthetic check', 'file':'/std/source.rs','line':'7','status':'SUCCESS'})
        for i, pid in enumerate(h['covers']['satisfied']):
            props.append({'id':pid,'class':'cover','description':'synthetic cover',
                          'file':'/std/source.rs','line':'7','status':'SATISFIED'})
        entries.append((h['name'],props))
    parser.feed(render_regular(entries)); parser.finish()


class GroupTests(unittest.TestCase):
    def test_groups_keep_rows_flags_variants_and_every_selector(self):
        request=legacy_request();groups=runner.group_rows(request['rows'],request['execution_groups'])
        self.assertEqual(len(groups),1)
        self.assertEqual([g['id'] for g in groups],[g['id'] for g in request['execution_groups']])
        self.assertEqual(sorted(r['id'] for g in groups for r in g['rows']),sorted(r['id'] for r in request['rows']))
        for g in groups:
            selectors=[r['selector'] for r in g['rows']]
            argv=runner.build_argv(Path('/std'),Path('/tool'),selectors,g['unwind'],Path('/tmp/export.json'))
            self.assertEqual(argv.count('verify-std'),1)
            self.assertEqual(argv.count('--harness'),len(selectors))
            self.assertEqual([argv[i+1] for i,a in enumerate(argv) if a=='--harness'],selectors)
            self.assertEqual(argv[argv.index('--harness-timeout')+1],'600s')
            self.assertIn('--jobs=1',argv);self.assertNotIn('--fail-fast',argv)
            self.assertNotIn('--only-codegen',argv);self.assertNotIn('list',argv)
            self.assertEqual(argv[argv.index('--default-unwind')+1],str(g['unwind']))
        duplicate=[row(id='a'),row(id='b')]
        with self.assertRaises(runner.RunnerError):runner.group_rows(duplicate)

    def test_execution_groups_are_exact_ordered_partition_and_subset_selection(self):
        rows=[row(id='one',selector='one'),row(id='two',selector='two')]
        request={'rows':rows,'execution_groups':[
            {'id':'first','variant':'production','unwind':4,'row_ids':['one']},
            {'id':'last','variant':'production','unwind':4,'row_ids':['two']}]}
        all_groups=runner.select_groups(request)
        ids=[all_groups[-1]['id'],all_groups[0]['id']]
        selected=runner.select_groups(request,ids)
        self.assertEqual([g['id'] for g in selected],[all_groups[0]['id'],all_groups[-1]['id']])
        bad=dict(request);bad['execution_groups']=[dict(x) for x in request['execution_groups']]
        bad['execution_groups'][0]['row_ids']=bad['execution_groups'][1]['row_ids']
        with self.assertRaises(runner.RunnerError):runner.group_rows(request['rows'],bad['execution_groups'])

    def test_batch_mapping_mixed_positive_negative_and_bad_inventory(self):
        rows=[row(id='ok'),row(id='bad',selector='slice::sort::bad',expected='DETECTED')]
        value=batch_export(rows);selectors=[r['selector'] for r in rows]
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'export.json'
            def parse(v,r):
                path.write_text(json.dumps(v))
                return runner.parse_export(path,r,source_binding=binding(r),std=Path('/std'),group_selectors=selectors)
            for r in rows:self.assertEqual(parse(value,r)['outcome'],'RECORDED')
            import copy
            mutations=[lambda v:v['harnesses'].append(v['harnesses'][0]),
                       lambda v:v['harnesses'].pop(),
                       lambda v:v['harnesses'][0].update(name=v['harnesses'][1]['name']),
                       lambda v:v['harness_selection'].update(matched_count=1),
                       lambda v:v['harness_selection'].update(unmatched_filters=['unknown']),
                       lambda v:v['harness_selection'].update(requested_filters=selectors[::-1]),
                       lambda v:v.update(harness_timeout_s=None),
                       lambda v:v.update(harness_timeout_s=300),
                       lambda v:v.update(run_state='PARTIAL')]
            for mutate in mutations:
                v=copy.deepcopy(value);mutate(v)
                for r in rows:self.assertEqual(parse(v,r)['outcome'],'UNKNOWN')
            v=copy.deepcopy(value);v['harnesses'][0]['attributes']['kind']['ProofForContract']['target_fn']='wrong'
            self.assertEqual(parse(v,rows[0])['outcome'],'RECORDED')
            self.assertEqual(parse(v,rows[1])['outcome'],'UNKNOWN')
            for kind in ('TIMEOUT','OUT_OF_MEMORY','CRASHED','NOT_RUN'):
                v=copy.deepcopy(value);v['harnesses'][0]['outcome']={'kind':kind}
                self.assertEqual(parse(v,rows[1])['outcome'],'UNKNOWN')

    def run_mock_batch(self, root, request, *, case='success'):
        import copy
        std=root/'std';std.mkdir();tool=root/'tool';out=root/'out'
        fp={'required_hashes_present':True,'binaries':{name:{'path':name,'sha256':'a'*64}
            for name in ('kani_driver','kani_compiler','cbmc')},'reported_versions':None}
        calls=[]
        def execute(argv,cwd,dest,timeout,**kw):
            selectors=[argv[i+1] for i,a in enumerate(argv) if a=='--harness']
            rows=[r for r in request['rows'] if r['selector'] in selectors and r['variant'] in dest.name]
            # Exact request group order is authoritative, variants may share selectors.
            g=next(g for g in runner.group_rows(request['rows'],request.get('execution_groups')) if g['id']==dest.name)
            rows=g['rows'];calls.append((argv,timeout,kw))
            self.assertTrue(kw['capture_tail']);self.assertNotIn('--only-codegen',argv)
            self.assertEqual(cwd,std.resolve());self.assertFalse(kw['export_path'].exists())
            (dest/'stdout.log').write_text('HEAD-COMPILE-TAIL');(dest/'stderr.log').write_text('HEAD-STDERR-TAIL')
            initial=batch_export(rows,request['source_bindings']);initial['run_state']='INCOMPLETE';initial.pop('harnesses')
            kw['export_path'].write_text(json.dumps(initial))
            kw['compile_monitor'].poll(0.01,{})
            final=batch_export(rows,request['source_bindings'])
            feed_regular(kw['rich_parser'], final)
            native=Path(kw['env']['CARGO_TARGET_DIR'])/'debug/deps/core.kani-metadata.json'
            native.parent.mkdir(parents=True,exist_ok=True)
            native.write_text(json.dumps({'crate_name':'core','proof_harnesses':[
                {'pretty_name':h['name'],'crate_name':h['crate_name'],
                 'attributes':h['attributes'],'contract':h['contract']}
                for h in final['harnesses']]}))
            if case=='exception':raise OSError('synthetic execution exception')
            if case=='partial':final={'run_state':'PARTIAL'}
            if case=='null':final=None
            if case=='wrong_type':final=[]
            if case=='timeout_row':final['harnesses'][0]['outcome']={'kind':'TIMEOUT'}
            if case=='wrong_target':final['harnesses'][0]['attributes']['kind']['ProofForContract']['target_fn']='other'
            if case=='not_run':final['harnesses'][0]['outcome']={'kind':'NOT_RUN'}
            if case=='duplicate':final['harnesses'][0]['name']=final['harnesses'][1]['name']
            if case=='missing':kw['export_path'].unlink()
            else:kw['export_path'].write_text('{' if case=='invalid_json' else json.dumps(final))
            code=1 if any(r['expected']=='DETECTED' for r in rows) or case in ('timeout_row','not_run') else 0
            result={'original_exit_code':code,'signal':None,'timed_out':False,'rss_peak_kib':100,
                    'elapsed_seconds':0.02,'stdout_bytes':17,'stderr_bytes':16}
            if case=='exit':result['original_exit_code']=42
            if case=='signal':result.update(original_exit_code=-15,signal=15)
            if case in ('timeout','rss_cap','external_signal','stdout_cap','export_cap'):
                result.update(original_exit_code=-15,termination_reason=case,timed_out=case=='timeout')
            return result
        fingerprints=[fp,fp]
        if case=='fingerprint':fingerprints=[fp,{**fp,'binaries':{'driver':{'sha256':'drift'}}}]
        with mock.patch.object(runner,'verify_source',side_effect=runner.RunnerError('source drift') if case=='source' else [{},runner.RunnerError('post source drift')] if case=='post_source' else None,return_value={}), \
             mock.patch.object(runner,'binary_fingerprints',side_effect=(fingerprints if case=='fingerprint' else None),return_value=fp), \
             mock.patch.object(runner,'group_memory_budget',return_value={'group_cap_kib':runner.GROUP_RSS_MAX_KIB}), \
             mock.patch.object(runner,'_run_variant',side_effect=lambda std,name,req:(None,{})), \
             mock.patch.object(runner,'execute',side_effect=execute):
            code=runner.run_rows(std,tool,out,request)
        return code,json.loads((out/'receipt.json').read_text()),calls,out

    def test_all_s2_rows_one_invocation_record_only(self):
        request=legacy_request()
        with tempfile.TemporaryDirectory() as d:
            code,summary,calls,out=self.run_mock_batch(Path(d),request)
            self.assertEqual(code,0,json.dumps(summary))
            self.assertEqual(len(calls),1)
            self.assertEqual([r['id'] for r in summary['rows']],[r['id'] for r in request['rows']])
            for r in summary['rows']:
                self.assertEqual(r['outcome'],'RECORDED')
                self.assertIsNone(r['original_exit']); self.assertIsNone(r['per_root_rss_kib'])
                self.assertEqual(r['proof_credit'],'NONE')
                self.assertEqual(r['group_original_exit'],1)
                self.assertEqual(r['cost_phases']['aggregate_root_rss_kib'],'UNKNOWN_NOT_EXPORTED_BY_STOCK')
            receipt=json.loads((out/'groups/s2-batch3probes-u34/receipt.json').read_text())
            self.assertEqual(receipt['group_budget_seconds'],7500)

    def test_group_and_row_errors_keep_original_group_exit_and_unknown(self):
        rows=[row(id='positive'),row(id='negative',selector='slice::sort::negative',expected='DETECTED')]
        request={'rows':rows,'source_bindings':{r['id']:binding(r) for r in rows},'changed_file_sha256':{},'variants':{}}
        for case in ('exit','signal','timeout','rss_cap','external_signal','stdout_cap','export_cap','missing',
                     'invalid_json','partial','null','wrong_type','duplicate','timeout_row','wrong_target',
                     'not_run','exception','fingerprint','source','post_source'):
            with self.subTest(case=case),tempfile.TemporaryDirectory() as d:
                code,summary,calls,out=self.run_mock_batch(Path(d),request,case=case)
                self.assertEqual(code,1)
                if case in ('timeout_row','wrong_target','not_run'):
                    self.assertEqual(summary['rows'][0]['outcome'],'RECORDED')
                    self.assertEqual(summary['rows'][1]['outcome'],'UNKNOWN')
                else:
                    self.assertTrue(all(r['outcome']=='UNKNOWN' for r in summary['rows']))
                if case=='exit':self.assertEqual(summary['rows'][0]['group_original_exit'],42)
                if case=='signal':self.assertEqual(summary['rows'][0]['signal'],15)
                if case=='exception':self.assertIn('synthetic execution exception',summary['stop_reason'])
                if case=='source':self.assertFalse(calls)

    def test_phase_reserve_does_not_launch_group(self):
        rows=[row(id='a')]
        with tempfile.TemporaryDirectory() as d, mock.patch.object(runner,'PHASE_SECONDS',0),mock.patch.object(runner,'execute') as execute:
            out=Path(d)/'out'
            self.assertEqual(runner.run_rows(Path('/std'),Path('/tool'),out,{'rows':rows}),1)
            execute.assert_not_called()
            self.assertEqual(json.loads((out/'a/receipt.json').read_text())['status'],'NOT_RUN')

    def test_phase_limit_is_separate_from_kani_harness_limit(self):
        request=legacy_request()
        with tempfile.TemporaryDirectory() as d,mock.patch.object(runner,'PHASE_SECONDS',50):
            code,summary,calls,out=self.run_mock_batch(Path(d),request)
            self.assertEqual(code,0)  # Complete evidence is independent of offline oracles
            for argv,timeout,kw in calls:
                self.assertLess(timeout,50)
                self.assertEqual(argv[argv.index('--harness-timeout')+1],'600s')

    def test_overlay_cleanup_failure_invalidates_entire_group(self):
        r=row(variant='activation-default')
        request={'rows':[r],'source_bindings':{r['id']:binding(r)},'changed_file_sha256':{},'variants':{}}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);std=root/'std';std.mkdir();out=root/'out';patchfile=root/'overlay.patch';patchfile.write_text('synthetic overlay')
            fp={'required_hashes_present':True,'binaries':{name:{'path':name,'sha256':'a'*64}
                for name in ('kani_driver','kani_compiler','cbmc')}}
            def execute(argv,cwd,dest,timeout,**kw):
                value=batch_export([r]);kw['export_path'].write_text(json.dumps(value));kw['compile_monitor'].poll(0.01,{})
                return {'original_exit_code':0,'signal':None,'rss_peak_kib':1,'elapsed_seconds':0.02}
            with mock.patch.object(runner,'verify_source',return_value={}), \
                 mock.patch.object(runner,'binary_fingerprints',return_value=fp), \
                 mock.patch.object(runner,'group_memory_budget',return_value={'group_cap_kib':runner.RSS_CAP_KIB}), \
                 mock.patch.object(runner,'_run_variant',return_value=(patchfile,{})), \
                 mock.patch.object(runner,'execute',side_effect=execute), \
                 mock.patch.object(runner.subprocess,'run',side_effect=RuntimeError('cleanup broken')) as cleanup:
                code=runner.run_rows(std,root/'tool',out,request)
            self.assertEqual(code,1);self.assertIn('--reverse',cleanup.call_args.args[0])
            result=json.loads((out/'synthetic/receipt.json').read_text())
            self.assertEqual(result['outcome'],'UNKNOWN');self.assertEqual(result['group_original_exit'],0)
            self.assertIn('variant_cleanup_failed',result['reason'])

    def test_group_memory_budget_host_and_cgroup(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);mem=root/'meminfo';cg=root/'cgroup';cg.mkdir()
            mem.write_text('MemAvailable: 20971520 kB\n')
            self.assertEqual(runner.group_memory_budget(mem,cg)['group_cap_kib'],12*1024*1024)
            (cg/'memory.max').write_text(str(8*1024**3));(cg/'memory.current').write_text(str(1024**3))
            value=runner.group_memory_budget(mem,cg)
            self.assertEqual(value['group_cap_kib'],5*1024*1024)
            self.assertIn('UNKNOWN',value['per_root_rss_status'])
            mem.write_text('MemAvailable: 1048576 kB\n')
            with self.assertRaises(runner.RunnerError):runner.group_memory_budget(mem,cg)
            mem.write_text('No available field\n')
            with self.assertRaises(runner.RunnerError):runner.group_memory_budget(mem,cg)


class CompileTests(unittest.TestCase):
    def test_single_process_compile_then_two_harnesses_and_bounded_previews(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);path=root/'export.json';rows=[row(),row(id='b',selector='slice::sort::b')]
            marker=batch_export(rows);marker.update(run_state='INCOMPLETE');marker.pop('harnesses')
            final=batch_export(rows);selectors=[r['selector'] for r in rows]
            monitor=runner.CompileMonitor(root/'compile/receipt.json',path,selectors,seconds=1)
            code="from pathlib import Path; import time,sys; p=Path("+repr(str(path))+"); "
            code+="sys.stderr.write('COMPILE-HEAD'+'x'*5000+'COMPILE-TAIL');sys.stderr.flush(); "
            code+='p.write_text('+repr(json.dumps(marker))+'); time.sleep(0.15); '
            code+='p.write_text('+repr(json.dumps(final))+'); print("proof finished")'
            result=runner.execute([sys.executable,'-c',code],root,root,timeout=2,compile_monitor=monitor,export_path=path,capture_tail=True)
            self.assertEqual(result['original_exit_code'],0)
            value=json.loads((root/'compile/receipt.json').read_text())
            self.assertEqual(value['state'],'COMPLETE');self.assertLess(value['elapsed_upper_bound_seconds'],1)
            self.assertTrue(value['stderr']['head'].startswith('COMPILE-HEAD'))
            self.assertTrue(value['stderr']['tail'].endswith('COMPILE-TAIL'))
            self.assertLessEqual(len(value['stderr']['head']),2048);self.assertLessEqual(len(value['stderr']['tail']),2048)
            self.assertEqual(value['proof_credit'],'NONE')

    def test_live_head_tail_capture_survives_missing_finalization(self):
        ready=threading.Event();release=threading.Event()
        class Pipe:
            calls=0
            def read(self,n):
                self.calls+=1
                if self.calls==1:return b'HEAD'+b'x'*6000+b'TAIL'
                ready.set();release.wait(2);return b''
            def close(self):pass
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'live.log';state={'stdout_kept':0,'stdout_bytes':0,'stdout_cap':False}
            thread=threading.Thread(target=runner._read_pipe,args=(Pipe(),path,4096,state,threading.Lock(),'stdout',True))
            thread.start()
            try:
                self.assertTrue(ready.wait(2))
                data=path.read_bytes()
                self.assertLessEqual(len(data),4096);self.assertTrue(data.startswith(b'HEAD'));self.assertTrue(data.endswith(b'TAIL'))
            finally:release.set();thread.join()

    def test_compile_timeout_missing_wrong_marker_and_process_failures(self):
        selectors=[row()['selector']]
        for name in ('missing','wrong_selection','wrong_tool','wrong_timeout','exit','signal','launch','rss'):
            with self.subTest(case=name),tempfile.TemporaryDirectory() as d:
                root=Path(d);path=root/'export.json';monitor=runner.CompileMonitor(root/'compile/receipt.json',path,selectors,seconds=0.2)
                marker=export(state='INCOMPLETE');marker.pop('harnesses')
                if name=='wrong_selection':marker['harness_selection']['matched_count']=2
                if name=='wrong_tool':marker['kani_commit']='other'
                if name=='wrong_timeout':marker['harness_timeout_s']=300
                code='import time; time.sleep(2)'
                if name.startswith('wrong_'):code='from pathlib import Path; Path('+repr(str(path))+').write_text('+repr(json.dumps(marker))+'); '+code
                if name=='exit':code='raise SystemExit(42)'
                if name=='signal':code='import os,signal; os.kill(os.getpid(),signal.SIGTERM)'
                argv=[str(root/'absent')] if name=='launch' else [sys.executable,'-c',code]
                with mock.patch.object(runner,'_group_rss_kib',return_value=runner.RSS_CAP_KIB+1 if name=='rss' else 1):
                    result=runner.execute(argv,root,root,timeout=2,compile_monitor=monitor,export_path=path)
                value=json.loads((root/'compile/receipt.json').read_text())
                self.assertEqual(value['state'],'FAILED')
                if name in ('missing','wrong_selection','wrong_tool','wrong_timeout'):
                    self.assertEqual(result['termination_reason'],'compile_timeout')
                if name=='exit':self.assertEqual(value['group_execution']['original_exit_code'],42)
                if name=='signal':self.assertEqual(value['group_execution']['signal'],15)
                if name=='launch':self.assertIn('exec failed',value['group_execution']['runner_error'])
                if name=='rss':self.assertEqual(value['group_execution']['termination_reason'],'rss_cap')


if __name__ == "__main__":
    unittest.main()
