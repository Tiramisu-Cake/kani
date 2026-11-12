#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""All subprocesses here are Python fake children; no compiler or verifier."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from capture import Milestones, digest, exit_code, run, save, snapshot
from analyze import failures, program, projection
import runner

HERE=Path(__file__).resolve().parent


class Synthetic(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name)
    def tearDown(self):
        self.tmp.cleanup()
    def fake(self, code, **kwargs):
        return run([sys.executable,'-c',code],self.root/'run',**kwargs)
    def test_exit_and_units(self):
        r=self.fake('print("ok"); raise SystemExit(7)')
        self.assertEqual(r['original_rc'],7)
        self.assertEqual(exit_code(r),7)
        self.assertEqual(r['streams']['stdout']['total_bytes'],3)
        self.assertIsInstance(r['sampled_max_rss_kib'],int)
        self.assertIsInstance(r['wait4_maxrss_kib'],int)
        self.assertIsNone(r['time_v_maxrss_kib'])
    def test_signal(self):
        r=self.fake('import os,signal; os.kill(os.getpid(),signal.SIGTERM)')
        self.assertEqual(r['original_signal'],15)
        self.assertEqual(exit_code(r),143)
    def test_timeout_and_descendant_cleanup(self):
        pidfile=self.root/'pid'
        code='import subprocess,sys,time; from pathlib import Path; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(20)"]); Path(sys.argv[1]).write_text(str(p.pid)); time.sleep(20)'
        r=run([sys.executable,'-c',code,str(pidfile)],self.root/'run',seconds=.3)
        self.assertEqual(r['limiter_reason'],'wall_timeout')
        self.assertEqual(r['original_signal'],9)
        pid=int(pidfile.read_text())
        stat=Path(f'/proc/{pid}/stat')
        self.assertTrue(not stat.exists() or stat.read_text().rsplit(')',1)[1].split()[0]=='Z')
    def test_orphan_setsid_cleanup(self):
        pidfile=self.root/'pid'
        code='import subprocess,sys; from pathlib import Path; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(20)"],start_new_session=True); Path(sys.argv[1]).write_text(str(p.pid))'
        began=time.monotonic()
        r=run([sys.executable,'-c',code,str(pidfile)],self.root/'run',seconds=.3)
        self.assertLess(time.monotonic()-began,2)
        self.assertEqual(r['limiter_reason'],'wall_timeout')
        self.assertEqual(r['original_rc'],0)
        pid=int(pidfile.read_text())
        stat=Path(f'/proc/{pid}/stat')
        self.assertTrue(not stat.exists() or stat.read_text().rsplit(')',1)[1].split()[0]=='Z')
    def test_unknown_program_line_incomplete(self):
        f=self.root/'unknown'
        f.write_text('Program constraints:\n// 1 f.rs line 1 function f\n(1) x = 1\n(weird) y = 2\n')
        r=program(f,'0'*64,True)
        self.assertFalse(r['parser_complete'])
        self.assertFalse(r['complete'])
    def test_cap_continues_drain(self):
        r=self.fake('import os; os.write(1,b"a"*200000); os.write(2,b"b"*100000)',cap=20)
        self.assertEqual(r['original_rc'],0)
        self.assertEqual(r['streams']['stdout']['total_bytes'],200000)
        self.assertEqual(r['streams']['stderr']['dropped_bytes'],99980)
        self.assertFalse(r['stream_complete'])
    def test_missing_binary(self):
        r=run(['/absent/d1p-tool'],self.root/'run')
        self.assertEqual(r['collector_status'],'ERROR')
        self.assertEqual(exit_code(r),125)
    def test_snapshot_identity_duplicate_cap(self):
        src=self.root/'source'; src.write_bytes(b'abc')
        dst=self.root/'snapshot'
        self.assertEqual(snapshot(src,dst)['sha256'],digest(src))
        with self.assertRaises(FileExistsError): snapshot(src,dst)
        with self.assertRaises(RuntimeError): snapshot(src,self.root/'capped',limit=2)
        self.assertFalse((self.root/'capped').exists())
    def test_program_unknown_widths_and_ignored(self):
        f=self.root/'text'
        f.write_text('Program constraints:\n// 17 file x.rs line 8 function f\n(1) x!0 = byte_extract_little_endian(a, off)\n(sliced) ASSERT(x!0[2])\n     guard: g\n')
        r=program(f,'a'*64,True)
        self.assertEqual(r['counts']['visible_all'],2)
        self.assertEqual(r['counts']['visible_ignored'],1)
        self.assertEqual(r['top30_roots_by_exact_width'],'UNKNOWN')
        self.assertEqual(r['excerpts'][0]['pc'],17)
        self.assertFalse(r['semantic_verdict_complete'])
    def test_vcc_repeated_prefix_is_not_ssa(self):
        f=self.root/'vcc'; f.write_text('VCC 1\nx = a\nVCC 2\nx = a\n')
        r=program(f,'0'*64,True)
        self.assertEqual(r['counts'].get('visible_all',0),0)
        self.assertFalse(r['complete'])
    def test_partial_empty_malformed(self):
        for i,value in enumerate(['','[','{"garbage":','Program constraints:\n(1) abc']):
            f=self.root/str(i);f.write_text(value)
            self.assertFalse(program(f,'0'*64,False)['complete'])
            self.assertFalse(failures(f,False)['complete'])
    def test_success_failure_json_no_top30(self):
        f=self.root/'json'
        values=[dict(property=f'f.assigns.{i}',status='FAILURE',description='bad',sourceLocation={'file':'f.rs','line':'2'}) for i in range(40)]
        f.write_text(json.dumps([{'result':values}]))
        r=failures(f,True)
        self.assertEqual(len(r['failures']),40)
        self.assertEqual(r['records_parsed'],40)
        self.assertEqual(r['status'],'NOT_RUN')
        self.assertFalse(r['complete'])
        f.write_text('[{"result":['+json.dumps(values[0])+',')
        r=failures(f,False)
        self.assertEqual(len(r['failures']),1)
        self.assertFalse(r['complete'])
        f.write_text('[{"result":[{"property":"x.assertion.1","status":"SUCCESS"}]}]')
        self.assertEqual(failures(f,True)['failures'],[])
    def test_quoting_argv_and_stream_identity(self):
        arg='a b; $(touch forbidden) `env` "quoted"'
        r=run([sys.executable,'-c','import sys; print(sys.argv[1])',arg],self.root/'run')
        self.assertEqual(r['argv'][-1],arg)
        self.assertEqual((self.root/'run/stdout.bin').read_text(),arg+'\n')
    def test_source_identity_rejects(self):
        with patch.object(runner,'git',return_value='wrong'):
            with self.assertRaisesRegex(RuntimeError,'identity mismatch'):
                runner.identity('r1-skip',self.root)
    def test_wrapper_real_once_and_dfcc_inplace(self):
        fake=self.root/'real'
        fake.write_text('#!/usr/bin/env python3\nimport pathlib,sys\np=pathlib.Path(sys.argv[-1]); p.write_bytes(p.read_bytes()+b"post"); print("untouched stdout")\n')
        fake.chmod(0o755)
        model=self.root/'model';model.write_bytes(b'pre')
        case=self.root/'case';case.mkdir()
        config=self.root/'config'
        save(config,{'case_dir':str(case),'tools':{'goto-instrument':{'path':str(fake),'sha256':digest(fake)}}})
        wrapper=self.root/'goto-instrument';wrapper.symlink_to(HERE/'wrapper.py')
        env=os.environ.copy();env.update(D1P_CONFIG=str(config),D1P_CASE_DIR=str(case))
        r=subprocess.run([str(wrapper),'--dfcc','root',str(model),str(model)],env=env,capture_output=True)
        self.assertEqual(r.returncode,0,r.stderr)
        slot=case/'invocations/goto-instrument-000'
        self.assertEqual((slot/'pre-dfcc.goto').read_bytes(),b'pre')
        self.assertEqual((slot/'post-dfcc.goto').read_bytes(),b'prepost')
        self.assertEqual(r.stdout,b'untouched stdout\n')
        r=subprocess.run([str(wrapper),'--dfcc','root',str(model),str(model)],env=env,capture_output=True)
        self.assertEqual(r.returncode,125)
        self.assertEqual(model.read_bytes(),b'prepost')
        self.assertTrue((case/'wrapper-error.json').is_file())
    def test_wrapper_mismatched_binary(self):
        import wrapper
        conf=self.root/'config'
        save(conf,{'case_dir':str(self.root),'tools':{'cbmc':{'path':sys.executable,'sha256':'bad'}}})
        with patch.dict(os.environ,D1P_CONFIG=str(conf)):
            with self.assertRaisesRegex(RuntimeError,'identity mismatch'):
                wrapper.invoke('cbmc',['--program-only'])
    def test_milestones_prefix_and_tail_after_cap(self):
        r=self.fake('print("Generated 1"); print("x"*1000); print("VERIFICATION diagnostic-end")',cap=10)
        self.assertTrue(r['streams']['stdout']['truncated'])
        events=json.loads((self.root/'run/milestones.json').read_text())['stdout']
        self.assertEqual(len(events['records']),2)
        self.assertIn('diagnostic-end',events['records'][-1]['text'])
        parser=Milestones()
        parser.feed(b'Generated\n'*400)
        summary=parser.report()
        self.assertEqual(summary['emitted_records'],200)
        self.assertEqual(summary['dropped_records'],200)
    def test_hard_address_space_receipt(self):
        r=self.fake('import resource; print(resource.getrlimit(resource.RLIMIT_AS)[0])',as_kib=262144)
        self.assertEqual(r['rlimit_as_kib'],262144)
        self.assertEqual((self.root/'run/stdout.bin').read_text().strip(),str(262144*1024))
    def test_json_order_wrong_types_and_depth(self):
        f=self.root/'json'
        f.write_text('[{"result":[{"sourceLocation":{"file":"x"},"status":"FAILURE","property":"f.assigns.7"}]}]')
        r=failures(f,True)
        self.assertEqual(len(r['failures']),1)
        self.assertEqual(r['failures'][0]['location'],{'file':'x'})
        for data in ['null','3','"FAILURE"','['*70+'0'+']'*70]:
            f.write_text(data)
            self.assertFalse(failures(f,True)['complete'])
    def test_forward_epipe_still_drains(self):
        capture_path=str(HERE)
        fake_code='import os; os.write(1,b"x"*200000)'
        code=('import sys; sys.path.insert(0,sys.argv[1]); from capture import run; '
              'r=run([sys.executable,"-c",'+repr(fake_code)+'],sys.argv[2],forward=True); '
              'sys.exit(0 if r["streams"]["stdout"]["total_bytes"]==200000 else 1)')
        child=subprocess.Popen([sys.executable,'-c',code,capture_path,str(self.root/'forward')],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        child.stdout.close()
        stderr=child.stderr.read();child.stderr.close()
        self.assertEqual(child.wait(timeout=5),0,stderr)
        result=json.loads((self.root/'forward/receipt.json').read_text())
        self.assertTrue(result['streams']['stdout']['forwarding_epipe'])
        self.assertFalse(result['stream_complete'])
    def test_cases_end_to_end_fake_only(self):
        # All binaries in this fixture are Python children, never installed tools.
        tools=self.root/'tools';tools.mkdir()
        fake=tools/'cbmc'
        fake.write_text('#!/usr/bin/env python3\nimport sys\nif sys.argv[1:]==["--version"]: print("6.11.0 fake")\nelse: print("Program constraints:\\n// 17 file f.rs line 1 function f\\n(1) x!0 = byte_extract_little_endian(a, off)")\n')
        fake.chmod(0o755)
        gi=tools/'goto-instrument'
        gi.write_text('#!/usr/bin/env python3\nimport sys,pathlib\nif sys.argv[1:]==["--version"]: print("6.11.0 fake")\nelif "--dfcc" in sys.argv: p=pathlib.Path(sys.argv[-1]); p.write_bytes(p.read_bytes()+b"post")\nelse: print("Layout UNKNOWN transfer ASSERT")\n')
        gi.chmod(0o755)
        scripts=self.root/'scripts';scripts.mkdir()
        kani=scripts/'kani'
        kani.write_text('#!/usr/bin/env python3\nimport pathlib,subprocess\np=pathlib.Path("model.out");p.write_bytes(b"pre")\nsubprocess.run(["goto-instrument","--dfcc","root",str(p),str(p)],check=True)\np.write_bytes(p.read_bytes()+b"later")\nsubprocess.run(["cbmc","--program-only","--object-bits","16","--slice-formula",str(p),"--json-ui"],check=True)\nraise SystemExit(7)\n')
        kani.chmod(0o755)
        out=self.root/'artifacts';out.mkdir()
        old=Path.cwd()
        try:
            os.chdir(self.root)
            real_which=shutil.which
            def which(name):
                return str(tools/name) if name in ('cbmc','goto-instrument') else real_which(name)
            with patch.object(runner,'identity',return_value={'source':'synthetic'}),patch.object(runner.shutil,'which',side_effect=which):
                rc=runner.cases('r1-skip',out)
            case=out/runner.PINS['r1-skip']/'P1'/runner.ROOT
            status=json.loads((case/'status.json').read_text())
            self.assertEqual(rc,1)  # original fake Kani failure never becomes PASS
            self.assertEqual(status['symex_only'],'COMPLETE')
            self.assertEqual(status['verification'],'NOT_RUN')
            self.assertEqual(status['diagnostic_completion'],'CAPTURE_COMPLETE')
            info=json.loads((case/'actual-input.json').read_text())
            self.assertEqual(Path(info['snapshot']).read_bytes(),b'prepostlater')
            self.assertFalse((case/'work').exists())
            self.assertEqual((case/'invocations/goto-instrument-000/pre-dfcc.goto').read_bytes(),b'pre')
            self.assertEqual((case/'invocations/goto-instrument-000/post-dfcc.goto').read_bytes(),b'prepost')
        finally:
            os.chdir(old)
    def test_projection_limits(self):
        f=self.root/'text'; f.write_text('Layout UNKNOWN\n'*400)
        projection(f,self.root/'selected.json','a'*64)
        r=json.loads((self.root/'selected.json').read_text())
        self.assertEqual(len(r['records']),200)
        self.assertFalse(r['complete'])
        self.assertTrue(r['selection_incomplete'])


if __name__=='__main__':
    unittest.main()
