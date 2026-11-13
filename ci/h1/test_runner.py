#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Small synthetic service tests: no compiler, verifier, real models or build."""
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('h1_runner', HERE/'runner.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def result(status='SUCCESS'):
    return [dict(messageText='123 steps of symex', messageType='STATUS-MESSAGE'),
            dict(messageText='10 VCC(s) remaining after simplification', messageType='STATUS-MESSAGE'),
            dict(messageText='converting SSA', messageType='STATUS-MESSAGE'),
            dict(messageText='Running propositional reduction', messageType='STATUS-MESSAGE'),
            dict(messageText='65 variables, 321 clauses', messageType='STATUS-MESSAGE'),
            dict(messageText='66 variables, 322 clauses', messageType='STATUS-MESSAGE'),
            dict(result=[dict(property='f.uninitialized.1', description='payload read', status=status,
                             sourceLocation=dict(file='scalar-pfc-hole.rs', line='16', function='ensures'))]),
            dict(cProverStatus='success' if status == 'SUCCESS' else 'failure')]


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.p = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def parse(self, items, **kwargs):
        observer = r.Observer(self.p, **kwargs)
        data = json.dumps(items).encode()
        for i in range(0, len(data), 7):
            observer.feed(data[i:i+7])
        return observer, observer.finish()

    def run_synthetic(self, source, **kwargs):
        return r.execute([sys.executable, '-c', source], self.p/'run',
                         kwargs.pop('seconds', 5), sample=0.01, **kwargs)

    def test_matrix_fixed_roots_and_only_ten_arms(self):
        cases = json.loads((HERE/'matrix.json').read_text())
        self.assertEqual([x['id'] for x in cases], ['C12-P1','C12-P2','D10-P1','D10-P2','B14-P1','B14-P2','A16-P1','F12-P1','H16-P1','E8-P1'])
        for c in cases:
            filename, root, digest = r.ROOTS[c['root']]
            self.assertEqual(r.sha(HERE/'cases'/filename), digest)
            args = r.case_args(c, 'kani', Path('/tmp')/filename)
            split = args.index('--cbmc-args')
            self.assertEqual(args.count('--object-bits'), 1)
            self.assertNotIn('--jobs', args)
            self.assertNotIn('--edition', args)
            self.assertEqual(args[split+1:split+3], ['--object-bits',str(c['object_bits'])])
            self.assertNotIn('--no-slice-formula', args[split:])
            self.assertEqual('--no-slice-formula' in args[:split], c['mode']=='no-slice')
            self.assertEqual('--arrays-uf-always' in args[split:], c['mode']=='uf')
            self.assertEqual(c['offset_bits'], 64-c['object_bits'])
            self.assertEqual(c['derived_max_allocation_bytes'], 2**(c['offset_bits']-1))

    def test_complete_inventory_source_class_rounds_and_negative_are_separate(self):
        observer, inventory = self.parse(result('FAILURE'))
        self.assertTrue(inventory['complete'])
        self.assertEqual(inventory['properties'][0]['class_from_id'], 'uninitialized')
        self.assertEqual(inventory['properties'][0]['source']['line'], '16')
        self.assertEqual(len(observer.rounds), 2)
        self.assertIsNotNone(observer.conversion_windows[0]['elapsed_observed_seconds'])
        self.assertEqual(observer.rounds[1]['round'], 2)
        self.assertEqual(observer.rounds[0]['clauses'], 321)
        self.assertEqual(inventory['semantic_oracle'], 'UNKNOWN_REQUIRES_SOURCE_CALLSITE_BINDING')

    def test_initial_phase_survives_cutoff_without_zero_cnf(self):
        observer = r.Observer(self.p)
        observer.feed(b'[{"messageText":"converting SSA","messageType":"STATUS-MESSAGE"},')
        inv = observer.finish()
        self.assertFalse(inv['complete'])
        self.assertEqual(len(observer.conversion), 1)
        self.assertEqual(observer.rounds, [])
        phase=json.loads((self.p/'phase.json').read_text())
        self.assertIsNone(phase['first_cnf'])
        self.assertEqual(phase['first_cnf_missing'], 'CENSORED_OR_NOT_REACHED')

    def test_null_missing_wrong_type_and_bad_status_never_complete(self):
        for item in ({'result':None}, {'result':{}}, {'result':[None]},
                     {'cProverStatus':None}, {'result':[]}, {'program':'synthetic'}):
            _, inv = self.parse([item])
            self.assertFalse(inv['complete'])

    def test_cap_and_property_cap_explicit(self):
        _, inv = self.parse(result(), object_cap=30)
        self.assertFalse(inv['complete'])
        self.assertTrue(inv['errors'])
        _, inv = self.parse(result(), property_cap=0)
        self.assertFalse(inv['complete'])
        self.assertEqual(inv['dropped'], 1)

    def test_prefix_tail_independent_and_full_stream_hash(self):
        sink = r.Bounded(self.p/'log', prefix=4, tail=3)
        sink.feed(b'012345'); sink.feed(b'6789')
        receipt = sink.close()
        self.assertEqual((self.p/'log').read_bytes(), b'0123')
        self.assertEqual((self.p/'log.tail').read_bytes(), b'789')
        self.assertFalse(receipt['complete'])
        self.assertEqual(receipt['total_bytes'], 10)

    def test_original_success_error_and_signal(self):
        a = self.run_synthetic('print("synthetic")')
        self.assertEqual(a['original_exit'], 0)
        b = self.run_synthetic('import sys; sys.exit(7)')
        self.assertEqual(b['original_exit'], 7)
        c = self.run_synthetic('import os, signal; os.kill(os.getpid(), signal.SIGTERM)')
        self.assertEqual(c['original_signal'], signal.SIGTERM)
        self.assertIsNone(c['original_exit'])

    def test_timeout_cleans_own_group_and_retains_tail(self):
        pidfile = self.p/'child.pid'
        code = f'import subprocess,time; p=subprocess.Popen(["{sys.executable}","-c","import time;time.sleep(30)"]);open({str(pidfile)!r},"w").write(str(p.pid));print("initial",flush=True);time.sleep(30)'
        got = self.run_synthetic(code, seconds=0.25)
        self.assertEqual(got['watchdog'], 'TIMEOUT')
        pid = int(pidfile.read_text())
        try:
            state = Path(f'/proc/{pid}/stat').read_text().split()[2]
        except (FileNotFoundError, ProcessLookupError):
            state = None
        self.assertIn(state, (None, 'Z'))
        self.assertIn(b'initial', (self.p/'run'/'stdout.prefix.tail').read_bytes())

    def test_memory_cap_raw_kib_and_spawn_error(self):
        got = self.run_synthetic('import time; a=bytearray(1024*1024);time.sleep(3)', memory_kib=1)
        self.assertEqual(got['watchdog'], 'RSS_LIMIT')
        self.assertGreater(got['peak_sampled_rss_kib'], 1)
        got = r.execute(['/this/is/a/synthetic/missing-command'], self.p/'missing', 1)
        self.assertEqual(got['state'], 'ERROR')
        self.assertIn('FileNotFoundError', got['exception'])
        self.assertIsNone(got['original_exit'])

    def test_classification_not_run_cutoff_capacity_and_semantics(self):
        self.assertEqual(r.classify({}, None, None, []), 'NOT_RUN')
        self.assertEqual(r.classify({}, {'state':'FINISHED','original_exit':0}, None, []), 'INCOMPLETE/UNKNOWN')
        self.assertEqual(r.classify({'watchdog':'TIMEOUT'}, {}, None, []), 'RESOURCE_CENSORED/INCONCLUSIVE')
        self.assertEqual(r.classify({}, {}, None, ['too many addressed objects']), 'OBJECT_CAPACITY_EXCEEDED/INCONCLUSIVE')
        self.assertEqual(r.classify({}, {}, None, ['Unsupported array encoding']), 'MODE_UNQUALIFIED/INCONCLUSIVE')
        self.assertEqual(r.classify({}, {'state':'FINISHED','original_exit':0}, {'complete':True}, []), 'COMPLETED/SEMANTIC_BINDING_REQUIRED')
        self.assertEqual(r.classify({}, {'state':'FINISHED','original_exit':127}, {'complete':True}, []), 'BACKEND_ERROR/INCONCLUSIVE')

    def test_real_argv_model_binding_and_refusal(self):
        model=self.p/'actual.goto'; model.write_bytes(b'synthetic not a real model')
        case={'object_bits':12, 'mode':'slice'}
        args=['--no-malloc-may-fail','--no-undefined-shift-check','--no-signed-overflow-check','--nan-check','--no-self-loops-to-assumptions','--no-pointer-primitive-check','--sat-solver','cadical','--slice-formula','--object-bits','12',str(model),'--verbosity','9','--json-ui']
        self.assertEqual(r.validate_backend(args,case), model)
        for bad in [args+['--slice-formula'], ['--object-bits','16']+args, [x.replace('--object-bits','--object-bits=12') for x in args]]:
            with self.assertRaises(ValueError): r.validate_backend(bad, case)
        model.unlink()
        with self.assertRaises(ValueError): r.validate_backend(args,case)

    def test_wrapper_transparently_forwards_normal_exit10_once(self):
        fake=self.p/'fake'; fake.write_text('#!'+sys.executable+'\nimport sys\nprint('+repr(json.dumps(result('FAILURE')))+')\nsys.exit(10)\n');fake.chmod(0o755)
        shim=self.p/'cbmc'; shim.symlink_to(HERE/'runner.py')
        model=self.p/'actual.goto';model.write_bytes(b'synthetic')
        env=os.environ.copy();env.update(H1_CASE_OUT=str(self.p/'case'), H1_REAL_CBMC=str(fake), H1_CASE=json.dumps(dict(object_bits=12,mode='slice')))
        args=[str(shim),*['--no-malloc-may-fail','--no-undefined-shift-check','--no-signed-overflow-check','--nan-check','--no-self-loops-to-assumptions','--no-pointer-primitive-check','--sat-solver','cadical','--slice-formula','--object-bits','12',str(model),'--verbosity','9','--json-ui']]
        p=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.assertEqual(p.returncode,10,p.stderr)
        self.assertEqual(json.loads(p.stdout),result('FAILURE'))
        ident=json.loads((self.p/'case/cbmc/identity.json').read_text())
        self.assertEqual(ident['goto_sha256'],r.sha(model))
        inv=json.loads((self.p/'case/cbmc/properties.json').read_text());self.assertTrue(inv['complete'])
        q=subprocess.run(args,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        self.assertEqual(q.returncode,125)
        self.assertEqual(q.stdout,b'')

    def test_source_stage_target_and_null_bundle_refused_without_tools(self):
        bundle=self.p/'bundle';bundle.mkdir()
        old=os.environ.get('RUNNER_TEMP');os.environ['RUNNER_TEMP']=str(self.p)
        try:
            for n, data in enumerate([None, {}, {'source':r.SOURCE,'tree':r.TREE,'cbmc_version':'6.11.0','target':'aarch64-unknown-linux-gnu'}]):
                (bundle/'identity.json').write_text(json.dumps(data))
                if (self.p/'h1-input').exists():
                    import shutil; shutil.rmtree(self.p/'h1-input')
                with self.assertRaises(ValueError): r.run_case('C12-P1',bundle,self.p/f'case-{n}')
                outcome=json.loads((self.p/f'case-{n}'/'outcome.json').read_text())
                self.assertEqual(outcome['resource'],'NOT_RUN')
        finally:
            if old is None: os.environ.pop('RUNNER_TEMP',None)
            else: os.environ['RUNNER_TEMP']=old

    def test_external_signal_retains_receipt_and_cleans_group(self):
        out=self.p/'external'
        command=[sys.executable,str(HERE/'runner.py'),'phase',str(out),'20','6291456',sys.executable,'-c','import time; print("started",flush=True); time.sleep(20)']
        guardian=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        import time
        deadline=time.monotonic()+5
        process_file=out/'process.json'
        while time.monotonic()<deadline:
            current=r.load_optional(process_file)
            if current and current.get('state')=='RUNNING' and (out/'stdout.prefix').stat().st_size:
                break
            time.sleep(0.01)
        guardian.send_signal(signal.SIGTERM)
        guardian.communicate(timeout=5)
        got=json.loads(process_file.read_text())
        self.assertEqual(got['watchdog'],'EXTERNAL_SIGNAL_'+str(signal.SIGTERM))
        self.assertEqual(got['state'],'FINISHED')
        self.assertEqual(guardian.returncode,1)
        self.assertEqual(r.group_members(got['pid']),[])

    def test_projection_streams_beyond_prefix_with_bounded_context(self):
        observer=r.ProjectionObserver(self.p)
        observer.feed(b'header\n'+b'unrelated\n'*1000+b'actual MEMORY_INITIALIZATION_STATE write\n')
        data=observer.finish()
        self.assertEqual(data['selected'][0]['line'],1002)
        self.assertIn('UNKNOWN',data['binding'])


if __name__ == '__main__':
    unittest.main()
