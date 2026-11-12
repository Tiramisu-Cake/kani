#!/usr/bin/env python3
# Copyright Kani Contributors
# SPDX-License-Identifier: Apache-2.0 OR MIT
"""Coordinator-dispatched CI only; local entry points are synthetic tests."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from capture import MIB, digest, exit_code, run, save
from analyze import failures, program, projection

HERE = Path(__file__).resolve().parent
PINS = {'r1-skip':'56cbc5c4a479bc3fb25310b14fcf279d90581a02',
        'r6b':'405c1f059264d8f7cedeeaa01c6d4ad6867a419e'}
TREES = {'r1-skip':'a97ec3d06efd827829f550f1e7a98f29538758fe',
         'r6b':'162e8ad1e76e842b18c24a4ac2986335902834d7'}
FIXTURES = {'scalar-pfc-legal.rs':'fe05e646b2ccc9188d073b78b30abecd59eb877b6298abfcdfc8a27aeb3a260b',
            'scalar-pfc-hole.rs':'61fc369a6830c6ff185887b04db36139ca529e4de097c0025ce7b29c8323f759'}
ROOT = 'postcondition_reads_initialized_return'


def git(*args):
    return subprocess.check_output(['git', *args], text=True).strip()


def identity(pin, out):
    source = PINS[pin]
    if git('rev-parse','HEAD^') != source or git('rev-parse',source+'^{tree}') != TREES[pin]:
        raise RuntimeError('source parent/tree identity mismatch')
    changed=git('diff','--name-only',source,'HEAD').splitlines()
    if not changed or any(not (p=='.github/workflows/kani3300-d1p.yml' or
                              p.startswith('diagnostics/kani3300-d1p/')) for p in changed):
        raise RuntimeError('non-allowlisted commit diff')
    if git('status','--porcelain','--untracked-files=no'):
        raise RuntimeError('tracked checkout is dirty')
    for name, expected in FIXTURES.items():
        if digest(HERE/'inputs'/name) != expected:
            raise RuntimeError('fixture identity mismatch')
    data=dict(source_sha=source, source_tree=TREES[pin], ci_sha=git('rev-parse','HEAD'),
        ci_tree=git('rev-parse','HEAD^{tree}'), pin=pin, fixtures=FIXTURES,
        run_id=os.environ.get('GITHUB_RUN_ID'), run_attempt=os.environ.get('GITHUB_RUN_ATTEMPT'),
        job=os.environ.get('GITHUB_JOB'), cwd=str(Path.cwd()), allowlist=changed,
        effective_allowlisted_flags={'RUSTFLAGS':'--edition 2021 -D warnings --emit=mir',
        'RUST_BACKTRACE':'1','KANI_FAIL_ON_UNEXPECTED_DESCRIPTION':'true'},
        historical_limits=dict(rss_kib=6291456, sample_seconds=2, timeout_seconds=300),
        production_trees={p:git('rev-parse',source+':'+p) for p in
                          ['kani-compiler','kani-driver','library','cprover_bindings','tests']},
        verification='NOT_RUN', observed_bindings='UNKNOWN', proof_credit=0)
    save(out/'identity.json',data)
    return data


def cases(pin, out):
    ident=identity(pin,out)
    case=out/PINS[pin]/'P1'/ROOT
    case.mkdir(parents=True, exist_ok=False)
    save(case/'status.json',dict(setup='RUNNING', capture='NOT_RUN', symex_only='NOT_RUN',
         verification='NOT_RUN', failure_inventory='NOT_RUN/UNKNOWN', parser='NOT_RUN',
         last_completed_phase='identity', proof_credit=0))
    tools={}
    for name in ['cbmc','goto-instrument']:
        binary=shutil.which(name)
        if not binary:
            raise RuntimeError('missing tool: '+name)
        binary=str(Path(binary).resolve())
        rec=run([binary,'--version'],case/(name+'-version'),seconds=10,rss_kib=2097152)
        version=(case/(name+'-version')/'stdout.bin').read_text(errors='replace').strip()
        if exit_code(rec) or not rec['stream_complete'] or not version.startswith('6.11.0'):
            raise RuntimeError('tool must identify as stock 6.11.0: '+name)
        tools[name]=dict(path=binary,sha256=digest(binary),version=version)
    work=(Path.cwd()/'d1p-work'/PINS[pin]/'P1'/ROOT).resolve()
    work.mkdir(parents=True, exist_ok=False)
    wrap=work/'wrappers'
    wrap.mkdir()
    for name in tools:
        (wrap/name).symlink_to(HERE/'wrapper.py')
    config=case/'config.json'
    save(config,dict(tools=tools,case_dir=str(case)))
    fixture=work/'scalar-pfc-legal.rs'
    shutil.copyfile(HERE/'inputs'/fixture.name,fixture)
    env=os.environ.copy()
    env.update(PATH=str(wrap)+os.pathsep+str(Path.cwd()/'scripts')+os.pathsep+env['PATH'],
        D1P_CONFIG=str(config), D1P_CASE_DIR=str(case),
        RUSTFLAGS='--edition 2021 -D warnings --emit=mir', RUST_BACKTRACE='1',
        KANI_FAIL_ON_UNEXPECTED_DESCRIPTION='true')
    # No values from the rest of the inherited environment are serialized.
    kani=str((Path.cwd()/'scripts/kani').resolve())
    argv=[kani,str(fixture),'--crate-name','m2br','-Z','uninit-checks',
        '-Z','function-contracts','--output-format=regular','--harness',ROOT,'--exact',
        '--keep-temps','-Z','unstable-options','--cbmc-args','--program-only']
    save(case/'invocation.json',dict(actual_kani_argv=argv, identity=ident, tools=tools,
         root=ROOT, fixture_sha256=digest(fixture), diagnostic_additions=[
             '-Z','unstable-options','--cbmc-args','--program-only']))
    kani_rec=run(argv,case/'frontend-dfcc-symex',cwd=work,env=env,seconds=300,rss_kib=2097152)
    actual=case/'actual-input.json'
    final=dict(setup='COMPLETE', capture='INCOMPLETE', symex_only='NOT_RUN',
        verification='NOT_RUN', failure_inventory='NOT_RUN/UNKNOWN', parser='NOT_RUN',
        last_completed_phase='setup', kani_original_rc=kani_rec['original_rc'],
        kani_original_signal=kani_rec['original_signal'], kani_timeout='UNKNOWN',
        diagnostic_completion='INCOMPLETE', proof_credit=0)
    save(case/'failures.json',dict(status='NOT_RUN',complete=False,failures=[],
         total_failed_properties=None, records_parsed=0, semantic_completeness='UNKNOWN'))
    dfcc=list((case/'invocations').glob('goto-instrument-*/dfcc.json')) if (case/'invocations').exists() else []
    valid_dfcc=len(dfcc)==1 and (dfcc[0].parent/'post-dfcc.goto').is_file()
    dfcc_complete=valid_dfcc and json.loads((dfcc[0].parent/'boundary.json').read_text())['status']=='COMPLETE'
    final['dfcc_status']='COMPLETE' if dfcc_complete else 'MISSING_DUPLICATE_FAILED_OR_INCOMPLETE'
    if actual.is_file():
        info=json.loads(actual.read_text())
        slot=Path(info['invocation'])
        cbmc_rec=json.loads((slot/'process/receipt.json').read_text())
        binary=Path(info['snapshot'])
        model=digest(binary)
        final['symex_only']='COMPLETE' if exit_code(cbmc_rec)==0 and cbmc_rec['stream_complete'] else 'INCOMPLETE'
        final['last_completed_phase']='symex-only' if final['symex_only']=='COMPLETE' else 'actual-cbmc-spawn'
        summary=program(slot/'process/stdout.bin',model,cbmc_rec['stream_complete'])
        save(case/'ssa-summary.json',summary)
        lines=['D1-P visible SSA only; verification NOT_RUN; proof_credit 0',
               'model_sha256='+model, 'counts='+json.dumps(summary['counts'],sort_keys=True),
               'parser_complete='+str(summary['parser_complete']),
               'stream_complete='+str(summary['stream_complete']),
               'width/owner/semantic feasibility UNKNOWN']
        lines += ['root '+key+' occurrences='+str(value) for key,value in summary['top30_textual_roots_by_occurrences']]
        lines += ['gap '+gap for gap in summary['gaps']]
        (case/'summary.txt').write_text('\n'.join(lines)+'\n')
        save(case/'failures.json',failures(slot/'process/stdout.bin',cbmc_rec['stream_complete']))
        final['parser']='COMPLETE' if summary['complete'] else 'INCOMPLETE'
        invocation_dirs=[p for p in (case/'invocations').iterdir() if p.is_dir()]
        boundaries_complete=all((p/'boundary.json').is_file() and
            json.loads((p/'boundary.json').read_text())['status']=='COMPLETE' for p in invocation_dirs)
        final['capture']='COMPLETE' if (dfcc_complete and boundaries_complete
            and cbmc_rec['stream_complete'] and kani_rec['stream_complete']) else 'INCOMPLETE'
        save(case/'snapshot-link.json',dict(actual_cbmc_sha256=model,
            post_dfcc_sha256=digest(dfcc[0].parent/'post-dfcc.goto') if valid_dfcc else None,
            relation='separate snapshots; intervening driver transformations; equality is not presumed'))
        # Stock read-only views; do not rewrite original snapshots. No extra symex.
        sources=[('actual-cbmc',binary)]
        if valid_dfcc:
            sources += [('pre-dfcc',dfcc[0].parent/'pre-dfcc.goto'),
                        ('post-dfcc',dfcc[0].parent/'post-dfcc.goto')]
        views_complete=True
        for phase, source in sources:
            for view in ['--show-symbol-table','--show-goto-functions']:
                dest=case/(phase+'-'+view[2:])
                rec=run([tools['goto-instrument']['path'],view,str(source)],dest,
                        seconds=30,rss_kib=2097152)
                views_complete &= exit_code(rec)==0 and rec['stream_complete']
                projection(dest/'stdout.bin',dest/'selected.json',digest(source))
                if digest(source) != json.loads(Path(str(source)+'.json').read_text())['sha256']:
                    raise RuntimeError('inspection modified a snapshot')
        final['stock_views']='COMPLETE' if views_complete else 'INCOMPLETE'
        # Kani parser compatibility is separate: never synthesize a verdict.
        final['kani_pipeline_status']='EXIT_ZERO' if exit_code(kani_rec)==0 else 'ERROR_OR_DIAGNOSTIC_PARSER_INCOMPATIBILITY'
        good=(final['capture']=='COMPLETE' and final['symex_only']=='COMPLETE'
              and final['parser']=='COMPLETE' and views_complete and not (case/'wrapper-error.json').exists())
        final['diagnostic_completion']='CAPTURE_COMPLETE' if good else 'INCOMPLETE'
    save(case/'status.json',final)
    # Diagnostic output and parser errors do not become a green proof/build gate.
    return 0 if final['diagnostic_completion']=='CAPTURE_COMPLETE' and exit_code(kani_rec)==0 else 1


def setup(pin, out):
    identity(pin,out)
    shell=shutil.which('bash')
    if not shell:
        raise RuntimeError('missing bash')
    env=os.environ.copy()
    env['PATH']=str(Path.home()/'.cargo/bin')+os.pathsep+env['PATH']
    env['GIT_LFS_SKIP_SMUDGE']='1'
    commands=[('rustup',[shell,str(Path.cwd()/'scripts/setup/install_rustup.sh')]),
              ('dependencies',[shell,str(Path.cwd()/'scripts/setup/ubuntu-24.04/install_deps.sh')]),
              ('safe-directory',[shutil.which('git'),'config','--global','--add','safe.directory',str(Path.cwd())]),
              ('submodules',[shutil.which('git'),'submodule','update','--init','--depth','1'])]
    for phase, argv in commands:
        rec=run(argv,out/('setup-'+phase),env=env,seconds=1200,rss_kib=12582912)
        if exit_code(rec):
            return exit_code(rec)
    # Same GITHUB_PATH update as the existing composite action.
    with open(os.environ['GITHUB_PATH'],'a') as target:
        target.write(str(Path.home()/'.cargo/bin')+'\n')
    return 0


def finalize(out):
    save(out/'workflow-status.json',dict(
        setup=os.environ.get('D1P_SETUP','UNKNOWN'),build=os.environ.get('D1P_BUILD','NOT_RUN'),
        capture=os.environ.get('D1P_CAPTURE','NOT_RUN'),upload=os.environ.get('D1P_UPLOAD','PENDING'),
        verification='NOT_RUN',failure_inventory='NOT_RUN/UNKNOWN',observed_bindings='UNKNOWN',proof_credit=0))
    entries=[]
    for path in sorted(out.rglob('*')):
        if path.is_file() and not path.is_symlink() and path.name!='ARTIFACT-MANIFEST.json':
            entries.append(dict(path=str(path.relative_to(out)),bytes=path.stat().st_size,sha256=digest(path)))
    save(out/'ARTIFACT-MANIFEST.json',dict(files=entries,coverage='bounded logs/snapshots/curated projections; receipts carry caps',
        verification='NOT_RUN',proof_credit=0))


def main():
    p=argparse.ArgumentParser()
    p.add_argument('command',choices=['identity','setup','build','cases','finalize'])
    p.add_argument('--pin',choices=list(PINS),required=True)
    args=p.parse_args()
    if os.environ.get('GITHUB_ACTIONS')!='true':
        raise RuntimeError('CI-only entry; use synthetic tests locally')
    out=(Path.cwd()/'d1p-artifacts').resolve()
    out.mkdir(exist_ok=True)
    rc=0
    if args.command=='identity':
        identity(args.pin,out)
    elif args.command=='setup':
        rc=setup(args.pin,out)
    elif args.command=='build':
        identity(args.pin,out)
        cargo=shutil.which('cargo')
        if not cargo:
            raise RuntimeError('missing cargo')
        rec=run([cargo,'build-dev'],out/'build',seconds=5400,rss_kib=12582912)
        rc=exit_code(rec)
    elif args.command=='cases':
        rc=cases(args.pin,out)
    else:
        finalize(out)
    return rc


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        out=Path.cwd()/'d1p-artifacts'
        save(out/'runner-error.json',dict(status='ERROR',error=type(exc).__name__+': '+str(exc),verification='NOT_RUN'))
        for path in out.glob('*/P1/*/status.json'):
            state=json.loads(path.read_text())
            for phase in ['setup','capture','symex_only','parser']:
                if state.get(phase)=='RUNNING':
                    state[phase]='ERROR'
            state.update(diagnostic_completion='INCOMPLETE',runner_error=str(exc))
            save(path,state)
        print('D1P error: '+str(exc),file=sys.stderr)
        raise SystemExit(125)
