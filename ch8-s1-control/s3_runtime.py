"""S3 owned-process lifecycle. Exact ESRCH/ENOENT handling; no blanket suppression."""
import ctypes, errno, os, re, signal, subprocess, time, traceback
from pathlib import Path
from r5_runtime import NativeStarts, subreaper, ContainmentError


class Events(list):
    def __init__(self):super().__init__();self.omitted=0
    def append(self,event):
        super().append(event)
        if len(self)>64:del self[0];self.omitted+=1


def diagnostic(exc, operation, **context):
    trace=''.join(traceback.format_exception(type(exc),exc,exc.__traceback__))
    return {'operation':operation,'type':type(exc).__name__,'message':str(exc)[:2048],
            'errno':getattr(exc,'errno',None),'traceback_tail':trace[-4096:],
            'traceback_truncated':len(trace)>4096,'monotonic':time.monotonic(),**context}


def missing(exc):
    return ((type(exc) is ProcessLookupError and exc.errno==errno.ESRCH)
            or (type(exc) is FileNotFoundError and exc.errno==errno.ENOENT))


def census(events=None):
    result={}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:
            raw=(p/'stat').read_text();tail=raw[raw.rfind(')')+2:].split()
            result[int(p.name)]={'pid':int(p.name),'state':tail[0],'ppid':int(tail[1]),
                'pgid':int(tail[2]),'start_ticks':int(tail[19])}
        except OSError as exc:
            if not missing(exc):raise
            # Enumeration disappearance only. Never establishes owned identity.
            if events is not None:events.append(diagnostic(exc,'census.read_stat',pid=int(p.name),classification='ENUMERATION_DISAPPEARED_NOT_OWNERSHIP'))
    return result


class Owned:
    """Exclusive dedicated subreaper; PID/start_ticks identity, no PG-only ownership."""
    def __init__(self):
        if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
            raise ContainmentError('Linux pidfds required')
        self.parent=os.getpid();self.known={};self.signals=[];self.reaped=[];self.events=Events()
        self.old=subreaper(True)
        try:
            if any(v['ppid']==self.parent for v in census(self.events).values()):
                raise ContainmentError('unrelated preexisting child; ownership not exclusive')
        except BaseException:
            subreaper(self.old);raise
    def restore(self):subreaper(self.old)
    def observe(self,worker_pid=None):
        table=census(self.events);owned={p for p,v in table.items() if v['ppid']==self.parent}
        if worker_pid in table:
            rec=table[worker_pid]
            if rec['ppid']!=self.parent and worker_pid not in self.known:
                raise ContainmentError('unowned worker PID')
            owned.add(worker_pid)
        for pid,old in self.known.items():
            if pid in table:
                if table[pid]['start_ticks']!=old['start_ticks']:raise ContainmentError('owned PID recycled')
                owned.add(pid)
        while True:
            extra={p for p,v in table.items() if v['ppid'] in owned}
            if extra<=owned:break
            owned|=extra
        live=[]
        for pid in owned:
            rec=table[pid];old=self.known.get(pid)
            if old is not None and old['start_ticks']!=rec['start_ticks']:raise ContainmentError('owned PID identity reused')
            self.known[pid]=rec
            if rec['state']!='Z':live.append(rec)
        return live,table
    def validate(self,rec):
        old=self.known.get(rec['pid'])
        if not old or old['start_ticks']!=rec['start_ticks'] or rec['start_ticks']<=0:
            raise ContainmentError('unowned PID/start-time request')
    def vanished(self,exc,operation,rec):
        self.validate(rec)
        if not missing(exc):raise exc
        current=census(self.events).get(rec['pid'])
        if current is not None:
            if current['start_ticks']!=rec['start_ticks']:raise ContainmentError('PID recycled after '+operation) from exc
            if current['state']!='Z':raise ContainmentError('unexplained live-owned '+operation) from exc
        self.events.append(diagnostic(exc,operation,pid=rec['pid'],start_ticks=rec['start_ticks'],
            ownership='PREVIOUSLY_OBSERVED_EXCLUSIVE_DESCENDANT',classification='OWNED_DISAPPEARED_OR_ZOMBIE'))
    def send(self,rec,sig):
        self.validate(rec)
        try:fd=os.pidfd_open(rec['pid'])
        except OSError as exc:
            self.vanished(exc,'signal.pidfd_open',rec);return
        try:
            current=census(self.events).get(rec['pid'])
            if current is None:
                self.events.append({'operation':'signal.identity_recheck','pid':rec['pid'],'start_ticks':rec['start_ticks'],
                    'classification':'OWNED_DISAPPEARED','monotonic':time.monotonic()});return
            if current['start_ticks']!=rec['start_ticks']:raise ContainmentError('pidfd identity mismatch')
            try:signal.pidfd_send_signal(fd,sig)
            except OSError as exc:
                self.vanished(exc,'signal.pidfd_send_signal',rec);return
            self.signals.append({'pid':rec['pid'],'start_ticks':rec['start_ticks'],'signal':sig,'monotonic':time.monotonic()})
        finally:os.close(fd)
    def rss(self,records):
        total=0
        for rec in records:
            self.validate(rec)
            current=census(self.events).get(rec['pid'])
            if current is None:continue
            if current['start_ticks']!=rec['start_ticks']:raise ContainmentError('sampling PID identity mismatch')
            try:
                lines=(Path('/proc')/str(rec['pid'])/'status').read_text().splitlines()
            except OSError as exc:
                self.vanished(exc,'sample.read_status',rec);continue
            current=census(self.events).get(rec['pid'])
            if current is not None and current['start_ticks']!=rec['start_ticks']:
                raise ContainmentError('sampling PID recycled during status read')
            if current is None:continue
            for line in lines:
                if line.startswith('VmRSS:'):total+=int(line.split()[1]);break
        return total
    def cleanup(self,proc,seconds=8):
        start=time.monotonic();deadline=start+seconds
        while time.monotonic()<deadline:
            live,table=self.observe(proc.pid);proc.poll()
            for rec in live:self.send(rec,signal.SIGTERM if time.monotonic()-start<1 else signal.SIGKILL)
            for pid,rec in list(self.known.items()):
                if pid==proc.pid:continue
                try:
                    got,status=os.waitpid(pid,os.WNOHANG)
                    if got:self.reaped.append({'pid':pid,'start_ticks':rec['start_ticks'],'status':status})
                except ChildProcessError as exc:
                    # ECHILD is not a generic success: an active owned process must still be tracked/cleaned.
                    if exc.errno!=errno.ECHILD:raise
                    self.events.append(diagnostic(exc,'cleanup.waitpid',pid=pid,start_ticks=rec['start_ticks'],classification='NOT_DIRECT_CHILD_RECHECK_TREE'))
            live,table=self.observe(proc.pid)
            children=[p for p,v in table.items() if v['ppid']==self.parent and p!=proc.pid]
            if not live and not children:
                proc.wait(timeout=max(.01,deadline-time.monotonic()))
                return {'verified':True,'scope':'EXCLUSIVE_SUBREAPER_PID_STARTTIME',
                        'observed':list(self.known.values()),'signals':self.signals,'reaped_adopted':self.reaped,
                        'worker_exit':proc.returncode,'elapsed_seconds':time.monotonic()-start}
            time.sleep(.02)
        return {'verified':False,'reason':'OWNED_DESCENDANTS_NOT_REAPED','observed':list(self.known.values()),
                'signals':self.signals,'reaped_adopted':self.reaped,'elapsed_seconds':time.monotonic()-start}


def supervise(argv,cwd,env,slot_seconds,outer_rss_kib,stderr_path,artifact_check=None):
    started=time.monotonic();owned=None;proc=None;cutoff=None;peak=0;cleanup=None;error=None;first=None;survivors=[];operation='ownership.initialize'
    stderr_path.parent.mkdir(parents=True,exist_ok=True)
    try:
        owned=Owned()
        with stderr_path.open('xb') as stream:
            operation='worker.Popen'
            proc=subprocess.Popen(argv,cwd=cwd,env=env,start_new_session=True,stdout=subprocess.DEVNULL,stderr=stream)
            operation='worker.initial_census';owned.observe(proc.pid);first=owned.known.get(proc.pid)
            while True:
                operation='supervise.observe';live,_=owned.observe(proc.pid)
                operation='sample.owned_rss';peak=max(peak,owned.rss(live))
                if time.monotonic()-started>=slot_seconds:cutoff='slot_wall'
                elif peak>outer_rss_kib:cutoff='outer_sampled_rss'
                elif stderr_path.stat().st_size>65536:cutoff='worker_stderr_cap'
                elif artifact_check is not None and artifact_check():cutoff='aggregate_artifact_cap'
                if cutoff:break
                if proc.poll() is not None:
                    survivors=[x for x in live if x['pid']!=proc.pid];break
                time.sleep(.02)
    except BaseException as exc:
        cutoff=cutoff or 'supervisor_exception';error=diagnostic(exc,operation,epoch='SUPERVISION')
    finally:
        try:
            if owned is not None and proc is not None:cleanup=owned.cleanup(proc)
        except BaseException as exc:cleanup={'verified':False,'error':diagnostic(exc,'cleanup.owned_tree',epoch='SHUTDOWN')}
        if time.monotonic()-started>=slot_seconds:cutoff=cutoff or 'slot_wall_during_cleanup'
        try:
            if owned is not None:owned.restore()
        except BaseException as exc:
            cleanup={**(cleanup or {}),'verified':False,'restore_error':diagnostic(exc,'cleanup.restore_subreaper')}
    return {'worker_pid':proc.pid if proc else None,'worker_initial_identity':first,
        'worker_exit':proc.returncode if proc else None,'worker_wall_limit_seconds':slot_seconds,'cutoff':cutoff,'supervisor_error':error,
        'containment':cleanup,'monotonic_start':started,'monotonic_end':time.monotonic(),
        'elapsed_seconds':time.monotonic()-started,'outer_sampled_peak_kib':peak,
        'lifecycle_events':(owned.events[-64:] if owned else []),'lifecycle_events_omitted':owned.events.omitted if owned else 0,
        'outer_rss_scope':'POLLED_NONATOMIC_SUM_VmRSS_OBSERVED_OWNED_PIDS; overshoot possible; not strict tree/cgroup/kernel',
        'limit_initiated':cutoff is not None,'orphan_survivors_at_worker_exit':survivors}
