"""Linux owned-process containment and observed native starts, no compiler logic."""
import ctypes,errno,os,re,signal,subprocess,sys,time
from pathlib import Path
import rich_evidence

class NativeStarts(rich_evidence.RegularEvidence):
    def __init__(self,*args):
        super().__init__(*args);self.starts=[]
    def _line(self,line):
        marker=re.fullmatch(r'Checking harness (.+)\.\.\.',line)
        if marker:self.starts.append({'selector':marker[1],'monotonic':time.monotonic()})
        return super()._line(line)

class ContainmentError(RuntimeError):pass

def census():
    result={}
    for p in Path('/proc').iterdir():
        if not p.name.isdigit():continue
        try:
            raw=(p/'stat').read_text();tail=raw[raw.rfind(')')+2:].split()
            result[int(p.name)]={'pid':int(p.name),'state':tail[0],'ppid':int(tail[1]),
                'pgid':int(tail[2]),'start_ticks':int(tail[19])}
        except (FileNotFoundError,ProcessLookupError):continue
    return result

def subreaper(enable=None):
    libc=ctypes.CDLL(None,use_errno=True);value=ctypes.c_int()
    if libc.prctl(37,ctypes.byref(value),0,0,0)!=0:raise ContainmentError('PR_GET_CHILD_SUBREAPER failed')
    old=bool(value.value)
    if enable is not None and libc.prctl(36,int(enable),0,0,0)!=0:raise ContainmentError('PR_SET_CHILD_SUBREAPER failed')
    return old

class Owned:
    """Dedicated subreaper process must own no unrelated active children."""
    def __init__(self):
        if not hasattr(os,'pidfd_open') or not hasattr(signal,'pidfd_send_signal'):
            raise ContainmentError('Linux pidfds required for race-safe owned signaling')
        self.parent=os.getpid();self.old=subreaper(True);self.known={};self.signals=[];self.reaped=[]
        self.scan_errors=[]
        if any(v['ppid']==self.parent for v in census().values()):
            subreaper(self.old);raise ContainmentError('unrelated preexisting child; containment scope not exclusive')
    def restore(self):subreaper(self.old)
    def observe(self,worker_pid=None):
        table=census();owned=set()
        if worker_pid in table:owned.add(worker_pid)
        owned.update(p for p,v in table.items() if v['ppid']==self.parent)
        owned.update(p for p,v in self.known.items() if p in table and table[p]['start_ticks']==v['start_ticks'])
        while True:
            extra={p for p,v in table.items() if v['ppid'] in owned}
            if extra<=owned:break
            owned|=extra
        live=[]
        for pid in owned:
            rec=table.get(pid)
            if rec is None:continue
            old=self.known.get(pid)
            if old is not None and old['start_ticks']!=rec['start_ticks']:
                raise ContainmentError('owned PID identity reused')
            self.known[pid]=rec
            if rec['state']!='Z':live.append(rec)
        return live,table
    def send(self,rec,sig):
        try:fd=os.pidfd_open(rec['pid'])
        except ProcessLookupError:return
        try:
            current=census().get(rec['pid'])
            if current is None:return
            if current['start_ticks']!=rec['start_ticks']:raise ContainmentError('pidfd identity mismatch')
            signal.pidfd_send_signal(fd,sig)
            self.signals.append({'pid':rec['pid'],'start_ticks':rec['start_ticks'],'signal':sig,'monotonic':time.monotonic()})
        except ProcessLookupError:pass
        finally:os.close(fd)
    def cleanup(self,proc,seconds=8):
        start=time.monotonic();deadline=start+seconds
        while time.monotonic()<deadline:
            live,table=self.observe(proc.pid);proc.poll()
            for rec in live:self.send(rec,signal.SIGTERM if time.monotonic()-start<1 else signal.SIGKILL)
            for pid,rec in list(self.known.items()):
                if pid==proc.pid:continue
                try:
                    got,status=os.waitpid(pid,os.WNOHANG)
                    if got:self.reaped.append({'pid':pid,'status':status})
                except ChildProcessError:pass
            live,table=self.observe(proc.pid)
            zombies=[p for p,v in table.items() if v['ppid']==self.parent and p!=proc.pid]
            if not live and not zombies:
                proc.wait(timeout=max(.01,deadline-time.monotonic()))
                return {'verified':True,'scope':'SUBREAPER_OWNED_DESCENDANTS_PID_STARTTIME; not kernel memory accounting',
                        'observed':list(self.known.values()),'signals':self.signals,'reaped_adopted':self.reaped,
                        'worker_exit':proc.returncode,'elapsed_seconds':time.monotonic()-start}
            time.sleep(.02)
        return {'verified':False,'reason':'OWNED_DESCENDANTS_NOT_REAPED','observed':list(self.known.values()),
                'signals':self.signals,'reaped_adopted':self.reaped,'elapsed_seconds':time.monotonic()-start}

def sampled_owned_rss(records):
    total=0
    for rec in records:
        try:
            for line in (Path('/proc')/str(rec['pid'])/'status').read_text().splitlines():
                if line.startswith('VmRSS:'):total+=int(line.split()[1]);break
        except FileNotFoundError:pass
    return total

def supervise(argv,cwd,env,slot_seconds,outer_rss_kib,stderr_path,artifact_check=None):
    """Never allows a success after the cutoff latch. All descendants cleaned first."""
    owned=Owned();proc=None;started=time.monotonic();cutoff=None;peak=0;cleanup=None;error=None;first=None;survivors=[]
    stderr_path.parent.mkdir(parents=True,exist_ok=True)
    try:
        with stderr_path.open('xb') as stream:
            proc=subprocess.Popen(argv,cwd=cwd,env=env,start_new_session=True,stdout=subprocess.DEVNULL,stderr=stream)
            # The first sample can race a fast exit; adopted children remain owned.
            first=census().get(proc.pid)
            if first:owned.known[proc.pid]=first
            while True:
                live,_=owned.observe(proc.pid);peak=max(peak,sampled_owned_rss(live))
                if time.monotonic()-started>=slot_seconds:cutoff='slot_wall'
                elif peak>outer_rss_kib:cutoff='outer_sampled_rss'
                elif stderr_path.stat().st_size>65536:cutoff='worker_stderr_cap'
                elif artifact_check is not None and artifact_check():cutoff='aggregate_artifact_cap'
                if cutoff:break
                if proc.poll() is not None:
                    survivors=[x for x in live if x['pid']!=proc.pid]
                    break
                time.sleep(.02)
    except BaseException as exc:
        cutoff=cutoff or 'supervisor_exception';error={'type':type(exc).__name__,'message':str(exc)}
    finally:
        try:
            if proc is not None:cleanup=owned.cleanup(proc)
        except BaseException as exc:
            cleanup={'verified':False,'reason':f'{type(exc).__name__}: {exc}'}
        if time.monotonic()-started>=slot_seconds:cutoff=cutoff or 'slot_wall_during_cleanup'
        try:owned.restore()
        except Exception as exc:cleanup={'verified':False,'reason':'subreaper_restore:'+str(exc)}
    return {'worker_pid':proc.pid if proc else None,'worker_initial_identity':first if proc else None,
        'worker_exit':proc.returncode if proc else None,'worker_wall_limit_seconds':slot_seconds,'cutoff':cutoff,'supervisor_error':error,
        'containment':cleanup,'monotonic_start':started,'monotonic_end':time.monotonic(),
        'elapsed_seconds':time.monotonic()-started,'outer_sampled_peak_kib':peak,
        'outer_rss_scope':'POLLED_NONATOMIC_SUM_VmRSS_OBSERVED_OWNED_PIDS; overshoot possible; not strict tree/cgroup/kernel',
        'limit_initiated':cutoff is not None,'orphan_survivors_at_worker_exit':survivors}
